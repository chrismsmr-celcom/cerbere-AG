#!/usr/bin/env python3
"""Test de charge Cerbere : N agents simulés, UNE clé API, un collector, un dashboard.

Chaque agent émet des spans (/span) selon un processus de Poisson (comme de vrais
agents : irrégulier, pas métronomique). Le générateur est « en boucle ouverte » : un
collector lent n'est pas ménagé, la latence mesurée est donc honnête.

    # 1) essai local (collector lancé sur ta machine)
    python load_demo.py --agents 200 --rate 0.2 --duration 60
    # 2) staging (déploiement de test AVEC SA PROPRE BASE)
    python load_demo.py --url https://staging.exemple.com --staging --agents 1500 --rate 0.2 \
        --ramp 30 --duration 180 --burst-factor 5 --probe-dashboard --out resultat.json

Clé : --api-key ou variable AGENTGUARD_API_KEY (une seule pour tous les agents ;
l'identité de chaque agent passe par l'en-tête X-Agent-Id).

NE LANCE JAMAIS CE TEST CONTRE LA PRODUCTION : chaque span écrit une entrée dans
l'audit chaîné (immuable) et des lignes dans spans/events/sessions. Des millions de
lignes synthétiques ne se purgent pas proprement et polluent les vrais clients.
"""
import argparse
import asyncio
import json
import math
import os
import platform
import random
import sys
import time
import uuid
from urllib.parse import urlparse

import httpx

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
PROD_SUFFIX = "cerbereag.site"

TOOLS = ["search_kb", "read_ticket", "lookup_order", "update_crm", "send_email", "refund"]
MODELS = [("gpt-4o-mini", 0.15, 0.60), ("claude-sonnet", 3.00, 15.00), ("deepseek-chat", 0.27, 1.10)]
PROMPTS = [
    "Summarize the open ticket and propose next steps",
    "Draft a polite reply to the customer about the delayed order",
    "Classify this message by urgency",
    "Contact jane.doe@example.com about invoice 4821",  # exerce redact_pii côté collector
    "Look up the refund policy for EU customers",
]


def check_target(url, staging, allow_production):
    host = urlparse(url).hostname or ""
    if host in LOCAL_HOSTS:
        return
    if host.endswith(PROD_SUFFIX):
        if not allow_production:
            sys.exit(
                f"REFUS : {host} est la production. Chaque span y écrirait dans l'audit chaîné (immuable) "
                "et polluerait les données réelles. Utilise un déploiement de test avec sa propre base "
                "(puis --staging). Pour passer outre : --allow-production, à tes risques."
            )
        print(f"ATTENTION : test de charge lancé contre la PRODUCTION ({host}).", file=sys.stderr)
        return
    if not staging:
        sys.exit("REFUS : cible distante. Ajoute --staging pour confirmer que c'est un déploiement de test "
                 "avec sa propre base de données.")


def make_span(trace_id, blocked_pct):
    now = time.time()
    if random.random() < 0.15:
        model, pin, pout = random.choice(MODELS)
        tin, tout = random.randint(300, 3000), random.randint(50, 800)
        return {
            "trace_id": trace_id, "span_id": uuid.uuid4().hex[:16], "span_type": "llm_call",
            "timestamp": now, "latency_ms": random.uniform(300, 2200),
            "input_data": {"prompt": random.choice(PROMPTS), "model": model},
            "output_data": {"response": "ok"}, "security_checks": [], "blocked": False,
            "cost_usd": tin / 1e6 * pin + tout / 1e6 * pout, "input_tokens": tin, "output_tokens": tout,
        }
    blocked = random.random() * 100 < blocked_pct
    tool = random.choice(TOOLS)
    checks = [{"check_name": "runtime_risk", "passed": False, "risk_level": "high",
               "details": "synthetic load test"}] if blocked else []
    return {
        "trace_id": trace_id, "span_id": uuid.uuid4().hex[:16], "span_type": "tool_call",
        "timestamp": now, "latency_ms": random.uniform(2, 120),
        "input_data": {"tool": tool, "params": {"id": random.randint(1, 99999)}},
        "output_data": {"blocked": True} if blocked else {"result": "ok"},
        "security_checks": checks, "blocked": blocked,
        "block_reason": "[RUNTIME DENY] synthetic" if blocked else None,
        "taint_level": random.choice([None, "PUBLIC", "INTERNAL"]), "risk_score": random.uniform(0, 30),
    }


def pct(values, p):
    if not values:
        return float("nan")
    values = sorted(values)
    return values[min(len(values) - 1, round(p / 100 * (len(values) - 1)))]


class Ctx:
    def __init__(self, args):
        self.args = args
        self.t0 = time.monotonic()
        self.end = self.t0 + args.ramp + args.duration
        self.inflight = 0
        self.client_dropped = 0
        self.records = []  # (t_depuis_début, sortie, ms)
        self.lag = []
        self.probes = {}  # route -> [(statut, ms)]
        self.burst_start = self.t0 + args.ramp + args.duration * 0.6
        self.burst_end = self.burst_start + args.burst_seconds

    def rate_mult(self, now):
        if self.args.burst_factor > 1 and self.burst_start <= now < self.burst_end:
            return self.args.burst_factor
        return 1.0

    def record(self, outcome, ms):
        self.records.append((time.monotonic() - self.t0, outcome, ms))


def outcome_of(status):
    if 200 <= status < 300:
        return "ok"
    if status == 429:
        return "429"
    if status in (401, 403):
        return "auth"
    return "4xx" if status < 500 else "5xx"


async def send(ctx, client, agent_id, span):
    t0 = time.perf_counter()
    try:
        r = await client.post("/span", json=span, headers={"X-Agent-Id": agent_id})
        ctx.record(outcome_of(r.status_code), (time.perf_counter() - t0) * 1000)
    except httpx.TimeoutException:
        ctx.record("timeout", None)
    except httpx.HTTPError:
        ctx.record("error", None)
    finally:
        ctx.inflight -= 1


async def agent_loop(ctx, client, idx):
    a = ctx.args
    agent_id = f"load-agent-{a.agent_offset + idx:05d}"
    await asyncio.sleep(a.ramp * idx / max(1, a.agents))  # montée en charge progressive
    trace, in_trace = uuid.uuid4().hex, 0
    nxt = time.monotonic()
    while True:
        nxt += random.expovariate(a.rate * ctx.rate_mult(time.monotonic()))
        delay = nxt - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        if time.monotonic() >= ctx.end:
            return
        if ctx.inflight >= a.max_inflight:  # garde-fou du GÉNÉRATEUR, compté à part
            ctx.client_dropped += 1
            continue
        if in_trace >= 25:
            trace, in_trace = uuid.uuid4().hex, 0
        in_trace += 1
        ctx.inflight += 1
        asyncio.create_task(send(ctx, client, agent_id, make_span(trace, a.blocked_pct)))


async def lag_monitor(ctx):
    while time.monotonic() < ctx.end + 1:
        t = time.perf_counter()
        await asyncio.sleep(0.1)
        ctx.lag.append(max(0.0, (time.perf_counter() - t - 0.1) * 1000))


async def probe_dashboard(ctx, client):
    routes = ["/api/audit/trail?limit=300", "/api/audit/summary", "/api/cost/trend"]
    while time.monotonic() < ctx.end:
        await asyncio.sleep(ctx.args.report_every)
        for route in routes:
            t = time.perf_counter()
            try:
                r = await client.get(route)
                ctx.probes.setdefault(route, []).append((r.status_code, (time.perf_counter() - t) * 1000))
            except httpx.HTTPError:
                ctx.probes.setdefault(route, []).append(("erreur", None))


async def reporter(ctx):
    last = 0
    while time.monotonic() < ctx.end:
        await asyncio.sleep(ctx.args.report_every)
        now = time.monotonic() - ctx.t0
        window = [r for r in ctx.records[last:]]
        last = len(ctx.records)
        n = max(1e-9, ctx.args.report_every)
        ok = [r[2] for r in window if r[1] == "ok"]
        bad = len(window) - len(ok)
        active = min(ctx.args.agents, int(ctx.args.agents * min(1.0, now / max(1e-9, ctx.args.ramp)))) if ctx.args.ramp else ctx.args.agents
        print(f"t={now:5.0f}s agents={active:5d} ok={len(ok)/n:7.0f}/s non-ok={bad/n:6.1f}/s "
              f"p50={pct(ok, 50):6.0f}ms p95={pct(ok, 95):6.0f}ms p99={pct(ok, 99):6.0f}ms "
              f"en vol={ctx.inflight} abandonnés(client)={ctx.client_dropped}", flush=True)


def summarize(ctx):
    a = ctx.args
    recs = ctx.records
    ok = [r[2] for r in recs if r[1] == "ok"]
    counts = {}
    for _, o, _ in recs:
        counts[o] = counts.get(o, 0) + 1
    total_s = max(1.0, a.ramp + a.duration)
    steady_lo, steady_hi = a.ramp, a.ramp + a.duration * 0.6
    steady = [r for r in recs if steady_lo <= r[0] < steady_hi]
    steady_ok = [r[2] for r in steady if r[1] == "ok"]

    # capacité soutenue : meilleure fenêtre glissante de 10 s respectant le SLA
    sec = math.ceil(total_s) + 2
    okc, badc, lat = [0] * sec, [0] * sec, [[] for _ in range(sec)]
    for t, o, ms in recs:
        i = int(t)
        if i < sec:
            if o == "ok":
                okc[i] += 1
                lat[i].append(ms)
            else:
                badc[i] += 1
    best, win = None, 10
    for s in range(sec - win + 1):
        n_ok, n_bad = sum(okc[s:s + win]), sum(badc[s:s + win])
        if n_ok + n_bad == 0:
            continue
        window_lat = [x for k in range(s, s + win) for x in lat[k]]
        err = 100 * n_bad / (n_ok + n_bad)
        if err <= a.sla_error and pct(window_lat, 99) <= a.sla_p99:
            rate = n_ok / win
            if best is None or rate > best["ok_per_s"]:
                best = {"ok_per_s": round(rate, 1), "from_s": s, "p99_ms": round(pct(window_lat, 99), 1), "error_pct": round(err, 2)}

    probes = {}
    for route, rows in ctx.probes.items():
        ms = [m for st, m in rows if m is not None and st == 200]
        probes[route] = {"n": len(rows), "non_200": sum(1 for st, _ in rows if st != 200),
                         "p50_ms": round(pct(ms, 50), 1), "p95_ms": round(pct(ms, 95), 1)}
    return {
        "config": {k: getattr(a, k) for k in ("agents", "rate", "ramp", "duration", "burst_factor", "burst_seconds", "blocked_pct")},
        "target_spans_per_s_steady": round(a.agents * a.rate, 1),
        "requests": len(recs), "outcomes": counts, "client_dropped": ctx.client_dropped,
        "ok_per_s_overall": round(len(ok) / total_s, 1),
        "ok_per_s_steady": round(len(steady_ok) / max(1.0, steady_hi - steady_lo), 1),
        "latency_ok_ms": {"p50": round(pct(ok, 50), 1), "p95": round(pct(ok, 95), 1), "p99": round(pct(ok, 99), 1),
                          "max": round(max(ok), 1) if ok else None},
        "latency_ok_steady_ms": {"p50": round(pct(steady_ok, 50), 1), "p95": round(pct(steady_ok, 95), 1),
                                 "p99": round(pct(steady_ok, 99), 1)},
        "sustained_capacity": best, "sla": {"error_pct_max": a.sla_error, "p99_ms_max": a.sla_p99},
        "generator_loop_lag_ms": {"p50": round(pct(ctx.lag, 50), 1), "p99": round(pct(ctx.lag, 99), 1)},
        "dashboard_probes": probes,
        "machine": {"python": platform.python_version(), "os": platform.platform(), "cpus": os.cpu_count()},
    }


def print_summary(s):
    print("\n" + "=" * 78)
    print(f"RÉSULTAT : {s['config']['agents']} agents × {s['config']['rate']} span/s "
          f"(objectif stable ≈ {s['target_spans_per_s_steady']} spans/s)")
    print("=" * 78)
    print(f"requêtes : {s['requests']}  sorties : {s['outcomes']}  abandonnées côté générateur : {s['client_dropped']}")
    print(f"débit réussi : {s['ok_per_s_overall']}/s en moyenne · {s['ok_per_s_steady']}/s en régime stable")
    L, S = s["latency_ok_ms"], s["latency_ok_steady_ms"]
    print(f"latence d'ingestion (réussis) : p50 {L['p50']} · p95 {L['p95']} · p99 {L['p99']} · max {L['max']} ms "
          f"| régime stable : p50 {S['p50']} · p95 {S['p95']} · p99 {S['p99']} ms")
    c = s["sustained_capacity"]
    sla = s["sla"]
    if c:
        print(f"CAPACITÉ SOUTENUE MESURÉE : {c['ok_per_s']} spans/s sur 10 s "
              f"(erreurs {c['error_pct']} %, p99 {c['p99_ms']} ms ; SLA : erreurs ≤ {sla['error_pct_max']} %, p99 ≤ {sla['p99_ms_max']} ms)")
    else:
        print(f"CAPACITÉ SOUTENUE : aucune fenêtre de 10 s n'a respecté le SLA (erreurs ≤ {sla['error_pct_max']} %, "
              f"p99 ≤ {sla['p99_ms_max']} ms) : le collector plafonne en dessous de la charge demandée.")
    g = s["generator_loop_lag_ms"]
    warn = "  <- le GÉNÉRATEUR sature : lance plusieurs processus (--agent-offset)" if g["p99"] > 50 else ""
    print(f"retard de la boucle du générateur : p50 {g['p50']} ms, p99 {g['p99']} ms{warn}")
    for route, p in s["dashboard_probes"].items():
        print(f"dashboard {route:<30} p50 {p['p50_ms']} ms · p95 {p['p95_ms']} ms · réponses non 200 : {p['non_200']}/{p['n']}")


def _write_summary(path: str, summary: dict) -> None:
    """Écrit le résumé JSON sur disque (appelé hors event loop)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)


async def main_async(args):
    key = args.api_key or os.getenv("AGENTGUARD_API_KEY")
    if not key:
        sys.exit("Clé API manquante : --api-key ou variable AGENTGUARD_API_KEY.")

    ctx = Ctx(args)
    limits = httpx.Limits(max_connections=args.connections, max_keepalive_connections=args.connections)

    async with httpx.AsyncClient(
        base_url=args.url.rstrip("/"),
        limits=limits,
        timeout=httpx.Timeout(args.timeout),
        headers={"X-API-Key": key, "X-Agent-Sdk": "load-demo"},
    ) as client:
        tasks = [asyncio.create_task(agent_loop(ctx, client, i)) for i in range(args.agents)]
        tasks += [asyncio.create_task(lag_monitor(ctx)), asyncio.create_task(reporter(ctx))]
        if args.probe_dashboard:
            tasks.append(asyncio.create_task(probe_dashboard(ctx, client)))
        await asyncio.gather(*tasks)

        deadline = time.monotonic() + args.timeout + 2
        while ctx.inflight > 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.1)

    summary = summarize(ctx)
    print_summary(summary)

    if args.out:
        await asyncio.to_thread(_write_summary, args.out, summary)
        print(f"\nrésultats écrits dans {args.out}")
        
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--agents", type=int, default=200)
    ap.add_argument("--agent-offset", type=int, default=0, help="numéro du 1er agent (pour lancer plusieurs processus)")
    ap.add_argument("--rate", type=float, default=0.2, help="spans par seconde et par agent (moyenne de Poisson)")
    ap.add_argument("--ramp", type=float, default=20, help="secondes pour atteindre tous les agents")
    ap.add_argument("--duration", type=float, default=60, help="secondes à pleine charge après la montée")
    ap.add_argument("--burst-factor", type=float, default=1.0, help="x fois la cadence pendant le pic (1 = pas de pic)")
    ap.add_argument("--burst-seconds", type=float, default=10)
    ap.add_argument("--blocked-pct", type=float, default=3.0)
    ap.add_argument("--connections", type=int, default=200)
    ap.add_argument("--max-inflight", type=int, default=3000)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--report-every", type=float, default=5.0)
    ap.add_argument("--probe-dashboard", action="store_true", help="mesure aussi la réactivité des pages du dashboard")
    ap.add_argument("--sla-error", type=float, default=1.0, help="% d'erreurs max pour compter la capacité")
    ap.add_argument("--sla-p99", type=float, default=1000.0, help="p99 max (ms) pour compter la capacité")
    ap.add_argument("--staging", action="store_true", help="confirme une cible distante de TEST avec sa propre base")
    ap.add_argument("--allow-production", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    check_target(args.url, args.staging, args.allow_production)
    print(f"cible {args.url} · {args.agents} agents × {args.rate} span/s · montée {args.ramp:.0f}s · "
          f"pleine charge {args.duration:.0f}s" + (f" · pic ×{args.burst_factor:g}" if args.burst_factor > 1 else ""))
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()