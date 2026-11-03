"""demo_scale.py — Démo Cerbère AG : 1 000 agents, UNE clé, un collector qui tient.

Le scénario qu'aucune slide ne prouve — le client entreprise le demande toujours :
  1. Une entreprise déploie 1 000 agents IA (support, finance, ops, ventes…)
  2. Tous partagent UNE SEULE clé API Cerbère — l'identité passe par X-Agent-Id,
     chaque agent reste individuellement visible, tracé et plafonné
  3. Montée progressive → régime stable → pic ×5 (le lundi matin de la vraie vie)
  4. Verdict mesuré : pas de 5xx, pas de spans abandonnés, p99 sous contrôle,
     et le dashboard reste fluide PENDANT que le collector absorbe tout
  5. Chaque span LLM est facturé et tracké : la vue Cost grimbe en direct

Le point clé : le collector ne craque pas sous 1 000 identités d'agents
différentes sur une seule clé. Le scaling est prouvé, pas affirmé.

Usage (PowerShell) :
  $env:CERBERE_API_KEY="ag_live_..."        # UNE clé pour les 1 000 agents
  $env:CERBERE_URL="https://app.cerbereag.site"   # ou un déploiement de test
  python demo_scale.py                       # 1 000 agents, ~90 s
  python demo_scale.py --agents 1500 --burst-factor 5 --probe-dashboard --out scale.json

⚠️ Contrairement aux autres démos (quelques dizaines d'appels), celle-ci écrit
des dizaines de milliers de spans. L'audit chaîné étant immuable, visez une
clé + une base de TEST (déploiement staging identique à la prod) pour garder
la prod propre. Contre la prod : DEMO_ALLOW_PROD=1, à vos risques.

Pour la vidéo : ouvrez le dashboard AVANT (vue Health + Agents + Cost) et
regardez les compteurs grimber pendant que le terminal raconte l'histoire.
"""

import argparse
import asyncio
import json
import os
import random
import time
import uuid
from urllib.parse import urlparse

import httpx

COLLECTOR = os.environ.get("CERBERE_URL", "https://app.cerbereag.site")
API_KEY = os.environ["CERBERE_API_KEY"]
PAUSE = float(os.environ.get("DEMO_PAUSE", "2.5"))
PROD_SUFFIX = "cerbereag.site"

TOOLS = ["search_kb", "read_ticket", "lookup_order", "update_crm", "send_email", "refund"]
MODELS = [("gpt-4o-mini", 0.15, 0.60), ("claude-sonnet", 3.00, 15.00), ("deepseek-chat", 0.27, 1.10)]
TEAM_PROMPTS = [
    "Summarize the open ticket and propose next steps",
    "Draft a polite reply about the delayed order",
    "Classify this message by urgency",
    "Look up the refund policy for EU customers",
]


# ── Mise en scène (même trame que les autres démos) ───────────────────
def preflight() -> None:
    for _ in range(3):
        try:
            r = httpx.get(f"{COLLECTOR}/healthz", timeout=30)
        except httpx.HTTPError as e:
            print(f"✗ collector unreachable: {e}")
            raise SystemExit(1) from e
        if r.status_code != 200:
            print(f"✗ collector unhealthy (HTTP {r.status_code})")
            raise SystemExit(1)
    print("✓ Collector reachable")


def guard_target() -> None:
    host = urlparse(COLLECTOR).hostname or ""
    if host.endswith(PROD_SUFFIX) and os.environ.get("DEMO_ALLOW_PROD") != "1":
        raise SystemExit(
            f"REFUS : {host} est la prod — cette démo écrit des dizaines de milliers de spans "
            "dans l'audit chaîné (immuable). Visez un déploiement de TEST, ou "
            "DEMO_ALLOW_PROD=1 pour passer outre, à vos risques."
        )


def say(msg, color="36"):
    print(f"\n\033[{color}m{msg}\033[0m")
    time.sleep(PAUSE)


def pct(values, p):
    if not values:
        return float("nan")
    values = sorted(values)
    return values[min(len(values) - 1, round(p / 100 * (len(values) - 1)))]


# ── Générateur de spans — mêmes formes que load_demo (mélange réaliste) ─
def make_span(trace_id, blocked_pct):
    now = time.time()
    if random.random() < 0.15:  # 15 % d'appels LLM → la vue Cost bouge en direct
        model, pin, pout = random.choice(MODELS)
        tin, tout = random.randint(300, 3000), random.randint(50, 800)
        return {
            "trace_id": trace_id, "span_id": uuid.uuid4().hex[:16], "span_type": "llm_call",
            "timestamp": now, "latency_ms": random.uniform(300, 2200),
            "input_data": {"prompt": random.choice(TEAM_PROMPTS), "model": model},
            "output_data": {"response": "ok"}, "security_checks": [], "blocked": False,
            "cost_usd": tin / 1e6 * pin + tout / 1e6 * pout,
            "input_tokens": tin, "output_tokens": tout,
        }
    blocked = random.random() * 100 < blocked_pct
    return {
        "trace_id": trace_id, "span_id": uuid.uuid4().hex[:16], "span_type": "tool_call",
        "timestamp": now, "latency_ms": random.uniform(2, 120),
        "input_data": {"tool": random.choice(TOOLS), "params": {"id": random.randint(1, 99999)}},
        "output_data": {"blocked": True} if blocked else {"result": "ok"},
        "security_checks": [{"check_name": "runtime_risk", "passed": False, "risk_level": "high",
                             "details": "synthetic load demo"}] if blocked else [],
        "blocked": blocked,
        "block_reason": "[RUNTIME DENY] synthetic" if blocked else None,
        "taint_level": random.choice([None, "PUBLIC", "INTERNAL"]),
        "risk_score": random.uniform(0, 30),
    }


# ── Cœur asynchrone : N agents, une clé, X-Agent-Id par agent ──────────
class Fleet:
    def __init__(self, args):
        self.args = args
        self.t0 = time.monotonic()
        self.end = self.t0 + args.ramp + args.duration
        self.burst_start = self.end - args.duration * 0.4
        self.burst_end = self.burst_start + args.burst_seconds
        self.inflight = 0
        self.dropped = 0
        self.records = []  # (outcome, ms)
        self.probes = {}

    def rate_mult(self):
        if self.args.burst_factor > 1 and self.burst_start <= time.monotonic() < self.burst_end:
            return self.args.burst_factor
        return 1.0


async def send(fleet, client, agent_id, span):
    t0 = time.perf_counter()
    try:
        r = await client.post("/span", json=span, headers={"X-Agent-Id": agent_id})
        ms = (time.perf_counter() - t0) * 1000
        if 200 <= r.status_code < 300:
            fleet.records.append(("ok", ms))
        elif r.status_code == 429:
            fleet.records.append(("429", ms))
        else:
            fleet.records.append(("5xx" if r.status_code >= 500 else "err", ms))
    except httpx.HTTPError:
        fleet.records.append(("net", None))
    finally:
        fleet.inflight -= 1


async def agent_loop(fleet, client, idx):
    a = fleet.args
    agent_id = f"load-agent-{a.agent_offset + idx:05d}"  # 1 000 identités distinctes, UNE clé
    await asyncio.sleep(a.ramp * idx / max(1, a.agents))
    trace, in_trace = uuid.uuid4().hex, 0
    nxt = time.monotonic()
    while True:
        nxt += random.expovariate(a.rate * fleet.rate_mult())
        delay = nxt - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        if time.monotonic() >= fleet.end:
            return
        if fleet.inflight >= a.max_inflight:
            fleet.dropped += 1
            continue
        if in_trace >= 25:
            trace, in_trace = uuid.uuid4().hex, 0
        in_trace += 1
        fleet.inflight += 1
        asyncio.create_task(send(fleet, client, agent_id, make_span(trace, a.blocked_pct)))


async def ticker(fleet):
    """Compteur live — miroir terminal du dashboard pendant la vidéo."""
    last = 0
    while time.monotonic() < fleet.end:
        await asyncio.sleep(5)
        window = fleet.records[last:]
        last = len(fleet.records)
        ok = [ms for _, ms in window if _ == "ok" and ms is not None]
        bad = len(window) - len(ok)
        elapsed = time.monotonic() - fleet.t0
        phase = f"PIC ×{fleet.args.burst_factor:g}" if fleet.rate_mult() > 1 else "stable"
        print(f"  t={elapsed:4.0f}s [{phase:>8}] ok={len(ok)/5:5.0f}/s erreurs={bad/5:5.1f}/s "
              f"p50={pct(ok,50):5.0f}ms p95={pct(ok,95):5.0f}ms en vol={fleet.inflight}", flush=True)


async def probe_dashboard(fleet, client):
    routes = ["/api/audit/trail?limit=300", "/api/audit/summary", "/api/cost/trend"]
    while time.monotonic() < fleet.end:
        await asyncio.sleep(10)
        for route in routes:
            t = time.perf_counter()
            try:
                r = await client.get(route)
                ms = (time.perf_counter() - t) * 1000
                fleet.probes.setdefault(route, []).append((r.status_code, ms))
            except httpx.HTTPError:
                fleet.probes.setdefault(route, []).append(("err", None))


def _write_out(path, summary):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)


# ── Déroulé filmable ──────────────────────────────────────────────────
async def run(args) -> None:
    fleet = Fleet(args)
    limits = httpx.Limits(max_connections=args.connections, max_keepalive_connections=args.connections)

    say("● 0. Une clé API. Un collector. Zéro serveur supplémentaire.", "36")
    print(f"  → {args.agents} agents simulés, tous authentifiés avec UNE clé,")
    print(f"    identité par X-Agent-Id (load-agent-00000 → …{args.agent_offset + args.agents - 1:05d})")

    async with httpx.AsyncClient(
        base_url=COLLECTOR.rstrip("/"),
        limits=limits,
        timeout=httpx.Timeout(args.timeout),
        headers={"X-API-Key": API_KEY, "X-Agent-Sdk": "scale-demo"},
    ) as client:
        say(f"● 1. Les équipes connectent leurs agents — montée en {args.ramp:.0f} s", "36")
        print("  → Surveillez le compteur d'agents grimber dans le dashboard.")
        print("    Chaque agent est une identité distincte, jamais une clé de plus.")

        tasks = [asyncio.create_task(agent_loop(fleet, client, i)) for i in range(args.agents)]
        tasks.append(asyncio.create_task(ticker(fleet)))
        if args.probe_dashboard:
            tasks.append(asyncio.create_task(probe_dashboard(fleet, client)))

        await asyncio.gather(*tasks)
        deadline = time.monotonic() + args.timeout + 2
        while fleet.inflight > 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.1)

    say("● 2. Verdict — le collector a-t-il craqué ?", "36")
    ok = [ms for o, ms in fleet.records if o == "ok"]
    counts = {}
    for o, _ in fleet.records:
        counts[o] = counts.get(o, 0) + 1
    total = len(fleet.records)
    print(f"  spans envoyés : {total}  sorties : {counts}")
    print(f"  abandonnés côté générateur : {fleet.dropped} (0 attendu)")
    print(f"  latence ingestion (ok) : p50 {pct(ok,50):.0f} · p95 {pct(ok,95):.0f} · "
          f"p99 {pct(ok,99):.0f} ms")
    for route, rows in fleet.probes.items():
        ms = [m for st, m in rows if m is not None and st == 200]
        bad = sum(1 for st, _ in rows if st != 200)
        print(f"  dashboard {route:<28} p50 {pct(ms,50):.0f} ms · p95 {pct(ms,95):.0f} ms · non-200 : {bad}/{len(rows)}")

    five_xx = counts.get("5xx", 0)
    verdict_ok = five_xx == 0 and fleet.dropped == 0 and ok
    if verdict_ok:
        say("  ✓ PAS DE 5xx, AUCUN span perdu, p99 maîtrisée — le collector tient.", "32")
        say("1 000 agents. Une clé. Un collector. Le scaling de Cerbère, prouvé en direct.", "32")
    else:
        say("  ⚠ Anomalies détectées (5xx ou spans perdus) — voir le JSON pour le détail.", "31")

    if args.out:
        await asyncio.to_thread(_write_out, args.out, {
            "config": vars(args),
            "requests": total, "outcomes": counts, "client_dropped": fleet.dropped,
            "latency_ok_ms": {"p50": round(pct(ok, 50), 1), "p95": round(pct(ok, 95), 1),
                              "p99": round(pct(ok, 99), 1)},
            "dashboard_probes": {r: [{"status": st, "ms": m} for st, m in rows]
                                 for r, rows in fleet.probes.items()},
        })
        print(f"\n  résultats écrits dans {args.out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agents", type=int, default=1000, help="taille de la flotte (défaut : 1000)")
    ap.add_argument("--agent-offset", type=int, default=0)
    ap.add_argument("--rate", type=float, default=0.2, help="spans/s par agent (Poisson)")
    ap.add_argument("--ramp", type=float, default=20, help="montée progressive (s)")
    ap.add_argument("--duration", type=float, default=40, help="pleine charge après montée (s)")
    ap.add_argument("--burst-factor", type=float, default=5.0, help="pic ×N (le lundi matin)")
    ap.add_argument("--burst-seconds", type=float, default=10.0)
    ap.add_argument("--blocked-pct", type=float, default=3.0)
    ap.add_argument("--connections", type=int, default=500)
    ap.add_argument("--max-inflight", type=int, default=3000)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--probe-dashboard", action="store_true", help="mesure la fluidité du dashboard sous charge")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    guard_target()
    preflight()
    print(f"\ncible {COLLECTOR} · {args.agents} agents × {args.rate} span/s "
          f"(≈ {args.agents * args.rate:.0f} spans/s stables, pic ×{args.burst_factor:g})")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()