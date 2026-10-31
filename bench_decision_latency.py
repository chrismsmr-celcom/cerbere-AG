"""Mesure L2 : latence complète de la décision de sécurité Cerbère.

Sépare la mesure en couches conformément à bench/methodology.md :
  L2 — appel de l'outil protégé à corps NO-OP : tout le temps mesuré
       provient du SDK (décision + mise en file du span), rien de l'outil.
       . chaud (snapshot frais)
       . démarrage à froid (première lecture statut/mode incluse)
       . snapshot périmé (TTL expiré — vérifie le fail-safe vers enforce)
  L3 concurrent — 200 appels depuis un pool de 32 threads.

Si une méthode de décision isolable existe (ex. decide/check), le mode
`discover` la liste avec sa signature pour l'ajouter via
AGENTGUARD_DECIDE_ATTR (mesure encore plus pure, sans mise en file).

Exporte les résultats BRUTS par appel (CSV) + agrégats (JSON).

Usage (collecteur RÉEL obligatoire) :
    AGENTGUARD_COLLECTOR_URL=http://127.0.0.1:8000 BENCH_N=200 python bench_decision_latency.py
    python bench_decision_latency.py discover   # liste les callables de l'instance
"""

from __future__ import annotations

import csv
import inspect
import json
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ── configuration ───────────────────────────────────────────────────────────

N = int(os.environ.get("BENCH_N", "200"))  # appels mesurés par scénario
WARMUP = 10  # appels non mesurés
POOL = 32  # threads pour le scénario concurrent
OUT = Path(os.environ.get("BENCH_OUT", "bench/results/run"))
COLD_INSTANCES = 10  # instances neuves mesurées pour le démarrage à froid
STALE_SAMPLES = 5  # appels après expiration du TTL de mode (chacun attend TTL)

DECIDE_ATTRS = (
    "decide",
    "check",
    "decision",
    "guard",
    "verdict",
    "evaluate",
    "verify",
    "authorize",
    "_decide",
    "_check_decision",
    "_make_decision",
)


def _make_guard(url: str):
    from agentguard import AgentGuard  # import tardif : lit les variables d'env

    return AgentGuard(
        collector_url=url,
        api_key=os.environ.get("AGENTGUARD_API_KEY", "bench-key"),
        agent_id=os.environ.get("AGENTGUARD_AGENT_ID", "bench"),
    )


def _make_tool(guard):
    """Outil protégé à corps NO-OP : le temps mesuré est SDK pur."""

    def noop(q: str) -> str:
        return "ok"

    wrapped = getattr(guard, "guard_tool_call", None)
    if not callable(wrapped):
        raise SystemExit("guard_tool_call introuvable : adaptez _make_tool.")
    return wrapped(noop)


# ── utilitaires de mesure ───────────────────────────────────────────────────


def _now_ns() -> int:
    return time.perf_counter_ns()


def _stats(samples_ns: list[int]) -> dict:
    ms = [v / 1_000_000 for v in samples_ns]
    if not ms:
        return {"n": 0}
    ordered = sorted(ms)

    def pct(p: float) -> float:
        return ordered[min(len(ordered) - 1, round(p / 100 * len(ordered)) - 1)]

    return {
        "n": len(ms),
        "min_ms": round(min(ms), 4),
        "p50_ms": round(pct(50), 4),
        "p95_ms": round(pct(95), 4),
        "p99_ms": round(pct(99), 4),
        "max_ms": round(max(ms), 4),
        "mean_ms": round(statistics.fmean(ms), 4),
        "stddev_ms": round(statistics.pstdev(ms), 4) if len(ms) > 1 else 0.0,
    }


def _write_csv(path: Path, samples_ns: list[int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["call_index", "duration_ns"])
        w.writerows(enumerate(samples_ns, start=1))


def _resolve_decider(guard):
    """Optionnel : méthode de décision isolable, si elle existe sur l'instance."""
    attr = os.environ.get("AGENTGUARD_DECIDE_ATTR")
    for name in ([attr] if attr else []) + list(DECIDE_ATTRS):
        obj = getattr(guard, name, None)
        if callable(obj):
            return name, obj
    return None, None


def _discover(guard) -> None:
    """Liste tous les callables de l'instance avec leur signature : sert à
    repérer une méthode de décision isolable (ex. decide) pour AGENTGUARD_DECIDE_ATTR."""
    print("── callables de l'instance AgentGuard ──")
    for name in sorted(vars(guard)):
        try:
            obj = getattr(guard, name)
            if callable(obj):
                try:
                    sig = str(inspect.signature(obj))
                except (TypeError, ValueError):
                    sig = "(signature indisponible)"
                print(f"  {name}{sig}")
        except Exception:
            continue
    print("Méthodes de classe héritées non listées. Si une méthode de décision")
    print("apparaît, relancer avec AGENTGUARD_DECIDE_ATTR=<nom>.")


# ── scénarios ──────────────────────────────────────────────────────────────


def _timed_call(tool, **kwargs) -> tuple[int, bool]:
    """Un appel chronométré ; retourne (durée_ns, bloqué). Un blocage
    fail-safe (exception) est un RÉSULTAT, pas une erreur du bench."""
    t0 = _now_ns()
    try:
        tool(**kwargs)
        return _now_ns() - t0, False
    except Exception:  # l'outil protégé N'A PAS été exécuté
        return _now_ns() - t0, True


def scenario_chaud(tool) -> tuple[list[int], int]:
    """L2 chaud : appels de l'outil protégé, snapshot frais, corps no-op."""
    for _ in range(WARMUP):  # préchauffage non mesuré (tolère un blocage)
        try:
            tool(q="warmup")
        except Exception:
            pass
    samples: list[int] = []
    blocked = 0
    for i in range(N):
        dur, blk = _timed_call(tool, q=f"bench {i}")
        samples.append(dur)
        blocked += int(blk)
    return samples, blocked


def scenario_decideur(decider) -> list[int]:
    """L2 pur : méthode de décision isolable, sans mise en file du span."""
    payload = {"tool": "fetch_url", "q": "demo"}
    try:
        decider(**payload)
        call = lambda **kw: decider(**kw)
    except TypeError:
        call = lambda **kw: decider(kw)
    for _ in range(WARMUP):
        call(**payload)
    samples = []
    for _ in range(N):
        t0 = _now_ns()
        call(**payload)
        samples.append(_now_ns() - t0)
    return samples


def scenario_froid(url: str) -> list[int]:
    """Nouvelle instance à chaque itération : premier appel, lecture
    statut/mode synchrone incluse."""
    samples = []
    for _ in range(COLD_INSTANCES):
        guard = _make_guard(url)
        tool = _make_tool(guard)
        t0 = _now_ns()
        tool(q="premier appel")
        samples.append(_now_ns() - t0)
        closer = getattr(guard, "close", None)
        if callable(closer):
            closer()
    return samples


def scenario_stale(tool) -> tuple[list[int], int]:
    """Attend l'expiration du TTL de mode puis mesure : le fail-safe doit
    bloquer (exception d'un agent déconnecté = RÉSULTAT ATTENDU, compté comme
    « bloqué », pas comme une erreur du bench)."""
    ttl = float(os.environ.get("AGENTGUARD_MODE_TTL", "2"))
    samples: list[int] = []
    blocked = 0
    for i in range(STALE_SAMPLES):
        time.sleep(ttl + 0.5)  # TTL expiré : relecture synchrone garantie
        t0 = _now_ns()
        try:
            tool(q=f"stale {i}")
        except Exception:  # fail-safe : action bloquée = attendu
            blocked += 1  # l'outil protégé N'A PAS été exécuté
        samples.append(_now_ns() - t0)
    return samples, blocked


def scenario_concurrent(tool) -> tuple[list[int], int]:
    """200 appels depuis un pool de threads : tenue sous charge."""
    samples: list[int] = []

    def one(i: int) -> None:
        dur, blk = _timed_call(tool, q=str(i))
        samples.append(dur)  # list.append atomique en CPython
        if blk:
            blocked_flags.append(1)  # comptage thread-safe via append

    blocked_flags: list[int] = []
    with ThreadPoolExecutor(max_workers=POOL) as pool:
        list(pool.map(one, range(N)))
    return samples, len(blocked_flags)


# ── programme principal ─────────────────────────────────────────────────────


def main() -> None:
    url = os.environ.get("AGENTGUARD_COLLECTOR_URL")
    if not url:
        raise SystemExit("AGENTGUARD_COLLECTOR_URL est requis (collecteur RÉEL).")

    os.environ.setdefault("AGENTGUARD_ASYNC_IO", "true")  # télémétrie en arrière-plan
    os.environ.setdefault("AGENTGUARD_MODE_TTL", "2")
    os.environ.setdefault("AGENTGUARD_STATUS_TTL", "2")

    guard = _make_guard(url)

    if len(sys.argv) > 1 and sys.argv[1] == "discover":
        _discover(guard)
        return

    tool = _make_tool(guard)
    name, decider = _resolve_decider(guard)

    results: dict[str, list[int]] = {}
    chaud_samples, chaud_blocked = scenario_chaud(tool)
    results["L2_chaud"] = chaud_samples
    if decider is not None:
        results[f"L2_decideur_{name}"] = scenario_decideur(decider)
    results["L2_froid"] = scenario_froid(url)
    stale_samples, stale_blocked = scenario_stale(tool)
    results["L2_stale"] = stale_samples
    conc_samples, conc_blocked = scenario_concurrent(tool)
    results["L3_concurrent"] = conc_samples

    flush = getattr(guard, "flush", None)
    if callable(flush):
        flush(30)
    closer = getattr(guard, "close", None)
    if callable(closer):
        closer()

    sender = getattr(guard, "_sender", None)
    summary = {
        "sdk_version": os.environ.get("AGENTGUARD_VERSION", "inconnu"),
        "collector_url": url,
        "n_per_scenario": N,
        "python": sys.version,
        "stats": {k: _stats(v) for k, v in results.items()},
        "stale_blocked_calls": stale_blocked,  # fail-safe attendu en mode dégradé
        "chaud_blocked_calls": chaud_blocked,
        "concurrent_blocked_calls": conc_blocked,
        "counters": (
            {
                "submitted": getattr(sender, "submitted", None),
                "delivered": getattr(sender, "delivered", None),
                "failed": getattr(sender, "failed", None),
                "dropped": getattr(sender, "dropped", None),
                "pending": getattr(sender, "pending", None),
            }
            if sender is not None
            else "expéditeur indisponible"
        ),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    for k, samples in results.items():
        _write_csv(OUT / f"raw_{k}.csv", samples)
    (OUT / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"Résultats bruts : {OUT}/")


if __name__ == "__main__":
    main()
