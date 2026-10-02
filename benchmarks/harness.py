"""Harnais de benchmark : rejoue unified.jsonl contre Cerbere et calcule les métriques.

Usage :
    python -m benchmarks.harness --corpus benchmarks/corpus/unified.jsonl \
        --base-url http://127.0.0.1:8000 --sample 1000
"""
from __future__ import annotations

import argparse
import json
import random
import time
from collections import Counter, defaultdict
from pathlib import Path

import requests

def load_corpus(path: Path, sample: int | None, seed: int = 42) -> list[dict]:
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if sample and sample < len(rows):
        # Échantillon stratifié : moitié attaques, moitié bénignes
        attacks = [r for r in rows if r["label"] == "attack"]
        benign = [r for r in rows if r["label"] == "benign"]
        rng = random.Random(seed)
        half = sample // 2
        rows = rng.sample(attacks, min(half, len(attacks))) + \
               rng.sample(benign, min(sample - half, len(benign)))
    return rows

def post_span(base_url: str, rec: dict, api_key: str | None) -> tuple[str | None, float]:
    span = dict(rec["span"])
    span.setdefault("start_time", time.time())
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{base_url}/span", json=span, headers=headers, timeout=30)
        lat = (time.perf_counter() - t0) * 1000
        if r.status_code == 201:
            body = r.json()
            # Adapter selon la vraie réponse de /span :
            decision = body.get("decision") or body.get("status") or "allow"
        elif r.status_code == 429:
            decision, lat = "block", lat   # rate-limit = bloque
        elif r.status_code == 403:
            decision = "block"
        else:
            decision = None
        return decision, lat
    except requests.RequestException as e:  # noqa: BLE001
        print(f"[harness] erreur réseau: {e}")
        return None, 0.0

def evaluate(rows: list[dict], base_url: str, api_key: str | None) -> dict:
    results = []
    latencies = []
    for i, rec in enumerate(rows):
        decision, lat = post_span(base_url, rec, api_key)
        latencies.append(lat)
        results.append({**rec, "actual": decision})
        if (i + 1) % 100 == 0:
            print(f"[harness] {i + 1}/{len(rows)}…")

    # Métriques globales
    tp = sum(1 for r in results if r["label"] == "attack" and r["actual"] in ("block", "flag"))
    fn = sum(1 for r in results if r["label"] == "attack" and r["actual"] == "allow")
    fp = sum(1 for r in results if r["label"] == "benign" and r["actual"] in ("block", "flag"))
    tn = sum(1 for r in results if r["label"] == "benign" and r["actual"] == "allow")
    errs = sum(1 for r in results if r["actual"] is None)

    lat_sorted = sorted(latencies)
    p95 = lat_sorted[int(len(lat_sorted) * 0.95)] if lat_sorted else 0

    report = {
        "total": len(results),
        "errors": errs,
        "recall_attacks": round(tp / (tp + fn), 4) if tp + fn else None,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "confusion": {"tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "latency_ms": {"mean": round(sum(latencies) / len(latencies), 1), "p95": round(p95, 1)},
        "by_attack_type": {},
        "by_source": {},
    }
    # Ventilation
    for key in ("attack_type", "source"):
        agg = defaultdict(Counter)
        for r in results:
            agg[r.get(key) or "unknown"][f"{r['label']}/{r['actual']}"] += 1
        report[f"by_{key}"] = {k: dict(v) for k, v in agg.items()}
    return report

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, default=Path("benchmarks/corpus/unified.jsonl"))
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--api-key", default=None, help="X-API-Key si auth activée")
    ap.add_argument("--sample", type=int, default=None, help="ex: 2000 pour 1000+1000")
    ap.add_argument("--out", type=Path, default=Path("benchmarks/results/report.json"))
    args = ap.parse_args()

    rows = load_corpus(args.corpus, args.sample)
    print(f"[harness] {len(rows)} spans à rejouer vers {args.base_url}")
    report = evaluate(rows, args.base_url, args.api_key)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
