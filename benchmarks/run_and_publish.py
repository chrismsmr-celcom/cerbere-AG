#!/usr/bin/env python3
"""
Public reproducible benchmark for CerbereAG detection engine.

Measures, per active layer combination:
  - Recall       (attacks detected / total attacks), per category
  - FPR          (benign prompts blocked / total benign)
  - Hard-Neg FPR (legitimate prompts resembling attacks, blocked)
  - Latency      p50 / p95 / p99 in ms

Reproducibility guarantees:
  - No network access for regex/ml layers (LLM layer requires a key and is
    explicitly reported as non-reproducible unless the judge model is pinned).
  - Every run records: SDK version, Python version, corpus SHA-256,
    active layers, date, machine-free raw latencies.

v2 (2026-09-28):
  - SUPPRIMÉ le prétraitement normalize_prompt du runner : la normalisation
    anti-obfuscation vit désormais DANS PolicyEngine.check_injection (passe
    fallback via agentguard/normalizer.py, early-exit). Le benchmark doit
    mesurer le moteur exactement comme la production l'appelle : texte brut.
    L'ancien prétraitement inline (suppression zero-width au lieu de
    remplacement par espace, points collés) corrompait les prompts et mas-
    quait 6 détections (cf. runs 2026-09-26/28 à 91.5%).
  - Correction de l'IndentationError introduite par la suppression partielle.

Usage:
    python benchmarks/run_public_benchmark.py --layers regex
    python benchmarks/run_public_benchmark.py --layers regex,ml
    python benchmarks/run_public_benchmark.py --all-layers
"""
import argparse
import hashlib
import json
import os
import platform
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

VALID_LAYERS = ("regex", "ml", "llm")
CORPUS_DIR = Path(__file__).parent / "corpus"
RESULTS_DIR = Path(__file__).parent / "results"

LAYER_PRESETS = {
    "regex": ["regex"],
    "regex,ml": ["regex", "ml"],
    "regex,ml,llm": ["regex", "ml", "llm"],
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sdk_version() -> str:
    try:
        from importlib.metadata import version
        return version("cerbere-ag")
    except Exception:
        return "unknown (not installed as package)"


def percentile(sorted_values, p):
    """Nearest-rank percentile on a sorted list."""
    if not sorted_values:
        return 0.0
    k = max(0, min(len(sorted_values) - 1, int(round(p / 100 * len(sorted_values))) - 1))
    return sorted_values[k]


def load_json(name: str) -> list:
    with open(CORPUS_DIR / name, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Accept both {"category": [entries]} and flat [entries]
    if isinstance(data, dict):
        entries = []
        for key, value in data.items():
            if key == "metadata":
                continue
            if isinstance(value, list):
                for item in value:
                    item.setdefault("category", key)
                    entries.append(item)
        return entries
    return data



def wilson_ci(successes: int, n: int, z: float = 1.96):
    """95% Wilson score interval for a proportion (robust on small n)."""
    if n == 0:
        return [0.0, 0.0]
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return [round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4)]


class LayerUnavailable(SystemExit):
    pass


class Engine:
    """Thin wrapper around PolicyEngine — texte brut, aucun prétraitement.

    La normalisation anti-obfuscation est une responsabilité du MOTEUR
    (PolicyEngine.check_injection, passe fallback normalizer.py). Le runner
    ne doit jamais transformer le prompt : il mesure le pipeline exact que
    la production exécute.
    """

    def __init__(self):
        from agentguard_sdk import PolicyEngine
        self.policy_engine = PolicyEngine()

    def active_layers(self):
        """Layers that will REALLY run (not merely requested via env vars)."""
        pe = self.policy_engine
        active = ["regex"]
        ml = getattr(pe, "ml_detector", None)
        if ml is not None and ml.enabled and getattr(ml, "model", None) is not None:
            active.append("ml")
        if getattr(pe, "_triple_judge", None) is not None:
            active.append("llm")
        return active

    def ml_info(self):
        ml = getattr(self.policy_engine, "ml_detector", None)
        if ml is None or not ml.enabled:
            return None
        return {
            "model_name": getattr(ml, "model_name", None),
            "model_path": getattr(ml, "model_path", None),
            "threshold": getattr(ml, "threshold", None),
            "dual_pass": getattr(ml, "dual_pass", None),
        }

    def check(self, prompt: str):
        check = self.policy_engine.check_injection(prompt)
        return {
            "detected": not check.passed,
            "risk_level": str(getattr(check.risk_level, "value", check.risk_level)),
            "reason": (check.details or "")[:200] if check.details else "",
        }


def run_subset(engine, entries, expect_detected: bool, label: str):
    """Run prompts and return per-prompt records."""
    records = []
    for e in entries:
        start = time.perf_counter()
        try:
            check = engine.check(e["prompt"])
            detected = bool(check["detected"])
            risk = check["risk_level"]
            reason = check["reason"]
        except Exception as exc:  # engine crash counts as miss, never hidden
            detected, risk, reason = False, "error", f"engine error: {exc}"
        latency_ms = (time.perf_counter() - start) * 1000

        passed = (detected == expect_detected)
        records.append({
            "id": e.get("id", ""),
            "category": e.get("category", label),
            "severity": e.get("severity", "n/a"),
            "lang": e.get("lang", "en"),
            "prompt": e["prompt"],
            "expected_detected": expect_detected,
            "detected": detected,
            "passed": passed,
            "risk_level": risk,
            "latency_ms": round(latency_ms, 3),
            "reason": reason,
        })
    return records


def aggregate(records):
    lat = sorted(r["latency_ms"] for r in records)
    return {
        "count": len(records),
        "detected": sum(1 for r in records if r["detected"]),
        "passed": sum(1 for r in records if r["passed"]),
        "latency_ms": {
            "p50": round(percentile(lat, 50), 3),
            "p95": round(percentile(lat, 95), 3),
            "p99": round(percentile(lat, 99), 3),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--layers", default="regex",
                        help="Comma-separated: regex,ml,llm")
    parser.add_argument("--all-layers", action="store_true",
                        help="Run all three presets: regex / regex,ml / regex,ml,llm")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit prompts per subset (smoke runs only; "
                             "results marked non-authoritative)")
    parser.add_argument("--allow-degraded", action="store_true",
                        help="Do not abort when a requested layer is not "
                             "really active; the run is then marked "
                             "degraded and records the layers that ran.")
    args = parser.parse_args()

    presets = list(LAYER_PRESETS) if args.all_layers else [args.layers]

    # --- Load corpora ---
    attacks = load_json("attacks.json")
    benign = load_json("benign.json")
    hard_neg = load_json("hard_negatives.json")

    # The legacy adversarial corpus mixes benign entries into the attack
    # file. The public benchmark keeps attacks-only here; the benign set
    # lives in benign.json / hard_negatives.json.
    attacks = [e for e in attacks if e.get("category") != "benign"]

    if args.limit:
        attacks = attacks[: args.limit]
        benign = benign[: args.limit]
        hard_neg = hard_neg[: args.limit]

    runs = []
    for preset in presets:
        layers = [l.strip().lower() for l in preset.split(",")]
        for l in layers:
            if l not in VALID_LAYERS:
                raise SystemExit(f"Unknown layer: {l}")
        os.environ["AGENTGUARD_USE_ML"] = "true" if "ml" in layers else "false"
        os.environ["AGENTGUARD_USE_LLM_JUDGE"] = "true" if "llm" in layers else "false"
        os.environ.setdefault("AGENTGUARD_DB_TYPE", "sqlite")

        print(f"\n=== Layers: {preset} ===")
        engine = Engine()

        actual = engine.active_layers()
        missing = [l for l in layers if l not in actual]
        degraded = bool(missing)
        if degraded:
            msg = (f"Requested layers {layers} but only {actual} are really "
                   f"active (missing: {missing}). Install torch/model for "
                   f"'ml'; 'llm' is not wired into PolicyEngine if "
                   f"_triple_judge is None.")
            if not args.allow_degraded:
                raise LayerUnavailable("ERROR: " + msg)
            print("  WARNING (degraded run): " + msg)

        # Warm-up: exclude model load / first-call cost from latency stats.
        for _ in range(3):
            try:
                engine.check("warm-up request, please ignore")
            except Exception:
                pass

        attack_rec = run_subset(engine, attacks, True, "attack")
        benign_rec = run_subset(engine, benign, False, "benign")
        hardneg_rec = run_subset(engine, hard_neg, False, "hard_negative")

        # Per-category recall on attacks
        by_cat = defaultdict(list)
        for r in attack_rec:
            by_cat[r["category"]].append(r)
        per_category = {
            cat: aggregate(recs) for cat, recs in sorted(by_cat.items())
        }
        att_all = aggregate(attack_rec)
        all_lat = aggregate(attack_rec + benign_rec + hardneg_rec)["latency_ms"]
        ben_all = aggregate(benign_rec)
        hn_all = aggregate(hardneg_rec)

        recall = att_all["detected"] / att_all["count"] if att_all["count"] else 0
        fpr = 1 - (ben_all["passed"] / ben_all["count"]) if ben_all["count"] else 0
        hn_fpr = 1 - (hn_all["passed"] / hn_all["count"]) if hn_all["count"] else 0

        run_report = {
            "layers": layers,
            "layers_active": actual,
            "degraded": degraded,
            "ml": engine.ml_info(),
            "recall_overall": round(recall, 4),
            "recall_per_category": {
                c: round(s["detected"] / s["count"], 4)
                for c, s in per_category.items()
            },
            "false_positive_rate_benign": round(fpr, 4),
            "false_positive_rate_hard_negatives": round(hn_fpr, 4),
            "recall_ci95": wilson_ci(att_all["detected"], att_all["count"]),
            "fpr_benign_ci95": wilson_ci(ben_all["count"] - ben_all["passed"], ben_all["count"]),
            "fpr_hard_negatives_ci95": wilson_ci(hn_all["count"] - hn_all["passed"], hn_all["count"]),
            # Latency over ALL prompts: attacks caught by regex exit early,
            # so attack-only latency hides the cost of the ML path.
            "latency_ms": all_lat,
            "latency_ms_by_subset": {
                "attacks": att_all["latency_ms"],
                "benign": ben_all["latency_ms"],
                "hard_negatives": hn_all["latency_ms"],
            },
            "counts": {
                "attacks": att_all["count"],
                "benign": ben_all["count"],
                "hard_negatives": hn_all["count"],
            },
            "failures": {
                "attacks_missed": [r for r in attack_rec if not r["detected"]],
                "benign_blocked": [r for r in benign_rec if r["detected"]],
                "hard_negatives_blocked": [r for r in hardneg_rec if r["detected"]],
            },
        }
        runs.append(run_report)

        print(f"  Recall (attacks):      {recall:.1%}")
        for c, s in per_category.items():
            print(f"    - {c:28s} {s['detected']}/{s['count']}")
        print(f"  FPR (benign):          {fpr:.2%}")
        print(f"  FPR (hard negatives): {hn_fpr:.2%}")
        print(f"  Active layers:         {actual}"
              f"{'  (DEGRADED)' if degraded else ''}")
        print(f"  Latency (all prompts) p50/p95/p99: "
              f"{all_lat['p50']:.2f} / {all_lat['p95']:.2f} / {all_lat['p99']:.2f} ms")
        print(f"  Latency (benign only) p50/p95/p99: "
              f"{ben_all['latency_ms']['p50']:.2f} / "
              f"{ben_all['latency_ms']['p95']:.2f} / "
              f"{ben_all['latency_ms']['p99']:.2f} ms")

    report = {
        "benchmark": "cerbere-ag-public-benchmark",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "sdk_version": sdk_version(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
        },
        "corpus": {
            "attacks_sha256": sha256_file(CORPUS_DIR / "attacks.json"),
            "benign_sha256": sha256_file(CORPUS_DIR / "benign.json"),
            "hard_negatives_sha256": sha256_file(CORPUS_DIR / "hard_negatives.json"),
        },
        "note_llm_layer": (
            "The 'llm' layer requires an external API and its results are "
            "environment-dependent; only regex/ml runs are fully reproducible."
        ),
        "limited_run": bool(args.limit),
        "degraded_any": any(r["degraded"] for r in runs),
        "runs": runs,
    }

    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = RESULTS_DIR / f"benchmark-{stamp}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n📄 Report written to {out_path}")
    return report


if __name__ == "__main__":
    main()

