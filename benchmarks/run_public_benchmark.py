
#!/usr/bin/env python3
"""
Public reproducible benchmark for CerbereAG detection engine.

Measures:
  - Recall: attacks detected / total attacks, overall and per category.
  - FPR: benign prompts blocked / total benign prompts.
  - Hard-negative FPR: legitimate attack-like prompts blocked.
  - Latency: p50 / p95 / p99 in milliseconds.
  - Wilson 95% confidence intervals.

The corpus can be selected with --corpus-dir.
Regex/ML runs should not require network access.
LLM results may depend on external APIs and model configuration.

Examples:
    python benchmarks/run_public_benchmark.py --layers regex
    python benchmarks/run_public_benchmark.py --layers regex,ml
    python benchmarks/run_public_benchmark.py --layers regex,ml,llm
    python benchmarks/run_public_benchmark.py --all-layers
    python benchmarks/run_public_benchmark.py ^
        --corpus-dir benchmarks/external/deepset_test --all-layers
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

ROOT_DIR = Path(__file__).resolve().parent.parent

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

VALID_LAYERS = ("regex", "ml", "llm")
CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
RESULTS_DIR = Path(__file__).resolve().parent / "results"

LAYER_PRESETS = {
    "regex": ["regex"],
    "regex,ml": ["regex", "ml"],
    "regex,ml,llm": ["regex", "ml", "llm"],
}


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            digest.update(chunk)

    return digest.hexdigest()


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

    index = max(
        0,
        min(
            len(sorted_values) - 1,
            int(round(p / 100 * len(sorted_values))) - 1,
        ),
    )
    return sorted_values[index]


def load_json(
    name: str,
    corpus_dir: Path = CORPUS_DIR,
    optional: bool = False,
) -> list:
    """Load a flat JSON list or a category-to-list mapping."""
    path = corpus_dir / name

    if not path.is_file():
        if optional:
            return []
        raise FileNotFoundError(f"Corpus file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = []

        for category, values in data.items():
            if category == "metadata":
                continue

            if not isinstance(values, list):
                continue

            for item in values:
                if not isinstance(item, dict):
                    raise ValueError(
                        f"Invalid entry in {path}, category {category!r}"
                    )

                item = dict(item)
                item.setdefault("category", category)
                entries.append(item)
    else:
        raise ValueError(
            f"Unsupported JSON structure in {path}: "
            f"expected a list or object"
        )

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(
                f"Invalid entry #{index} in {path}: expected an object"
            )

        if not isinstance(entry.get("prompt"), str):
            raise ValueError(
                f"Entry #{index} in {path} has no string 'prompt' field"
            )

    return entries


def verify_manifest(corpus_dir: Path) -> dict:
    """
    Verify SHA-256 values declared in MANIFEST.json.

    Supports the manifest layout:
        {"files": {"attacks.json": "<sha256>", ...}}

    If no manifest exists, warn rather than pretending the corpus
    has been verified.
    """
    manifest_path = corpus_dir / "MANIFEST.json"

    if not manifest_path.is_file():
        print(
            f"WARNING: no MANIFEST.json in {corpus_dir}; "
            "corpus integrity was not verified."
        )
        return {}

    with manifest_path.open("r", encoding="utf-8") as file:
        manifest = json.load(file)

    files = manifest.get("files", {})
    if not isinstance(files, dict):
        raise SystemExit(
            f"Invalid 'files' field in {manifest_path}"
        )

    for name in ("attacks.json", "benign.json"):
        expected_hash = files.get(name)

        if not expected_hash:
            raise SystemExit(
                f"Missing SHA-256 for {name} in {manifest_path}"
            )

        path = corpus_dir / name
        if not path.is_file():
            raise SystemExit(f"Missing corpus file: {path}")

        actual_hash = sha256_file(path)

        if actual_hash.lower() != str(expected_hash).lower():
            raise SystemExit(
                f"CORPUS INTEGRITY ERROR: {name} does not match "
                f"MANIFEST.json.\nExpected: {expected_hash}\n"
                f"Actual:   {actual_hash}"
            )

    print(f"Corpus integrity verified: {corpus_dir}")
    return manifest


def wilson_ci(successes: int, n: int, z: float = 1.96):
    """95% Wilson score interval for a proportion."""
    if n == 0:
        return [0.0, 0.0]

    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (
        z
        * (
            p * (1 - p) / n
            + z * z / (4 * n * n)
        ) ** 0.5
        / denom
    )

    return [
        round(max(0.0, center - margin), 4),
        round(min(1.0, center + margin), 4),
    ]


class LayerUnavailable(SystemExit):
    """Raised when a requested detection layer is not active."""


class Engine:
    """
    Thin wrapper around PolicyEngine.

    Prompts are passed as raw text. Normalization and anti-obfuscation
    belong to the production detection engine, not the benchmark runner.
    """

    def __init__(self):
        from agentguard_sdk import PolicyEngine

        self.policy_engine = PolicyEngine()

    def active_layers(self):
        """Return layers that are actually available in the engine."""
        engine = self.policy_engine
        active = ["regex"]

        ml = getattr(engine, "ml_detector", None)
        if (
            ml is not None
            and getattr(ml, "enabled", False)
            and getattr(ml, "model", None) is not None
        ):
            active.append("ml")

        if getattr(engine, "_triple_judge", None) is not None:
            active.append("llm")

        return active

    def ml_info(self):
        ml = getattr(self.policy_engine, "ml_detector", None)

        if ml is None or not getattr(ml, "enabled", False):
            return None

        return {
            "model_name": getattr(ml, "model_name", None),
            "model_path": getattr(ml, "model_path", None),
            "threshold": getattr(ml, "threshold", None),
            "dual_pass": getattr(ml, "dual_pass", None),
        }

    def check(self, prompt: str):
        result = self.policy_engine.check_injection(prompt)

        return {
            "detected": not result.passed,
            "risk_level": str(
                getattr(
                    result.risk_level,
                    "value",
                    result.risk_level,
                )
            ),
            "reason": (
                (result.details or "")[:200]
                if result.details
                else ""
            ),
        }


def run_subset(engine, entries, expect_detected: bool, label: str):
    """Run prompts and return individual results."""
    records = []

    for entry in entries:
        start = time.perf_counter()

        try:
            result = engine.check(entry["prompt"])
            detected = bool(result["detected"])
            risk = result["risk_level"]
            reason = result["reason"]
        except Exception as exc:
            # An engine failure must never be counted as a successful
            # detection of an attack.
            detected = False
            risk = "error"
            reason = f"engine error: {type(exc).__name__}: {exc}"

        latency_ms = (time.perf_counter() - start) * 1000
        passed = detected == expect_detected

        records.append({
            "id": entry.get("id", ""),
            "category": entry.get("category", label),
            "severity": entry.get("severity", "n/a"),
            "lang": entry.get("lang", "en"),
            "prompt": entry["prompt"],
            "expected_detected": expect_detected,
            "detected": detected,
            "passed": passed,
            "risk_level": risk,
            "latency_ms": round(latency_ms, 3),
            "reason": reason,
        })

    return records


def aggregate(records):
    latencies = sorted(record["latency_ms"] for record in records)

    return {
        "count": len(records),
        "detected": sum(
            1 for record in records if record["detected"]
        ),
        "passed": sum(
            1 for record in records if record["passed"]
        ),
        "latency_ms": {
            "p50": round(percentile(latencies, 50), 3),
            "p95": round(percentile(latencies, 95), 3),
            "p99": round(percentile(latencies, 99), 3),
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="CerbereAG public detection benchmark"
    )

    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=CORPUS_DIR,
        help=(
            "Directory containing attacks.json, benign.json, "
            "and optionally hard_negatives.json"
        ),
    )
    parser.add_argument(
        "--layers",
        default="regex",
        help="Comma-separated detection layers: regex,ml,llm",
    )
    parser.add_argument(
        "--all-layers",
        action="store_true",
        help="Run regex, regex+ML, and regex+ML+LLM",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit prompts per subset; smoke runs only",
    )
    parser.add_argument(
        "--allow-degraded",
        action="store_true",
        help=(
            "Allow a run when requested layers are unavailable. "
            "Such results are explicitly marked degraded."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output JSON path",
    )

    args = parser.parse_args()

    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be greater than zero")

    corpus_dir = args.corpus_dir.resolve()

    if not corpus_dir.is_dir():
        parser.error(f"Corpus directory does not exist: {corpus_dir}")

    if args.all_layers and args.layers != "regex":
        parser.error("Use either --all-layers or --layers, not both")

    presets = (
        list(LAYER_PRESETS)
        if args.all_layers
        else [args.layers]
    )

    # Validate all requested layers before running.
    for preset in presets:
        layers = [layer.strip().lower() for layer in preset.split(",")]

        if not layers or any(not layer for layer in layers):
            parser.error(f"Invalid layer combination: {preset!r}")

        if len(layers) != len(set(layers)):
            parser.error(f"Duplicate layers in: {preset!r}")

        unknown = [layer for layer in layers if layer not in VALID_LAYERS]
        if unknown:
            parser.error(
                f"Unknown layers: {unknown}. "
                f"Valid layers: {list(VALID_LAYERS)}"
            )

        if "ml" in layers and "regex" not in layers:
            parser.error("ML benchmark must include the regex layer")

        if "llm" in layers and "ml" not in layers:
            parser.error("LLM benchmark must include regex and ML layers")

    # Load and verify the selected corpus.
    manifest = verify_manifest(corpus_dir)

    attacks = load_json("attacks.json", corpus_dir)
    benign = load_json("benign.json", corpus_dir)
    hard_neg = load_json(
        "hard_negatives.json",
        corpus_dir,
        optional=True,
    )

    # Never silently count benign entries from a legacy attack file
    # as attacks.
    attacks = [
        entry for entry in attacks
        if entry.get("category") != "benign"
    ]

    if not attacks:
        parser.error("The attack corpus is empty after filtering")

    if not benign:
        parser.error("The benign corpus is empty")

    if args.limit:
        attacks = attacks[:args.limit]
        benign = benign[:args.limit]
        hard_neg = hard_neg[:args.limit]

    print(f"Corpus directory: {corpus_dir}")
    print(f"Attacks: {len(attacks)}")
    print(f"Benign: {len(benign)}")
    print(f"Hard negatives: {len(hard_neg)}")

    runs = []

    for preset in presets:
        layers = [
            layer.strip().lower()
            for layer in preset.split(",")
        ]

        os.environ["AGENTGUARD_USE_ML"] = (
            "true" if "ml" in layers else "false"
        )
        os.environ["AGENTGUARD_USE_LLM_JUDGE"] = (
            "true" if "llm" in layers else "false"
        )
        os.environ.setdefault("AGENTGUARD_DB_TYPE", "sqlite")

        print(f"\n=== Layers: {preset} ===")

        engine = Engine()
        actual = engine.active_layers()
        missing = [layer for layer in layers if layer not in actual]
        degraded = bool(missing)

        if degraded:
            message = (
                f"Requested layers {layers}, but active layers are "
                f"{actual}. Missing: {missing}."
            )

            if not args.allow_degraded:
                raise LayerUnavailable("ERROR: " + message)

            print("WARNING: DEGRADED RUN: " + message)

        # Warm up before collecting latency measurements.
        for _ in range(3):
            try:
                engine.check("warm-up request; ignore this prompt")
            except Exception:
                pass

        attack_records = run_subset(
            engine, attacks, True, "attack"
        )
        benign_records = run_subset(
            engine, benign, False, "benign"
        )
        hardneg_records = run_subset(
            engine, hard_neg, False, "hard_negative"
        )

        by_category = defaultdict(list)

        for record in attack_records:
            by_category[record["category"]].append(record)

        per_category = {
            category: aggregate(records)
            for category, records in sorted(by_category.items())
        }

        attack_summary = aggregate(attack_records)
        benign_summary = aggregate(benign_records)
        hardneg_summary = aggregate(hardneg_records)

        all_summary = aggregate(
            attack_records + benign_records + hardneg_records
        )

        attack_count = attack_summary["count"]
        benign_count = benign_summary["count"]
        hardneg_count = hardneg_summary["count"]

        recall = (
            attack_summary["detected"] / attack_count
            if attack_count else 0.0
        )
        benign_fpr = (
            (benign_count - benign_summary["passed"]) / benign_count
            if benign_count else 0.0
        )
        hardneg_fpr = (
            (hardneg_count - hardneg_summary["passed"]) / hardneg_count
            if hardneg_count else 0.0
        )

        run_report = {
            "layers": layers,
            "layers_active": actual,
            "degraded": degraded,
            "ml": engine.ml_info(),
            "recall_overall": round(recall, 4),
            "recall_per_category": {
                category: round(
                    summary["detected"] / summary["count"], 4
                )
                if summary["count"] else 0.0
                for category, summary in per_category.items()
            },
            "false_positive_rate_benign": round(benign_fpr, 4),
            "false_positive_rate_hard_negatives": round(
                hardneg_fpr, 4
            ),
            "recall_ci95": wilson_ci(
                attack_summary["detected"], attack_count
            ),
            "fpr_benign_ci95": wilson_ci(
                benign_count - benign_summary["passed"],
                benign_count,
            ),
            "fpr_hard_negatives_ci95": wilson_ci(
                hardneg_count - hardneg_summary["passed"],
                hardneg_count,
            ),
            "latency_ms": all_summary["latency_ms"],
            "latency_ms_by_subset": {
                "attacks": attack_summary["latency_ms"],
                "benign": benign_summary["latency_ms"],
                "hard_negatives": hardneg_summary["latency_ms"],
            },
            "counts": {
                "attacks": attack_count,
                "benign": benign_count,
                "hard_negatives": hardneg_count,
            },
            "failures": {
                "attacks_missed": [
                    record for record in attack_records
                    if not record["detected"]
                ],
                "benign_blocked": [
                    record for record in benign_records
                    if record["detected"]
                ],
                "hard_negatives_blocked": [
                    record for record in hardneg_records
                    if record["detected"]
                ],
            },
        }

        runs.append(run_report)

        print(f"Recall (attacks): {recall:.1%}")
        for category, summary in per_category.items():
            print(
                f"  {category:28s} "
                f"{summary['detected']}/{summary['count']}"
            )

        print(f"FPR (benign): {benign_fpr:.2%}")
        if hardneg_count:
            print(f"FPR (hard negatives): {hardneg_fpr:.2%}")
        else:
            print("FPR (hard negatives): N/A (no hard-negative set)")

        print(
            f"Active layers: {actual}"
            f"{' (DEGRADED)' if degraded else ''}"
        )
        print(
            "Latency all prompts p50/p95/p99: "
            f"{all_summary['latency_ms']['p50']:.2f} / "
            f"{all_summary['latency_ms']['p95']:.2f} / "
            f"{all_summary['latency_ms']['p99']:.2f} ms"
        )

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
            "directory": str(corpus_dir),
            "name": manifest.get("name", corpus_dir.name),
            "source": manifest.get("source", {}),
            "manifest_sha256": (
                sha256_file(corpus_dir / "MANIFEST.json")
                if (corpus_dir / "MANIFEST.json").is_file()
                else None
            ),
            "attacks_sha256": sha256_file(
                corpus_dir / "attacks.json"
            ),
            "benign_sha256": sha256_file(
                corpus_dir / "benign.json"
            ),
            "hard_negatives_sha256": (
                sha256_file(corpus_dir / "hard_negatives.json")
                if (corpus_dir / "hard_negatives.json").is_file()
                else None
            ),
        },
        "note_llm_layer": (
            "LLM results may depend on external API availability, "
            "provider configuration, and model version. "
            "Regex/ML results are only reproducible when the model "
            "artifacts and runtime environment are held constant."
        ),
        "limited_run": args.limit is not None,
        "degraded_any": any(run["degraded"] for run in runs),
        "runs": runs,
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if args.output:
        output_path = args.output.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
        output_path = RESULTS_DIR / f"benchmark-{stamp}.json"

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print(f"\nReport written to {output_path}")
    return report


if __name__ == "__main__":
    main()