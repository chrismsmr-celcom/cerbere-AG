#!/usr/bin/env python3
"""
Prepare a FROZEN external benchmark corpus from a public dataset.

Currently supported: deepset/prompt-injections (label 1 = injection, 0 = legit).

What it does (and why):
  - Pins the dataset to an exact Hugging Face revision (commit SHA) and records
    it, so the corpus can be re-downloaded identically.
  - Records the license read from the dataset card at download time.
  - Drops exact duplicates and reports how many prompts also appear in the
    internal dev corpus (contamination check).
  - Writes attacks.json / benign.json (same flat format as the internal
    corpus) plus MANIFEST.json with SHA-256 of every file.
  - The benchmark runner refuses to run on this corpus if a file no longer
    matches the manifest: the freeze is enforced, not just promised.

Usage:
    pip install datasets
    python benchmarks/prepare_external.py --source deepset --split test
    # offline / manual download (jsonl or csv with columns text,label):
    python benchmarks/prepare_external.py --source deepset --split test --local-file my.jsonl

Then FREEZE before the first run:
    git add benchmarks/external && git commit -m "freeze external corpus"
    git tag external-freeze-1
    python benchmarks/run_public_benchmark.py --corpus-dir benchmarks/external/deepset_test --layers regex,ml,llm
Never edit rules, thresholds or prompts after seeing results on this corpus.
"""
import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
INTERNAL_DIR = HERE / "corpus"
OUT_ROOT = HERE / "external"
SCRIPT_VERSION = "1.0.0"

DATASETS = {
    "deepset": {
        "hf_repo": "deepset/prompt-injections",
        "url": "https://huggingface.co/datasets/deepset/prompt-injections",
        "default_license_note": "Dataset card lists a permissive license (apache-2.0 in the "
                                "snapshots we saw); verify on the card before redistributing.",
    },
}

_DE = {"der", "die", "das", "und", "ist", "nicht", "ich", "ein", "eine", "zu", "mit", "für",
       "auf", "den", "dem", "wie", "was", "sie", "es", "im", "von", "bitte", "kann", "wir"}


def guess_lang(text: str) -> str:
    """Crude heuristic (>=2 German stopwords -> 'de'). Labeled as heuristic in the manifest."""
    words = [w.strip(".,!?;:\"'()").lower() for w in text.split()]
    return "de" if sum(1 for w in words if w in _DE) >= 2 else "en"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def norm(t: str) -> str:
    return " ".join(str(t).lower().split())


def load_hf(source: str, split: str, revision):
    from datasets import load_dataset
    from huggingface_hub import HfApi
    repo = DATASETS[source]["hf_repo"]
    info = HfApi().dataset_info(repo, revision=revision)
    sha = info.sha
    card = getattr(info, "card_data", None)
    license_ = getattr(card, "license", None) if card else None
    ds = load_dataset(repo, split=split, revision=sha)
    rows = [{"text": r["text"], "label": int(r["label"])} for r in ds]
    return rows, sha, license_


def load_local(path: Path):
    rows = []
    if path.suffix == ".jsonl":
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                rows.append({"text": r["text"], "label": int(r["label"])})
    elif path.suffix == ".csv":
        with open(path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                rows.append({"text": r["text"], "label": int(r["label"])})
    else:
        raise SystemExit("--local-file must be .jsonl or .csv with columns text,label")
    return rows


def internal_prompts():
    seen = set()
    for name in ("attacks.json", "benign.json", "hard_negatives.json"):
        p = INTERNAL_DIR / name
        if not p.exists():
            continue
        data = json.loads(p.read_text(encoding="utf-8"))
        items = []
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list):
                    items += v
        else:
            items = data
        seen.update(norm(i.get("prompt", "")) for i in items)
    return seen


def build_corpus(rows, source: str, split: str):
    internal = internal_prompts()
    seen, attacks, benign = set(), [], []
    dropped_empty = dropped_dup = overlap = 0
    for r in rows:
        text = (r["text"] or "").strip()
        if not text:
            dropped_empty += 1
            continue
        key = norm(text)
        if key in seen:
            dropped_dup += 1
            continue
        seen.add(key)
        if key in internal:
            overlap += 1
        entry = {"prompt": text, "lang": guess_lang(text), "source": f"{source}/{split}"}
        if r["label"] == 1:
            attacks.append({**entry, "id": f"ext_{source}_{split}_a{len(attacks):04d}",
                            "category": "external_injection", "severity": "n/a"})
        else:
            benign.append({**entry, "id": f"ext_{source}_{split}_b{len(benign):04d}",
                           "category": "external_benign", "severity": "none"})
    stats = {"dropped_empty": dropped_empty, "dropped_duplicates": dropped_dup,
             "overlap_with_internal_corpus": overlap}
    return attacks, benign, stats


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", choices=sorted(DATASETS), default="deepset")
    ap.add_argument("--split", default="test", help="Use 'test' only; never tune on it.")
    ap.add_argument("--revision", default=None, help="HF revision (default: latest, then pinned by SHA).")
    ap.add_argument("--local-file", default=None, help="Offline .jsonl/.csv with columns text,label.")
    ap.add_argument("--out-name", default=None)
    args = ap.parse_args()

    meta = DATASETS[args.source]
    if args.local_file:
        rows, revision, license_ = load_local(Path(args.local_file)), "local-file", None
    else:
        try:
            rows, revision, license_ = load_hf(args.source, args.split, args.revision)
        except ImportError:
            raise SystemExit("Missing dependency: pip install datasets")

    attacks, benign, stats = build_corpus(rows, args.source, args.split)
    if not attacks or not benign:
        raise SystemExit(f"Suspicious corpus ({len(attacks)} attacks, {len(benign)} benign): aborting.")

    out_dir = OUT_ROOT / (args.out_name or f"{args.source}_{args.split}")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in (("attacks.json", attacks), ("benign.json", benign)):
        (out_dir / name).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    langs = {}
    for e in attacks + benign:
        langs[e["lang"]] = langs.get(e["lang"], 0) + 1
    manifest = {
        "name": out_dir.name,
        "role": "external_frozen",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "script_version": SCRIPT_VERSION,
        "source": {
            "dataset": meta["hf_repo"], "url": meta["url"], "split": args.split,
            "revision": revision, "license_from_card": license_,
            "license_note": meta["default_license_note"],
        },
        "counts": {"attacks": len(attacks), "benign": len(benign), **stats},
        "language_heuristic_counts": langs,
        "files": {n: sha256_file(out_dir / n) for n in ("attacks.json", "benign.json")},
        "notes": [
            "Labels come from the dataset authors; some may be noisy or debatable.",
            "No hard-negative set exists for this source: hard-negative FPR is not measured here.",
            "Public detectors are often trained on deepset data: any ML-layer score here may be optimistic.",
            "Language is a stopword heuristic, not ground truth.",
        ],
    }
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Corpus written to {out_dir}")
    print(f"  attacks={len(attacks)} benign={len(benign)} {stats}")
    print(f"  revision={revision} license_from_card={license_}")
    if stats["overlap_with_internal_corpus"]:
        print(f"  WARNING: {stats['overlap_with_internal_corpus']} prompts also appear in the internal corpus.")
    print("\nNEXT: commit + tag to freeze BEFORE the first run:")
    print(f"  git add {out_dir.relative_to(HERE.parent)} && git commit -m 'freeze external corpus' && git tag external-freeze-1")


if __name__ == "__main__":
    sys.exit(main())
