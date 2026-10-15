#!/usr/bin/env python3
"""
Generate the frozen 10k-prompt corpus in benchmarks/corpus_10k/.

Composition (fixed targets):
  - attacks.json       5000 prompts across 7 attack categories (EN/FR)
  - benign.json        3500 benign prompts (dev, general, support, data, creative, FR)
  - hard_negatives.json 1500 legitimate prompts that *mention* attack vocabulary

Properties:
  - 100% deterministic: no randomness, no clock, no network. The committed
    corpus is byte-for-byte reproducible with this script.
  - 100% unique prompts (global deduplication across all three files).
  - The validated hand-written prompts from benchmarks/corpus/ are seeded
    in first, so nothing is lost from the original corpus.
  - Integrity is pinned in MANIFEST.json (SHA-256), verified by
    benchmarks/run_public_benchmark.py via verify_manifest().

Run from the repository root:
    python benchmarks/generate_corpus_10k.py

Run the benchmark against it:
    python benchmarks/run_public_benchmark.py \
        --corpus-dir benchmarks/corpus_10k --layers regex
"""

import base64
import hashlib
import json
from itertools import product
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE / "corpus"
OUT_DIR = HERE / "corpus_10k"
TABLES = HERE / "corpus_10k" / "tables.json"

ATTACK_CATEGORY_ORDER = [
    "direct_injection",
    "jailbreak",
    "system_extraction",
    "exfiltration",
    "dangerous_commands",
    "encoded_obfuscated",
    "indirect_injection",
]
BENIGN_GROUP_ORDER = [
    "benign_dev",
    "benign_general",
    "benign_support",
    "benign_data",
    "benign_creative",
    "benign_fr",
]
HARD_NEGATIVE_GROUP_ORDER = [
    "hn_security_writing",
    "hn_fiction",
    "hn_test_fixtures",
    "hn_fr",
]


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── transforms for the encoded_obfuscated category ──────────────────────────
# Standard base64 / lowercase hex applied to UTF-8 bytes of ASCII payloads.


def t_base64(s: str) -> str:
    return "Decode and follow: " + base64.b64encode(s.encode("utf-8")).decode("ascii")


def t_hex(s: str) -> str:
    return "Decode and follow: " + s.encode("utf-8").hex()


def t_rot13(s: str) -> str:
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def t_leet(s: str) -> str:
    table = str.maketrans("aeiostAEIOST", "431057431057")
    return s.translate(table)


def t_dotted(s: str) -> str:
    return ".".join(s)


def t_spaced_upper(s: str) -> str:
    return " ".join(s.upper())


def t_zws(s: str) -> str:
    return s.replace(" ", "\u200b ")


def t_reversed(s: str) -> str:
    return s[::-1]


def t_doubled(s: str) -> str:
    return "".join(ch + ch if ch.isalnum() else ch for ch in s)


def t_unicode_escape(s: str) -> str:
    return "".join(f"\\u00{b:02x}" for b in s.encode("utf-8"))


TRANSFORMS = {
    "base64": t_base64,
    "hex": t_hex,
    "rot13": t_rot13,
    "leet": t_leet,
    "dotted": t_dotted,
    "spaced_upper": t_spaced_upper,
    "zws": t_zws,
    "reversed": t_reversed,
    "doubled": t_doubled,
    "unicode_escape": t_unicode_escape,
}


def fill(template: str, combo: dict) -> str:
    """Replace only the placeholders the template actually uses."""
    out = template
    for key, value in combo.items():
        out = out.replace("{" + key + "}", value)
    return out


def generator_queue(gen: dict, seen: set, limit: int) -> list:
    """Deterministic ordered list of (prompt, lang) from one generator.

    Stops once `limit` items have been collected: a group can never
    contribute more than the total target of its subset, so capping
    keeps memory bounded without changing the selection.
    """
    items = []
    lang = gen.get("lang", "en")
    if gen.get("transform"):
        for tname in gen["transforms"]:
            fn = TRANSFORMS[tname]
            for payload in gen["payloads"]:
                if len(items) >= limit:
                    return items
                text = fn(payload)
                if text in seen:
                    continue
                seen.add(text)
                items.append((text, lang))
        return items
    templates = gen["templates"]
    dims = gen.get("dims", {})
    for template in templates:
        referenced = [d for d in dims if "{" + d + "}" in template]
        if not referenced:
            if len(items) >= limit:
                return items
            text = template
            if text not in seen:
                seen.add(text)
                items.append((text, lang))
            continue
        for values in product(*[dims[d] for d in referenced]):
            if len(items) >= limit:
                return items
            combo = dict(zip(referenced, values))
            text = fill(template, combo)
            if text in seen:
                continue
            seen.add(text)
            items.append((text, lang))
    return items


def load_attack_seeds() -> dict:
    """Validated hand-written attack prompts from the original corpus."""
    data = load_json(CORPUS_DIR / "attacks.json")
    seeds: dict = {cat: [] for cat in ATTACK_CATEGORY_ORDER}
    if isinstance(data, dict):
        for cat, entries in data.items():
            if cat == "metadata" or cat == "benign" or not isinstance(entries, list):
                continue
            for e in entries:
                if isinstance(e, dict) and isinstance(e.get("prompt"), str):
                    seeds.setdefault(cat, []).append(e["prompt"])
    return seeds


def main():
    tables = load_json(TABLES)
    targets = tables["targets"]
    seen = set()  # global dedup across attacks, benign and hard negatives

    # ── attacks: fixed order, first-N per category ──────────────────────────
    seeds = load_attack_seeds()
    attacks = []
    attack_stats = {}
    for cat in ATTACK_CATEGORY_ORDER:
        cfg = tables["attacks"][cat]
        queue = []
        for prompt in seeds.get(cat, []):
            if prompt in seen:
                continue
            seen.add(prompt)
            queue.append((prompt, "en"))
        for gen in cfg["generators"]:
            queue.extend(generator_queue(gen, seen, cfg["target"] - len(queue)))
        target = cfg["target"]
        if len(queue) < target:
            raise SystemExit(
                f"Not enough unique prompts for {cat}: {len(queue)} < {target}"
            )
        selected = queue[:target]
        attack_stats[cat] = len(selected)
        for text, lang in selected:
            attacks.append(
                {
                    "id": "",
                    "prompt": text,
                    "category": cat,
                    "severity": cfg["severity"],
                    "lang": lang,
                }
            )

    # ── benign: round-robin across groups ───────────────────────────────────
    groups = []
    for group in BENIGN_GROUP_ORDER:
        cfg = tables["benign"][group]
        queue = []
        for gen in cfg["generators"]:
            queue.extend(generator_queue(gen, seen, targets["benign"] - len(queue)))
        groups.append((group, queue))
    # seed the original benign prompts into the first group
    if (CORPUS_DIR / "benign.json").is_file():
        data = load_json(CORPUS_DIR / "benign.json")
        entries = data.get("benign", []) if isinstance(data, dict) else []
        seeded = []
        for e in entries:
            if isinstance(e, dict) and isinstance(e.get("prompt"), str):
                if e["prompt"] in seen:
                    continue
                seen.add(e["prompt"])
                seeded.append((e["prompt"], e.get("lang", "en")))
        groups[0] = (groups[0][0], seeded + groups[0][1])

    benign = []
    benign_stats = {}
    while len(benign) < targets["benign"] and any(q for _, q in groups):
        for gi, (group, queue) in enumerate(groups):
            if len(benign) >= targets["benign"]:
                break
            if not queue:
                continue
            text, lang = queue.pop(0)
            benign.append(
                {
                    "id": "",
                    "prompt": text,
                    "category": group,
                    "severity": "none",
                    "lang": lang,
                }
            )
            benign_stats[group] = benign_stats.get(group, 0) + 1
    if len(benign) < targets["benign"]:
        raise SystemExit(f"Not enough unique benign prompts: {len(benign)}")

    # ── hard negatives: round-robin across groups ───────────────────────────
    groups = []
    for group in HARD_NEGATIVE_GROUP_ORDER:
        cfg = tables["hard_negatives"][group]
        queue = []
        for gen in cfg["generators"]:
            queue.extend(
                generator_queue(gen, seen, targets["hard_negatives"] - len(queue))
            )
        groups.append((group, queue))
    if (CORPUS_DIR / "hard_negatives.json").is_file():
        data = load_json(CORPUS_DIR / "hard_negatives.json")
        entries = data.get("hard_negatives", []) if isinstance(data, dict) else []
        seeded = []
        for e in entries:
            if isinstance(e, dict) and isinstance(e.get("prompt"), str):
                if e["prompt"] in seen:
                    continue
                seen.add(e["prompt"])
                seeded.append((e["prompt"], e.get("lang", "en")))
        groups[0] = (groups[0][0], seeded + groups[0][1])

    hard_negatives = []
    hn_stats = {}
    while len(hard_negatives) < targets["hard_negatives"] and any(q for _, q in groups):
        for gi, (group, queue) in enumerate(groups):
            if len(hard_negatives) >= targets["hard_negatives"]:
                break
            if not queue:
                continue
            text, lang = queue.pop(0)
            hard_negatives.append(
                {
                    "id": "",
                    "prompt": text,
                    "category": "hard_negative",
                    "severity": "none",
                    "lang": lang,
                }
            )
            hn_stats[group] = hn_stats.get(group, 0) + 1
    if len(hard_negatives) < targets["hard_negatives"]:
        raise SystemExit(f"Not enough unique hard negatives: {len(hard_negatives)}")

    # ── assign ids and write files ─────────────────────────────────────────
    for i, e in enumerate(attacks, 1):
        e["id"] = "atk_%04d" % i
    for i, e in enumerate(benign, 1):
        e["id"] = "ben_%04d" % i
    for i, e in enumerate(hard_negatives, 1):
        e["id"] = "hn_%04d" % i

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest_files = {}
    for name, data in (
        ("attacks.json", attacks),
        ("benign.json", benign),
        ("hard_negatives.json", hard_negatives),
    ):
        payload = (
            json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        (OUT_DIR / name).write_bytes(payload)
        manifest_files[name] = sha256_bytes(payload)

    manifest = {
        "version": tables["version"],
        "generated_by": "benchmarks/generate_corpus_10k.py",
        "description": (
            "Frozen 10k-prompt corpus: 5000 attacks, 3500 benign, "
            "1500 hard negatives. Deterministic and byte-for-byte "
            "reproducible. Integrity verified by run_public_benchmark.py."
        ),
        "counts": {
            "attacks": {k: attack_stats[k] for k in ATTACK_CATEGORY_ORDER},
            "benign": {k: benign_stats.get(k, 0) for k in BENIGN_GROUP_ORDER},
            "hard_negatives": {
                k: hn_stats.get(k, 0) for k in HARD_NEGATIVE_GROUP_ORDER
            },
            "total": {
                "attacks": len(attacks),
                "benign": len(benign),
                "hard_negatives": len(hard_negatives),
                "all": len(attacks) + len(benign) + len(hard_negatives),
            },
        },
        "files": manifest_files,
    }
    (OUT_DIR / "MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print("Corpus written to", OUT_DIR)
    print(json.dumps(manifest["counts"]["total"], indent=2))


if __name__ == "__main__":
    main()
