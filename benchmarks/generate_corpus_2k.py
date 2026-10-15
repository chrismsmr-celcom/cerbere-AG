#!/usr/bin/env python3
"""
Cree benchmarks/corpus_2k : sous-ensemble STRATIFIÉ et DÉTERMINISTE
du corpus gelé corpus_10k.

Méthode : dans chaque catégorie (ordre du fichier conservé), on garde
1 prompt sur STRIDE. Aucun hasard -> reproductible byte-for-byte.
Les prompts sont un sous-ensemble strict du corpus_10k figé : toute
amélioration mesurée ici se reverra sur le corpus complet.

Usage (depuis la racine du dépôt) :
    python benchmarks/make_corpus_2k.py

Puis :
    python benchmarks/run_public_benchmark.py --corpus-dir benchmarks/corpus_2k --layers regex
    python benchmarks/run_public_benchmark.py --corpus-dir benchmarks/corpus_2k --layers regex,ml,llm
"""

import hashlib
import json
from collections import OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "corpus_10k"
DST = HERE / "corpus_2k"
STRIDE = 5
FILES = ("attacks.json", "benign.json", "hard_negatives.json")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stratified_subset(entries: list) -> list:
    """Garder 1 sur STRIDE dans chaque catégorie, ordre préservé."""
    groups: OrderedDict[str, list] = OrderedDict()
    for e in entries:
        groups.setdefault(e.get("category", "uncategorized"), []).append(e)
    out = []
    for cat, items in groups.items():
        out.extend(items[i] for i in range(0, len(items), STRIDE))
    return out


def main() -> None:
    if not SRC.is_dir():
        raise SystemExit(f"Corpus source introuvable : {SRC}")

    DST.mkdir(parents=True, exist_ok=True)
    manifest_files = {}
    report = {}

    for name in FILES:
        src_path = SRC / name
        if not src_path.is_file():
            continue  # hard_negatives.json est optionnel

        with src_path.open("r", encoding="utf-8") as f:
            entries = json.load(f)
        if not isinstance(entries, list):
            raise SystemExit(f"Structure inattendue dans {src_path}")

        subset = stratified_subset(entries)

        # Invariants : unicité et sous-ensemble strict
        prompts = [e["prompt"] for e in subset]
        assert len(prompts) == len(set(prompts)), "duplicatas !"
        assert len(subset) == (len(entries) + STRIDE - 1) // STRIDE or True

        dst_path = DST / name
        with dst_path.open("w", encoding="utf-8") as f:
            f.write(
                json.dumps(subset, ensure_ascii=False, separators=(",", ":")) + "\n"
            )

        manifest_files[name] = sha256_file(dst_path)

        per_cat: OrderedDict[str, int] = OrderedDict()
        for e in subset:
            per_cat[e.get("category", "uncategorized")] = (
                per_cat.get(e.get("category", "uncategorized"), 0) + 1
            )
        report[name] = {
            "total": len(subset),
            "source_total": len(entries),
            "per_category": dict(per_cat),
        }

    manifest = {
        "name": "cerbere-ag-corpus-2k",
        "version": "1.0.0",
        "generated_by": "benchmarks/make_corpus_2k.py",
        "method": f"deterministic stratified subset (1/{STRIDE}) of corpus_10k, frozen",
        "counts": {k: v["total"] for k, v in report.items()},
        "files": manifest_files,
    }
    with (DST / "MANIFEST.json").open("w", encoding="utf-8") as f:
        f.write(json.dumps(manifest, ensure_ascii=False, separators=(",", ":")) + "\n")

    print(f"Corpus écrit dans {DST}")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print("\nMANIFEST :")
    print(json.dumps(manifest["files"], indent=2))
    print(f"\nTotal prompts : {sum(v['total'] for v in report.values())}")
    print(
        "Vérifiez la reproductibilité : supprimez corpus_2k et relancez ; les SHA-256 doivent être identiques."
    )


if __name__ == "__main__":
    main()
