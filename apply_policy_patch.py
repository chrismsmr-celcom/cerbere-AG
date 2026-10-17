"""Applique le correctif llm_model + layer 'ml+llm' à agentguard/policy.py.

Usage (depuis la racine du dépôt) :  python apply_policy_patch.py
Idempotent : refuse de patcher si une ancre est absente ou ambiguë.
"""

import sys
from pathlib import Path

PATH = Path("agentguard/policy.py")

EDITS = [
    # 1) extraire le modèle du verdict, avant la construction des métadonnées
    (
        '            meta = {**meta, "arbiter_verdict": verdict_value}\n',
        '            if isinstance(judged, dict):\n'
        '                llm_model = judged.get("model")\n'
        '            else:\n'
        '                llm_model = getattr(judged, "model", None)\n'
        '\n'
        '            meta = {**meta, "arbiter_verdict": verdict_value}\n',
    ),
    # 2) verdict SAFE : tracer la couche et le modèle
    (
        '                    {**meta, "ml_overridden": True},\n',
        '                    {\n'
        '                        **meta,\n'
        '                        "layer": "ml+llm",\n'
        '                        "ml_overridden": True,\n'
        '                        "llm_model": llm_model,\n'
        '                    },\n',
    ),
    # 3) verdict ATTACK : blocage confirmé par le LLM
    (
        '                    f"ML ({ml_score:.2%}) confirmed by LLM arbiter: {reason}",\n'
        '                    meta,\n',
        '                    f"ML ({ml_score:.2%}) confirmed by LLM arbiter: {reason}",\n'
        '                    {**meta, "layer": "ml+llm", "llm_model": llm_model},\n',
    ),
]


def main() -> int:
    raw = PATH.read_bytes().decode("utf-8")
    crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")

    if '"llm_model": llm_model' in text:
        print("Déjà patché — rien à faire.")
        return 0

    for old, new in EDITS:
        if text.count(old) != 1:
            print(f"✗ ancre introuvable ou ambiguë ({text.count(old)}x):\n{old}")
            return 1
        text = text.replace(old, new)

    if crlf:
        text = text.replace("\n", "\r\n")
    PATH.write_bytes(text.encode("utf-8"))
    print("✓ agentguard/policy.py patché (3 modifications).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
