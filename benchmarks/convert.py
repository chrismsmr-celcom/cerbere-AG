"""Convertisseur de corpus publics → spans Cerbere unifiés.

Usage :
    python -m benchmarks.convert --sources agentdojo --out benchmarks/corpus/unified.jsonl
    python -m benchmarks.convert --sources all --max-per-source 10000

Sources :
    - agentdojo   (HF: ethz-spylab/agentdojo via datasets, ou clone local du repo)
    - tensor_trust(HF: SophosAgent/TensorTrust ou similaire)
    - injecagent  (fichier local benchmarks/corpus/attacks.json — format maison)
    - benign      (HF: tool-calling / conversations légitimes)
"""
from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

OUT_DEFAULT = Path("benchmarks/corpus/unified.jsonl")
OUT_ATTACKS = Path("benchmarks/corpus/attacks.json")

# ---------------------------------------------------------------- helpers

def _write_jsonl(records: list[dict], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[convert] écrit {len(records)} entrées → {out}")

def _make_span(idx: int, label: str, source: str, expected: str,
               prompt: str, tool_name: str | None = None,
               tool_arguments: dict | None = None, context: dict | None = None,
               attack_type: str | None = None) -> dict:
    return {
        "id": f"{source}_{label}_{idx:05d}",
        "label": label,
        "source": source,
        "attack_type": attack_type,
        "expected": expected,
        "span": {
            "agent_id": "bench-agent",
            "session_id": f"bench-session-{idx // 100}",
            "trace_id": f"bench-trace-{idx:05d}",
            "span_name": "tool_call" if tool_name else "llm_message",
            "prompt": prompt,
            "tool_name": tool_name,
            "tool_arguments": tool_arguments or {},
            "context": context or {},
        },
    }

# ---------------------------------------------------------------- injecagent (maison)
def convert_local_attacks() -> list[dict]:
    """Convertit benchmarks/corpus/attacks.json (dict: catégories -> liste d'entrées)."""
    if not OUT_ATTACKS.exists():
        print(f"[convert] {OUT_ATTACKS} absent, source ignorée")
        return []
    raw = json.loads(OUT_ATTACKS.read_text(encoding="utf-8"))

    PROMPT_KEYS = ("prompt", "text", "payload", "injection", "content", "message", "instruction")
    out, skipped = [], []
    idx = 0
    for category, entries in raw.items():
        if category == "metadata" or not isinstance(entries, list):
            continue
        for e in entries:
            if not isinstance(e, dict):
                e = {"prompt": str(e)}
            prompt = next((str(e[k]) for k in PROMPT_KEYS if e.get(k)), "")
            if not prompt:
                skipped.append({**e, "_category": category})
                continue
            tool_name, tool_args = _extract_tool(prompt)
            out.append(_make_span(
                idx, "attack", "injecagent", "block",
                prompt, tool_name, tool_args,
                context={
                    "severity": e.get("severity"),
                    "lang": e.get("lang", "en"),
                    "category": e.get("category", category),
                },
                attack_type=e.get("category", category),
            ))
            idx += 1
    if skipped:
        print(f"[convert] ⚠ {len(skipped)} entrées sans prompt — 1er exemple : {skipped[0]}")
    return out

_TOOL_PATTERNS = [
    (r"\btransfer(?:_funds)?\b", "transfer_funds",
     lambda m: {"amount": 10000, "to": "attacker_account"}),
    (r"\bsend_(?:email|mail)\b", "send_email", lambda m: {"to": "attacker@evil.com"}),
    (r"\bdelete_(?:file|email)s?\b", "delete_file", lambda m: {"path": "/etc/passwd"}),
    (r"\b(?!ignore\b)(\w+)\s+tool\b", None, None),  # générique, capturé ci-dessous
]

def _extract_tool(prompt: str) -> tuple[str | None, dict | None]:
    p = prompt.lower()
    for pat, name, args in _TOOL_PATTERNS:
        m = re.search(pat, p)
        if m:
            if name:
                return name, args(m)
            return m.group(1), {"raw": prompt[:200]}
    return None, None

# ---------------------------------------------------------------- agentdojo
def convert_agentdojo(max_items: int = 10000) -> list[dict]:
    """Extrait injections + prompts bénins d'AgentDojo (clone ou HF)."""
    try:
        from datasets import load_dataset
    except ImportError:
        print("[convert] `pip install datasets` requis pour agentdojo — ignorée")
        return []
    out = []
    suites = ["workspace", "banking", "slack", "travel", "file_system"]
    idx = 0
    for suite in suites:
        try:
            ds = load_dataset("ethz-spylab/agentdojo", suite, trust_remote_code=True)
        except Exception as e:  # noqa: BLE001
            print(f"[convert] suite {suite} indisponible: {e}")
            continue
        for split in ds:
            for row in ds[split]:
                if idx >= max_items:
                    break
                inj = row.get("injection") or row.get("injections") or {}
                goal = row.get("goal") or row.get("prompt") or ""
                if not goal:
                    continue
                if inj:
                    # Cas d'attaque : contenu d'outil piégé
                    for _, payload in (inj.items() if isinstance(inj, dict) else []):
                        out.append(_make_span(
                            idx, "attack", "agentdojo", "block",
                            str(payload), tool_name="get_email",
                            tool_arguments={"body": str(payload)},
                            context={"domain": suite, "injection": True},
                            attack_type="indirect_prompt_injection",
                        ))
                        idx += 1
                else:
                    out.append(_make_span(
                        idx, "benign", "agentdojo", "allow", str(goal),
                        context={"domain": suite, "injection": False},
                    ))
                    idx += 1
    return out[:max_items]

# ---------------------------------------------------------------- benign (function-calling)
def convert_benign_tools(max_items: int = 10000) -> list[dict]:
    """Conversations/outils légitimes — trafic réaliste pour les faux positifs."""
    try:
        from datasets import load_dataset
    except ImportError:
        return []
    out = []
    # ShareGPT-like ou ToolBench ; fallback LMSYS
    candidates = [
        ("lmsys/lmsys-chat-1k", None),
        ("HuggingFaceH4/no_robots", None),
    ]
    for name, _cfg in candidates:
        try:
            ds = load_dataset(name, split="train")
        except Exception:  # noqa: BLE001
            continue
        for i, row in enumerate(ds):
            if i >= max_items:
                break
            text = row.get("messages") or row.get("text") or ""
            if isinstance(text, list):
                text = " ".join(
                    (m.get("content", "") if isinstance(m, dict) else str(m))
                    for m in text
                )
            text = str(text)[:4000]
            if not text.strip():
                continue
            out.append(_make_span(
                i, "benign", "lmsys", "allow", text,
                tool_name=random.choice([None, "get_email", "search", "read_file", "get_weather"]),
                context={"domain": "generic"},
            ))
        break
    return out

# ---------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="all",
                    help="all | injecagent,agentdojo,benign,...")
    ap.add_argument("--max-per-source", type=int, default=10000)
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    args = ap.parse_args()

    sources = (["injecagent", "agentdojo", "benign"]
               if args.sources == "all" else args.sources.split(","))

    records: list[dict] = []
    for s in sources:
        if s == "injecagent":
            records += convert_local_attacks()
        elif s == "agentdojo":
            records += convert_agentdojo(args.max_per_source)
        elif s == "benign":
            records += convert_benign_tools(args.max_per_source)
        else:
            print(f"[convert] source inconnue: {s}")

    random.Random(42).shuffle(records)   # reproductible
    _write_jsonl(records, args.out)
    n_att = sum(1 for r in records if r["label"] == "attack")
    print(f"[convert] {n_att} attaques / {len(records) - n_att} bénignes")

if __name__ == "__main__":
    main()
