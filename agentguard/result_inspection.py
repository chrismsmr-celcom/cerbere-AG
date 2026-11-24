"""Post-tool inspection primitives. Detection is deterministic and dependency-free."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class InspectionFinding:
    category: str
    evidence: str
    confidence: str = "high"


@dataclass
class ResultInspection:
    safe: bool
    findings: list[InspectionFinding] = field(default_factory=list)
    redacted_text: str = ""


_INJECTION_PATTERNS = (
    re.compile(r"(?is)\bignore (?:all |any |the )?(?:previous|prior|above|earlier) instructions\b"),
    re.compile(r"(?is)\b(system|developer) prompt\s*[:=]"),
    re.compile(r"(?is)\b(reveal|print|exfiltrate|leak) (?:the )?(?:system prompt|secrets?|credentials?|api keys?)\b"),
    re.compile(r"(?is)\b(disregard|override) (?:your |all )?(?:safety|security|system|developer) (?:rules|instructions|policies)\b"),
    re.compile(r"(?is)\b(run|execute) (?:this|the following) (?:command|payload) (?:without|ignoring) (?:approval|permission)\b"),
)
_SECRET_PATTERNS = (
    re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
)


def inspect_result(value: Any, *, block_on_injection: bool = True) -> ResultInspection:
    """Inspect recursively serialized tool output before it is reintroduced to an agent."""
    import json

    try:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = str(value)
    findings = []
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            findings.append(InspectionFinding("prompt_injection", pattern.pattern[:100]))
    redacted = text
    for pattern in _SECRET_PATTERNS:
        if pattern.search(redacted):
            findings.append(InspectionFinding("secret_exposure", "secret-like material"))
            redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    malicious = any(item.category == "prompt_injection" for item in findings)
    return ResultInspection(
        safe=not (block_on_injection and malicious), findings=findings, redacted_text=redacted
    )


def inspect_mcp_content(content: list[Any], *, block_on_injection: bool = True) -> tuple[list[Any], list[InspectionFinding]]:
    """Redact secret-like values and fail closed on high-confidence injection text."""
    all_findings = []
    for item in content:
        value = getattr(item, "text", None)
        if not isinstance(value, str):
            continue
        result = inspect_result(value, block_on_injection=block_on_injection)
        all_findings.extend(result.findings)
        if not result.safe:
            raise ValueError("Blocked by Cerbere: prompt injection detected in tool result")
        try:
            item.text = result.redacted_text
        except (AttributeError, TypeError):
            pass
    return content, all_findings
