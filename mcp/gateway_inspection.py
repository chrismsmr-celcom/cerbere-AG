"""Inspection des réponses et registre de taints.

Deux rôles :

1. ResponseInspector : nettoie le TEXTE retourné par les serveurs amonts
   avant qu'il n'entre dans le contexte de l'agent (PII et secrets redactés,
   comme mcp_server.py mais appliqué AUTOMATIQUEMENT à chaque résultat).

2. TaintRegistry : mémorise (en mémoire de la gateway, jamais envoyé au
   collector) les valeurs sensibles vues dans les résultats d'outils internes.
   Avant chaque appel vers un serveur marqué `external: true`, les arguments
   sont comparés aux taints — en clair, base64, hex ou URL-encodé — et
   l'appel est bloqué s'il en contient un. Réutilise la logique de taint.py
   du SDK mais à l'échelle de la gateway, sans modification du code agent.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse

# Mêmes familles de motifs que mcp_server.py (cohérence du produit).
PII_PATTERNS: dict[str, str] = {
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "API_KEY": r"\b(?:sk-|pk-|api_|ghp_|ag-)[a-zA-Z0-9_\-]{16,}\b",
}
# Motifs qui marquent une valeur comme TAINT (leak potentiel vers l'extérieur).
SECRET_PATTERNS: list[tuple[str, str]] = [
    ("API_KEY", PII_PATTERNS["API_KEY"]),
    ("CREDIT_CARD", PII_PATTERNS["CREDIT_CARD"]),
    ("SSN", PII_PATTERNS["SSN"]),
]
MIN_TAINT_LENGTH = 12


def _encodings(value: str) -> set[str]:
    """Toutes les formes sous lesquelles une valeur peut se cacher."""
    forms = {value}
    try:
        forms.add(base64.b64encode(value.encode()).decode())
    except Exception:  # pragma: no cover
        pass
    try:
        forms.add(binascii.hexlify(value.encode()).decode())
    except Exception:  # pragma: no cover
        pass
    forms.add(urllib.parse.quote(value, safe=""))
    return {f for f in forms if f}


class TaintRegistry:
    """Registre mémoire des valeurs sensibles traversant la gateway."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._taints: list[str] = []
        self._max = max_entries

    def register(self, value: str) -> None:
        value = value.strip()
        if len(value) < MIN_TAINT_LENGTH or value in self._taints:
            return
        self._taints.append(value)
        if len(self._taints) > self._max:
            self._taints.pop(0)

    def find_in_arguments(self, arguments: dict) -> str | None:
        """Retourne le premier taint présent dans les arguments, sinon None.

        Compare le texte sérialisé des arguments aux formes clair/base64/
        hex/URL de chaque taint. Volontairement linéaire et borné : le
        registre est petit et les appels doivent rester rapides.
        """
        if not self._taints:
            return None
        try:
            blob = json.dumps(arguments, ensure_ascii=False, default=str)
        except Exception:
            blob = str(arguments)
        for taint in self._taints:
            for form in _encodings(taint):
                if form in blob:
                    return taint
        return None

    def clear(self) -> None:
        self._taints.clear()


class ResponseInspector:
    """Redacte les PII/secrets dans les résultats d'outils avant retour à l'agent."""

    def __init__(self, redact_pii: bool = True, redact_secrets: bool = True) -> None:
        self.redact_pii = redact_pii
        self.redact_secrets = redact_secrets
        self.taints = TaintRegistry()

    def inspect_text(self, text: str) -> tuple[str, list[str]]:
        """Retourne (texte_redacté, types_trouvés) et enregistre les taints."""
        findings: list[str] = []
        redacted = text

        for ptype, pattern in PII_PATTERNS.items():
            is_secret = ptype in {"API_KEY", "CREDIT_CARD", "SSN"}
            if ptype == "API_KEY" and not self.redact_secrets:
                continue
            if ptype != "API_KEY" and not self.redact_pii:
                continue

            matches = re.findall(pattern, redacted)
            if not matches:
                continue
            findings.append(ptype)
            redacted = re.sub(pattern, f"[REDACTED_{ptype}]", redacted)
            if is_secret:
                for m in matches:
                    self.taints.register(m)

        return redacted, findings

    def inspect_content(self, content: list) -> list:
        """Applique inspect_text à chaque élément textuel d'un résultat MCP."""
        for item in content:
            text = getattr(item, "text", None)
            if isinstance(text, str) and text:
                redacted, _ = self.inspect_text(text)
                try:
                    setattr(item, "text", redacted)
                except Exception:  # pragma: no cover - content figé
                    pass
        return content
