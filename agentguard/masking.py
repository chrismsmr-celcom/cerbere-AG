"""Masquage des spans avant envoi au collector.

Modes (AGENTGUARD_MASKING) :
  redact   — défaut : les PII/secrets sont remplacés par un hash
             unidirectionnel. AUCUNE récupération possible.
  incident — idem dans les spans, MAIS le vault local conserve une copie
             chiffrée (clé du collector) avec TTL. Récupérable uniquement
             via le collector, par un admin, avec audit.
  off      — pas de masquage (dev uniquement, warning émis).
"""

import hashlib
import json
import os
import re
from typing import Any

from .taint import _PII_PATTERNS, _SECRET_PATTERNS

_ALL_SENSITIVE = list(_SECRET_PATTERNS) + list(_PII_PATTERNS)


class SpanMasker:
    def __init__(self, mode: str | None = None, vault: Any = None):
        self.mode = (mode or os.getenv("AGENTGUARD_MASKING", "redact")).lower()
        self.vault = vault
        if self.mode == "off":
            import warnings

            warnings.warn("AGENTGUARD_MASKING=off : spans non masqués. Dev uniquement.")

    # -- tokenisation -----------------------------------------------------
    def _token(self, plaintext: str) -> str:
        digest = hashlib.sha256(plaintext.encode()).hexdigest()[:12]
        return f"\u27e6CERB:{digest}\u27e7"

    def mask_text(self, text: str) -> str:
        """Remplace chaque secret/PII par un token. En mode incident,
        scelle la valeur claire dans le vault avant de l'effacer."""
        if not text or self.mode == "off":
            return text
        for pat in _ALL_SENSITIVE:
            for m in list(pat.finditer(text)):
                value = m.group(0)
                token = self._token(value)
                if self.mode == "incident" and self.vault is not None:
                    self.vault.seal(token, value)
                text = text.replace(value, token)
        return text

    # -- application récursive aux payloads de span ------------------------
    def mask_payload(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.mask_text(obj)
        if isinstance(obj, dict):
            return {k: self.mask_payload(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return type(obj)(self.mask_payload(v) for v in obj)
        return obj

    def mask_span(self, payload: dict) -> dict:
        """Masque les champs sensibles d'un span prêt à partir au collector."""
        for field in ("params", "result", "input", "output", "prompt", "response"):
            if field in payload and payload[field] is not None:
                payload[field] = self.mask_payload(payload[field])
        return payload