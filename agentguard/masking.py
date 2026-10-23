"""Masquage des spans avant envoi au collector.

Modes (AGENTGUARD_MASKING) :
  redact   — défaut : les PII/secrets sont remplacés par un token HMAC.
             AUCUNE récupération possible.
  incident — idem dans les spans, MAIS une copie chiffrée avec la CLÉ PUBLIQUE
             de l'incident est scellée dans le vault, avec TTL. Seul le
             collector (clé privée), par un admin humain, avec audit, peut la
             rouvrir. Ce mode ne s'active que via start_incident_capture().
  off      — pas de masquage. Refusé sauf si AGENTGUARD_ALLOW_UNMASKED=true
             (développement uniquement) : sinon retour automatique à redact.

Tokens : HMAC-SHA256(clé, valeur). Sans la clé, impossible de tester des
valeurs prévisibles (emails, numéros). La clé vient de AGENTGUARD_MASKING_KEY
(tokens stables entre processus, utile pour corréler) ; à défaut elle est
aléatoire par processus (tokens non corrélables entre redémarrages).

Couverture : TOUTES les chaînes du payload sont masquées (valeurs ET clés de
dictionnaire), sauf une liste blanche de champs structurels. Un champ ajouté
demain au modèle de span est donc masqué par défaut.
"""

import hashlib
import hmac
import os
import re
import secrets
import warnings
from typing import Any

from .taint import _PII_PATTERNS, _SECRET_PATTERNS

_ALL_SENSITIVE = list(_SECRET_PATTERNS) + list(_PII_PATTERNS)

# Champs structurels : jamais de contenu utilisateur, nécessaires tels quels.
_SAFE_KEYS = frozenset(
    {
        "trace_id",
        "span_id",
        "span_type",
        "check_name",
        "risk_level",
        "action",
        "taint_level",
        "model",
        "tool_name",
    }
)

_TOKEN_RE = re.compile("\u27e6CERB:[0-9a-f]{16}\u27e7")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


class SpanMasker:
    def __init__(
        self,
        mode: str | None = None,
        vault: Any = None,
        key: bytes | str | None = None,
    ):
        requested = (mode or os.getenv("AGENTGUARD_MASKING", "redact")).lower()
        if requested not in {"redact", "incident", "off"}:
            warnings.warn(
                f"AGENTGUARD_MASKING={requested!r} inconnu : retour à 'redact'."
            )
            requested = "redact"
        if requested == "off" and not _truthy(os.getenv("AGENTGUARD_ALLOW_UNMASKED")):
            warnings.warn(
                "AGENTGUARD_MASKING=off ignoré (AGENTGUARD_ALLOW_UNMASKED non "
                "défini) : masquage 'redact' conservé."
            )
            requested = "redact"
        if requested == "off":
            warnings.warn("AGENTGUARD_MASKING=off : spans non masqués. Dev uniquement.")
        self.mode = requested
        self.vault = vault

        raw = key if key is not None else os.getenv("AGENTGUARD_MASKING_KEY")
        if raw:
            raw = raw.encode() if isinstance(raw, str) else raw
            if len(raw) < 16:
                raise ValueError("AGENTGUARD_MASKING_KEY : 16 caractères minimum")
            self._key = hashlib.sha256(b"cerbere-masking-v1|" + raw).digest()
        else:
            self._key = secrets.token_bytes(32)

    # -- tokenisation -----------------------------------------------------
    def _token(self, plaintext: str) -> str:
        digest = hmac.new(self._key, plaintext.encode(), hashlib.sha256).hexdigest()
        return f"\u27e6CERB:{digest[:16]}\u27e7"

    def _sub(self, pattern: "re.Pattern[str]", text: str) -> str:
        def repl(m: "re.Match[str]") -> str:
            value = m.group(0)
            token = self._token(value)
            if self.mode == "incident" and self.vault is not None:
                try:
                    self.vault.seal(token, value)
                except Exception:  # le masquage prime : jamais de fuite
                    pass
            return token

        return pattern.sub(repl, text)

    def mask_text(self, text: str) -> str:
        """Remplace chaque secret/PII par un token. En mode incident,
        scelle la valeur claire dans le vault avant de l'effacer."""
        if not text or self.mode == "off":
            return text
        # Ne jamais re-masquer un token déjà produit.
        parts = _TOKEN_RE.split(text)
        tokens = _TOKEN_RE.findall(text)
        out: list[str] = []
        for i, part in enumerate(parts):
            for pat in _ALL_SENSITIVE:
                part = self._sub(pat, part)
            out.append(part)
            if i < len(tokens):
                out.append(tokens[i])
        return "".join(out)

    # -- application récursive aux payloads de span ------------------------
    def mask_payload(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.mask_text(obj)
        if isinstance(obj, dict):
            return {
                (self.mask_text(k) if isinstance(k, str) else k): (
                    v
                    if k in _SAFE_KEYS and isinstance(v, str)
                    else self.mask_payload(v)
                )
                for k, v in obj.items()
            }
        if isinstance(obj, (list, tuple)):
            return type(obj)(self.mask_payload(v) for v in obj)
        return obj

    def mask_span(self, payload: dict) -> dict:
        """Masque tout le contenu d'un span prêt à partir au collector."""
        if self.mode == "off":
            return payload
        return self.mask_payload(payload)
