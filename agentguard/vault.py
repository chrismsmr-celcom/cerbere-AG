"""IncidentVault — mapping chiffré token → valeur claire, TTL court.

Le SDK ne détient JAMAIS la clé de déchiffrement : elle est générée par le
collector à l'ouverture de l'incident (/v1/incident/start). Le SDK chiffre
( AES-256-GCM ) avec, et seul le collector peut déchiffrer.

Cycle de vie :
  1. admin du dashboard → POST /v1/incident/start {ttl_seconds}
     → collector génère incident_id + key (AES 256-bit), répond au SDK
  2. SDK scelle chaque valeur masquée : vault.seal(token, value)
  3. SDK flush le ciphertext vers POST /v1/incident/sealed
  4. Forensic → POST /v1/incident/reveal {incident_id, token, reason}
     → collector : vérifie TTL, déchiffre, écrit audit_log, répond
  5. TTL expiré → collector purge incidents_mapping : irrécupérable
"""

import os
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class IncidentVault:
    def __init__(self, collector_url: str, incident_id: str, key: bytes,
                 ttl_seconds: int = 24 * 3600, started_at: float | None = None):
        if len(key) != 32:
            raise ValueError("clé d'incident : 32 octets attendus (AES-256)")
        self._aes = AESGCM(key)
        self.collector_url = collector_url.rstrip("/")
        self.incident_id = incident_id
        self.ttl_seconds = ttl_seconds
        self.started_at = started_at or time.time()
        self._sealed: dict[str, bytes] = {}
        self._audit: list[dict] = []   # mémoire locale des seals (jamais envoyée)

    @property
    def expired(self) -> bool:
        return time.time() - self.started_at > self.ttl_seconds

    def seal(self, token: str, plaintext: str) -> str:
        """Chiffre la valeur claire et la garde pour flush vers le collector.
        Appelée par SpanMasker en mode incident. Ne lève PAS si le TTL est
        expiré : le masque reste, mais plus rien n'est conservé."""
        if self.expired:
            return token
        nonce = os.urandom(12)
        ct = nonce + self._aes.encrypt(nonce, plaintext.encode(), None)
        self._sealed[token] = ct
        self._audit.append({
            "ts": time.time(), "event": "seal", "token": token,
        })
        return token

    def pending(self) -> int:
        return len(self._sealed)

    def flush(self, session: Any = None) -> int:
        """Envoie le ciphertext au collector (POST /v1/incident/sealed).
        Retourne le nombre d'entrées flushées. Le collector purge selon TTL."""
        if not self._sealed:
            return 0
        import requests

        body = {
            "incident_id": self.incident_id,
            "ttl_seconds": self.ttl_seconds,
            "sealed": {
                tok: ct.hex() for tok, ct in self._sealed.items()
            },
        }
        resp = (session or requests).post(
            f"{self.collector_url}/v1/incident/sealed", json=body, timeout=10
        )
        resp.raise_for_status()
        n = len(self._sealed)
        self._sealed.clear()   # l'agent ne garde RIEN en clair ni en chiffré
        return n

    def close(self, session: Any = None) -> None:
        """Fin d'incident : flush final. Après close(), le mode repasse
        à redact — plus aucune capture n'a lieu."""
        try:
            self.flush(session)
        except Exception:
            pass  # les données non flushées sont simplement perdues : voulu