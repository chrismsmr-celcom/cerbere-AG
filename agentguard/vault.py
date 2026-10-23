"""IncidentVault — mapping chiffré token → valeur claire, TTL court.

Modèle de chiffrement : boîte scellée (X25519 + HKDF-SHA256 + AES-256-GCM).
Le SDK ne reçoit que la CLÉ PUBLIQUE de l'incident : il sait chiffrer, il ne
sait pas déchiffrer (aucune clé de déchiffrement n'existe dans ce processus).
La clé privée est générée par le collector à l'ouverture de l'incident, ne
quitte jamais le collector, et y est stockée chiffrée par une clé maître.

Cycle de vie :
  1. un admin HUMAIN ouvre l'incident depuis le dashboard
     (POST /api/incidents {agent_id, ttl_seconds, reason}) ;
  2. le SDK de l'agent concerné récupère la clé publique
     (GET /v1/incident/active) avec sa clé API habituelle ;
  3. SDK scelle chaque valeur masquée : vault.seal(token, value) ;
  4. SDK envoie le chiffré (POST /v1/incident/sealed) ;
  5. un admin humain rouvre une valeur (POST /api/incidents/<id>/reveal),
     motif obligatoire, journalisé dans l'audit chaîné ;
  6. TTL expiré → le collector détruit chiffrés ET clé privée : irrécupérable.

Garanties et limites :
  - un processus d'agent compromis ne peut pas relire ce qu'il a scellé ;
  - il PEUT sceller de fausses entrées (la clé publique est publique) : le
    contenu d'un coffre est une preuve de ce que l'agent a vu, pas une preuve
    d'authenticité du contenu ;
  - la mémoire tampon est bornée ; en cas de débordement ou d'échecs répétés,
    les preuves sont abandonnées (jamais écrites en clair) et l'événement est
    journalisé SANS valeur.
"""

import os
import time
from typing import Any

import structlog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = structlog.get_logger("agentguard.vault")

_HKDF_INFO = b"cerbere-incident-v1|"


def _derive_key(shared: bytes, incident_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO + incident_id.encode(),
    ).derive(shared)


def seal_to_public_key(
    public_key: bytes, incident_id: str, token: str, plaintext: str
) -> bytes:
    """Chiffre pour le détenteur de la clé privée. Format :
    clé publique éphémère (32) | nonce (12) | chiffré+tag.
    incident_id et token sont liés au chiffré (AAD) : un blob ne peut pas être
    rejoué sous un autre token ou un autre incident."""
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(public_key))
    nonce = os.urandom(12)
    aad = f"{incident_id}|{token}".encode()
    ct = AESGCM(_derive_key(shared, incident_id)).encrypt(
        nonce, plaintext.encode(), aad
    )
    eph_pub = eph.public_key().public_bytes_raw()
    return eph_pub + nonce + ct


class IncidentVault:
    MAX_PENDING = 2000
    MAX_CONSECUTIVE_FAILURES = 5
    MIN_FLUSH_INTERVAL = 2.0

    def __init__(
        self,
        collector_url: str,
        incident_id: str,
        public_key: bytes,
        expires_at: float,
        headers: dict[str, str] | None = None,
        timeout: float = 3.0,
    ):
        if len(public_key) != 32:
            raise ValueError("clé publique d'incident : 32 octets attendus (X25519)")
        self._public_key = public_key
        self.collector_url = collector_url.rstrip("/")
        self.incident_id = incident_id
        self.expires_at = float(expires_at)
        self._headers = headers or {}
        self._timeout = timeout
        self._sealed: dict[str, bytes] = {}
        self._failures = 0
        self._dropped = 0
        self._last_flush = 0.0

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    @property
    def dropped(self) -> int:
        return self._dropped

    def seal(self, token: str, plaintext: str) -> str:
        """Chiffre la valeur claire et la garde pour flush. Ne lève jamais :
        si le TTL est expiré ou la mémoire tampon pleine, le masque reste et
        rien n'est conservé."""
        if self.expired or token in self._sealed:
            return token
        if len(self._sealed) >= self.MAX_PENDING:
            self._dropped += 1
            if self._dropped == 1:
                logger.warning(
                    "incident_vault_buffer_full", incident_id=self.incident_id
                )
            return token
        try:
            self._sealed[token] = seal_to_public_key(
                self._public_key, self.incident_id, token, plaintext
            )
        except Exception as exc:  # jamais de valeur dans le log
            self._dropped += 1
            logger.warning(
                "incident_vault_seal_failed",
                incident_id=self.incident_id,
                error_type=type(exc).__name__,
            )
        return token

    def pending(self) -> int:
        return len(self._sealed)

    def flush(self, session: Any = None, force: bool = False) -> int:
        """Envoie le chiffré au collector. Retourne le nombre d'entrées
        envoyées. Ne lève pas : un échec est journalisé, la reprise est bornée
        (MAX_CONSECUTIVE_FAILURES), après quoi le tampon est abandonné."""
        if not self._sealed:
            return 0
        now = time.time()
        if not force and now - self._last_flush < self.MIN_FLUSH_INTERVAL:
            return 0
        self._last_flush = now
        import requests

        batch = dict(self._sealed)
        try:
            resp = (session or requests).post(
                f"{self.collector_url}/v1/incident/sealed",
                json={
                    "incident_id": self.incident_id,
                    "sealed": {tok: ct.hex() for tok, ct in batch.items()},
                },
                headers=self._headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except Exception as exc:
            self._failures += 1
            logger.warning(
                "incident_vault_flush_failed",
                incident_id=self.incident_id,
                pending=len(batch),
                consecutive_failures=self._failures,
                error_type=type(exc).__name__,
            )
            if self._failures >= self.MAX_CONSECUTIVE_FAILURES:
                self._dropped += len(self._sealed)
                self._sealed.clear()
                logger.error(
                    "incident_vault_evidence_dropped",
                    incident_id=self.incident_id,
                    dropped_total=self._dropped,
                )
            return 0
        self._failures = 0
        for tok in batch:
            self._sealed.pop(tok, None)
        return len(batch)

    def close(self, session: Any = None) -> int:
        """Fin de capture : flush final. Retourne le nombre d'entrées perdues
        (non envoyées), journalisé."""
        self.flush(session, force=True)
        lost = len(self._sealed)
        if lost:
            self._dropped += lost
            self._sealed.clear()
            logger.error(
                "incident_vault_closed_with_loss",
                incident_id=self.incident_id,
                lost=lost,
            )
        return lost
