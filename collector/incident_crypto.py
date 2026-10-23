"""Cryptographie d'incident, côté collector uniquement.

Le SDK (agentguard/vault.py) ne sait que CHIFFRER avec la clé publique. Ici
vivent la génération de la paire de clés, la protection de la clé privée au
repos (chiffrée par une clé maître) et le déchiffrement, que seule une route
humaine (admin, motif, audit) peut déclencher.

Clé maître : AGENTGUARD_INCIDENT_MASTER_KEY, 64 caractères hexadécimaux
(32 octets), fournie par l'environnement / un gestionnaire de secrets, jamais
stockée dans la base. Sans elle, la fonctionnalité est désactivée (fail-closed).
Détruire la clé privée d'un incident (crypto-shredding) rend ses preuves
irrécupérables même si des copies de la base subsistent.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentguard.vault import _derive_key


class IncidentCryptoError(Exception):
    """Clé maître absente/invalide, ou blob illisible. Jamais de valeur dedans."""


def _master_key() -> bytes:
    raw = (os.getenv("AGENTGUARD_INCIDENT_MASTER_KEY") or "").strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise IncidentCryptoError("master key must be hexadecimal") from exc
    if len(key) != 32:
        raise IncidentCryptoError("master key must be 32 bytes (64 hex chars)")
    return key


def master_key_ready() -> bool:
    try:
        _master_key()
        return True
    except IncidentCryptoError:
        return False


def generate_incident_keypair(incident_id: str) -> tuple[str, str]:
    """Retourne (clé publique hex, clé privée chiffrée hex)."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    nonce = os.urandom(12)
    wrapped = nonce + AESGCM(_master_key()).encrypt(
        nonce, priv.private_bytes_raw(), f"incident-key|{incident_id}".encode()
    )
    return pub.hex(), wrapped.hex()


def open_sealed(
    wrapped_private_key_hex: str, incident_id: str, token: str, blob: bytes
) -> str:
    """Déchiffre un blob scellé par le SDK. Lève IncidentCryptoError."""
    try:
        wrapped = bytes.fromhex(wrapped_private_key_hex)
        priv_bytes = AESGCM(_master_key()).decrypt(
            wrapped[:12], wrapped[12:], f"incident-key|{incident_id}".encode()
        )
        priv = X25519PrivateKey.from_private_bytes(priv_bytes)
        eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
        shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        plaintext = AESGCM(_derive_key(shared, incident_id)).decrypt(
            nonce, ct, f"{incident_id}|{token}".encode()
        )
        return plaintext.decode()
    except IncidentCryptoError:
        raise
    except Exception as exc:
        raise IncidentCryptoError("cannot open sealed value") from exc
