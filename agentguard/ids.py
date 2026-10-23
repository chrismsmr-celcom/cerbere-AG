"""
Identifiants uniques, triables chronologiquement (UUIDv7).

Pourquoi UUIDv7 plutôt que sha256(time_ns()) ?
  - 74 bits d'aléatoire crypto (os.urandom) : collision quasi impossible,
    même pour deux appels dans la même nanoseconde.
  - Tri lexicographique = tri chronologique : idéal pour index DB.
  - Format standard RFC 9562 (héritier de la proposition UUIDv7).
"""

import os
import time
import uuid


def uuid7() -> str:
    """
    UUID version 7 : timestamp Unix en ms + aléatoire.
    - Collision quasi impossible (74 bits aléatoires)
    - Tri lexicographique = tri chronologique (idéal pour index DB)
    """
    ts_ms = time.time_ns() // 1_000_000
    rand = os.urandom(10)
    b = bytearray(uuid.UUID(int=0).bytes)
    # timestamp 48 bits big-endian
    b[0] = (ts_ms >> 40) & 0xFF
    b[1] = (ts_ms >> 32) & 0xFF
    b[2] = (ts_ms >> 24) & 0xFF
    b[3] = (ts_ms >> 16) & 0xFF
    b[4] = (ts_ms >> 8) & 0xFF
    b[5] = ts_ms & 0xFF
    b[6] = (rand[0] & 0x0F) | 0x70  # version 7
    b[7] = rand[1]
    b[8] = (rand[2] & 0x3F) | 0x80  # variant RFC 4122
    b[9:] = rand[3:]
    return str(uuid.UUID(bytes=bytes(b)))


def short_id(prefix: str = "") -> str:
    """ID court pour l'affichage (PAS un identifiant de sécurité)."""
    return f"{prefix}{uuid.uuid4().hex[:12]}"
