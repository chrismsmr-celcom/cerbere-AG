"""
AgentGuard Identity Engine — Multi-tenant RBAC.

Hiérarchie :
  Tenant (entreprise) → Org (département) → {User, Agent} → Session

Rôles RBAC :
  - admin      : tout gérer
  - developer  : créer agents, voir traces
  - auditor    : read-only sur audit + traces
  - viewer     : dashboard uniquement

Format clé API agent :
  ag_{tenant_short}_{org_short}_{agent_short}_{random32}
  Ex: ag_acme_fin_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

Hachage des clés :
  Argon2id (sel intégré, coûteux en CPU/RAM) depuis la v0.6.2.
  Les anciens hashs SHA256 non salés sont acceptés en lecture
  (verify_key) et migrés transparentment via needs_rehash().
"""

import hashlib
import re
import secrets
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Paramètres Argon2id : coûteux à casser par brute force, rapide à vérifier.
_PH = PasswordHasher(
    time_cost=3,  # itérations
    memory_cost=65536,  # 64 Mo de RAM requises par hash
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

# Préfixes de version de hash (migration progressive SHA256 → Argon2id)
_HASH_ALGO_ARGON2 = "argon2id"
_HASH_ALGO_LEGACY_SHA256 = "sha256"


class Role(str, Enum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    VIEWER = "viewer"

    @classmethod
    def hierarchy(cls) -> dict["Role", int]:
        """Plus le niveau est élevé, plus le rôle a de permissions."""
        return {
            cls.ADMIN: 100,
            cls.DEVELOPER: 70,
            cls.AUDITOR: 40,
            cls.VIEWER: 10,
        }

    def has_permission(self, required: "Role") -> bool:
        """Vérifie si self a au moins le niveau de required."""
        h = self.hierarchy()
        return h.get(self, 0) >= h.get(required, 0)


class IdentityType(str, Enum):
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"


@dataclass
class Tenant:
    """Entreprise cliente (top-level isolation)."""

    tenant_id: str
    name: str
    created_at: float = field(default_factory=time.time)
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Org:
    """Département/projet au sein d'un tenant."""

    org_id: str
    tenant_id: str
    name: str
    created_at: float = field(default_factory=time.time)
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class User:
    """Utilisateur humain (se connecte au dashboard)."""

    user_id: str
    org_id: str
    tenant_id: str
    email: str
    role: Role
    display_name: str = ""
    created_at: float = field(default_factory=time.time)
    active: bool = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["role"] = self.role.value
        return d


@dataclass
class Agent:
    """Agent IA (bot) avec sa propre clé API."""

    agent_id: str
    org_id: str
    tenant_id: str
    name: str
    description: str = ""
    created_at: float = field(default_factory=time.time)
    active: bool = True
    max_budget_per_day: float = 100.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResolvedIdentity:
    """
    Identité résolue à partir d'une clé API.
    Injectée dans g.identity par le middleware auth.
    """

    identity_type: IdentityType
    tenant_id: str
    org_id: str
    subject_id: str  # user_id ou agent_id
    role: Role
    agent_name: str | None = None
    user_email: str | None = None

    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    def has_role(self, required: Role) -> bool:
        return self.role.has_permission(required)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["identity_type"] = self.identity_type.value
        d["role"] = self.role.value
        return d


# ═══════════════════════════════════════════════════════════════
# KEY GENERATION & PARSING
# ═══════════════════════════════════════════════════════════════

# Format : ag_{tenant}_{org}_{agent}_{random32}
_AGENT_KEY_PATTERN = re.compile(
    r"^ag_([a-z0-9]{3,8})_([a-z0-9]{3,8})_([a-z0-9]{3,8})_([a-z0-9]{32})$"
)


def short_id(prefix: str = "", length: int = 6) -> str:
    """Génère un ID court lowercase alphanumérique."""
    rand = secrets.token_hex(length)[:length]
    return f"{prefix}{rand}" if prefix else rand


def generate_agent_api_key(tenant_id: str, org_id: str, agent_id: str) -> str:
    """
    Génère une clé API agent au format structuré.
    Permet d'identifier rapidement l'agent sans lookup DB (préfixe).
    """
    # Extraction des short IDs (on prend les 6 derniers chars)
    t_short = tenant_id.replace("tenant_", "")[-6:].lower()
    o_short = org_id.replace("org_", "")[-6:].lower()
    a_short = agent_id.replace("agent_", "")[-6:].lower()
    random_part = secrets.token_hex(16)  # 32 chars hex
    return f"ag_{t_short}_{o_short}_{a_short}_{random_part}"


def parse_agent_api_key(key: str) -> dict[str, str] | None:
    """
    Parse une clé API agent.
    Retourne None si format invalide (ex: ancienne clé "ag-xxx").
    """
    if not key or not key.startswith("ag_"):
        return None
    m = _AGENT_KEY_PATTERN.match(key)
    if not m:
        return None
    return {
        "tenant_short": m.group(1),
        "org_short": m.group(2),
        "agent_short": m.group(3),
        "random_part": m.group(4),
    }


# ═══════════════════════════════════════════════════════════════
# KEY HASHING — Argon2id (v0.6.2+), SHA256 legacy accepté en lecture
# ═══════════════════════════════════════════════════════════════


def hash_key(key: str) -> str:
    """
    Hash une clé API pour stockage DB (ne jamais stocker la clé en clair).

    Argon2id avec sel unique intégré : deux clés identiques produisent
    des hashs différents, et le brute force est ~1000x plus coûteux
    qu'avec SHA256.

    Format stocké : "{algo}${hash_argon2}"
    Ex : "argon2id$argon2id$v=19$m=65536,t=3,p=2$..."
    """
    return f"{_HASH_ALGO_ARGON2}${_PH.hash(key.encode()).decode()}"


def verify_key(stored: str, key: str) -> bool:
    """
    Vérifie une clé contre son hash stocké.

    - Préfixe "argon2id$" → vérification Argon2 native.
    - Hash SHA256 nu (legacy, pré-v0.6.2) → accepté puis migré par
      l'appelant via needs_rehash().
    - Retourne toujours en temps comparable (anti timing attack).
    """
    if not stored or not key:
        # Longueur constante pour éviter les timing attacks
        _PH.hash(b"x" * 32)
        return False

    if stored.startswith(f"{_HASH_ALGO_ARGON2}$"):
        try:
            return _PH.verify(stored.split("$", 1)[1], key.encode())
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    # Ancien format SHA256 nu (legacy) — vérification puis re-hash
    # par l'appelant (voir needs_rehash).
    return hashlib.sha256(key.encode()).hexdigest() == stored


def needs_rehash(stored: str) -> bool:
    """True si le hash stocké est un SHA256 legacy à migrer vers Argon2id."""
    return not stored.startswith(f"{_HASH_ALGO_ARGON2}$")


# ═══════════════════════════════════════════════════════════════
# PERMISSIONS MATRIX
# ═══════════════════════════════════════════════════════════════

# Permissions par rôle (ce que chaque rôle peut faire)
PERMISSIONS = {
    Role.ADMIN: {
        "org:create",
        "org:delete",
        "user:create",
        "user:delete",
        "user:assign_role",
        "agent:create",
        "agent:delete",
        "agent:revoke",
        "traces:view_all",
        "audit:view",
        "audit:verify",
        "settings:edit",
        "billing:view",
    },
    Role.DEVELOPER: {
        "agent:create",
        "agent:revoke",  # ses propres agents
        "traces:view_own_org",
        "audit:view",
        "dashboard:view",
    },
    Role.AUDITOR: {
        "traces:view_own_org",
        "audit:view",
        "audit:verify",
        "dashboard:view",
    },
    Role.VIEWER: {
        "dashboard:view",
    },
}


def role_has_permission(role: Role, permission: str) -> bool:
    """Vérifie si un rôle a une permission spécifique."""
    return permission in PERMISSIONS.get(role, set())
