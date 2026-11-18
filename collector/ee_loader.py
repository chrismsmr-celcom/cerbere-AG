"""Pont entre le cœur (Apache-2.0) et les fonctions Enterprise Edition (ee/).

Le dossier `ee/` est optionnel : s'il est absent, Cerbere démarre normalement et ces
fonctions sont simplement indisponibles. Une vraie erreur DANS `ee/` (dépendance manquante,
bug) n'est jamais masquée : seule l'absence de `ee` lui-même est tolérée.
"""

from __future__ import annotations

import importlib
from types import ModuleType


def load_enterprise_module(name: str) -> ModuleType | None:
    """Importe un module de `ee/`, ou retourne None si `ee/` n'est pas présent."""
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.split(".")[0] == "ee":
            return None
        raise


def enterprise_available() -> bool:
    return load_enterprise_module("ee") is not None


def sso_config():
    """Configuration SSO active (Team/Enterprise), ou None si absente ou non licenciée."""
    oidc = load_enterprise_module("ee.sso.oidc")
    return oidc.get_config() if oidc else None
