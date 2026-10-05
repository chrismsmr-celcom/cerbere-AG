"""Configuration du package collector.auth (lue depuis l'environnement)."""
import os


def _env_first(*names, default=None):
    """Retourne la première variable d'environnement non vide parmi `names`."""
    for name in names:
        value = os.environ.get(name)
        if value not in (None, ""):
            return value
    return default


def _as_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


MAGIC_LINK_TTL_SECONDS = int(_env_first("AGENTGUARD_MAGIC_LINK_TTL", default=300))
HUMAN_SESSION_TTL_SECONDS = int(_env_first("AGENTGUARD_SESSION_TTL", default=60 * 60 * 24 * 7))
MAGIC_LINK_TOKEN_BYTES = int(_env_first("AGENTGUARD_MAGIC_LINK_TOKEN_BYTES", default=32))
MAGIC_LINK_COOKIE = _env_first("AGENTGUARD_SESSION_COOKIE", default="ag_session")
MAGIC_LINK_ENABLED = _as_bool(_env_first("AGENTGUARD_MAGIC_LINK_ENABLED"), default=True)

SMTP_HOST = _env_first("AGENTGUARD_SMTP_HOST", "SMTP_HOST", default="")
SMTP_PORT = int(_env_first("AGENTGUARD_SMTP_PORT", "SMTP_PORT", default=587))
SMTP_USERNAME = _env_first("AGENTGUARD_SMTP_USERNAME", "SMTP_USERNAME", default="")
SMTP_PASSWORD = _env_first("AGENTGUARD_SMTP_PASSWORD", "SMTP_PASSWORD", default="")
SMTP_FROM = _env_first("AGENTGUARD_SMTP_FROM", "SMTP_FROM", default=SMTP_USERNAME)
SMTP_USE_TLS = _as_bool(_env_first("AGENTGUARD_SMTP_USE_TLS", "SMTP_USE_TLS"), default=True)

APP_BASE_URL = _env_first("AGENTGUARD_APP_BASE_URL", "APP_BASE_URL", default="http://localhost:5000")

PROTECTED_ENDPOINTS = frozenset()  # TODO: à remplir d'après middleware.py
