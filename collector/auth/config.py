"""Configuration du package collector.auth (reprise de l'ancien collector/auth.py)."""
import os

MAGIC_LINK_TTL_SECONDS = 10 * 60
HUMAN_SESSION_TTL_SECONDS = 8 * 60 * 60
MAGIC_LINK_TOKEN_BYTES = 32

MAGIC_LINK_COOKIE = "cerbere_session"

MAGIC_LINK_ENABLED = (
    os.environ.get("AGENTGUARD_MAGIC_LINK_ENABLED", "true").lower()
    in {"1", "true", "yes", "on"}
)


def _env_first(*names: str, default: str = "") -> str:
    """Lit la première variable d'env définie parmi plusieurs alias.

    On accepte AGENTGUARD_* (documenté et déployé) et les noms SMTP_* historiques,
    en priorisant le préfixe AGENTGUARD_.
    """
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


SMTP_HOST = _env_first("AGENTGUARD_SMTP_HOST", "SMTP_HOST").strip()
SMTP_PORT = int(_env_first("AGENTGUARD_SMTP_PORT", "SMTP_PORT", default="587"))
SMTP_USERNAME = _env_first("AGENTGUARD_SMTP_USER", "SMTP_USERNAME").strip()
SMTP_PASSWORD = _env_first("AGENTGUARD_SMTP_PASS", "SMTP_PASSWORD")
SMTP_FROM = _env_first(
    "AGENTGUARD_SMTP_FROM",
    "SMTP_FROM",
    default=(SMTP_USERNAME or "security@agentguard.local"),
).strip()
SMTP_USE_TLS = (
    _env_first("AGENTGUARD_SMTP_USE_TLS", "SMTP_USE_TLS", default="true").lower()
    in {"1", "true", "yes", "on"}
)

APP_BASE_URL = os.environ.get(
    "APP_BASE_URL",
    os.environ.get("AGENTGUARD_APP_URL", "http://localhost:5000"),
).rstrip("/")

PROTECTED_ENDPOINTS = {
    "api.receive_span",
    "api.list_traces",
    "api.get_trace",
    "api.get_metrics",
    "auth.dashboard",
    "trace.trace_detail",
    "api.get_detection_stats",
    "api.api_models",
    "api.api_heatmap",
    "api.api_checks_breakdown",
    "api.api_expensive_spans",
    "api.api_cost_trend",
    "api.api_latency_distribution",
    "api.api_recent_events",
    "api.api_trend_daily",
    "api.get_llm_stats",
    "api.api_audit_trail",
    "api.api_checks_daily",
    "api.api_models_daily",
    "audit.audit_stats",
    "audit.audit_verify",
    "audit.audit_query",
    "identity.create_tenant",
    "identity.create_org",
    "identity.create_user",
    "identity.create_agent",
    "identity.revoke_agent",
    "identity.list_agents",
    "identity.get_me",
}