"""Helpers partagés du package collector.api : blueprint, connexions DB,
signer Ed25519, registre d'agents, sérialisation, audit humain."""

import json
import re
import sqlite3
import time
import os
from datetime import datetime

import structlog
from flask import Blueprint, g, request, jsonify, current_app

from collector.db import (
    get_db,
    dict_from_row,
    is_postgres,
    redact_pii,
    _get_db_path,
    sql_placeholder,
)

from decision_engine import DecisionEngine

logger = structlog.get_logger("agentguard.api")

api_bp = Blueprint("api", __name__)

decision_engine = DecisionEngine()


# ── Connexions SQLite : WAL + busy_timeout partout ──────────────────────────
# Ancien bug : sqlite3.connect() nu partout. En cas d'exception non gérée
# (ex. UNIQUE constraint), la transaction restait ouverte avec le verrou
# d'écriture -> "database is locked" en cascade sur TOUTES les requêtes
# suivantes (dont le rate-limiter, qui ne renvoyait plus jamais 429).
# WAL permet lecture concurrente pendant écriture ; busy_timeout absorbe
# les contentions courtes entre workers.

def _sqlite_connect():
    """Connexion SQLite avec WAL + busy_timeout. TOUJOURS utiliser ceci
    à la place de sqlite3.connect(_get_db_path()) directement."""
    conn = sqlite3.connect(_get_db_path(), timeout=3.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=3000")
    return conn


def get_decision_signer():
    signer = current_app.extensions.get("agentguard_decision_signer")
    if signer is not None:
        return signer

    from signing import DecisionSigner

    signing_key = (
        os.environ.get("CERBERE_SIGNING_KEY")
        or os.environ.get("AGENTGUARD_SIGNING_KEY")
    )

    if not signing_key:
        raise RuntimeError(
            "CERBERE_SIGNING_KEY or AGENTGUARD_SIGNING_KEY is required"
        )

    signer = DecisionSigner(signing_key)
    current_app.extensions["agentguard_decision_signer"] = signer
    return signer


def is_server_registered_tool(tool_name):
    tool_name = str(tool_name or "").strip()
    if not tool_name:
        return False

    for policy in decision_engine.policies.values():
        if tool_name in getattr(policy, "blocked_tools", set()):
            continue

        allowed_tools = getattr(policy, "allowed_tools", None)
        if allowed_tools is not None and tool_name in allowed_tools:
            return True

    return False


def _as_json(value, default):
    """PostgreSQL (JSONB) renvoie déjà dict/list ; SQLite renvoie du texte.
    json.loads() sur un dict levait TypeError -> HTTP 500 sur /api/traces/<id> en prod."""
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _iso_utc(value):
    """Horodatage -> ISO 8601 UTC ('...Z'), que le navigateur sait parser."""
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        text = value.isoformat()
    else:
        text = str(value).replace(" ", "T")
    if text.endswith("Z") or "+" in text[10:]:
        return text
    return text.split(".")[0] + "Z"


def _db_run(sql, params=(), fetch=None, commit=False):
    """Exécute une requête écrite avec des '?' (converti en %s pour PostgreSQL)."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(sql.replace("?", "%s") if is_postgres() else sql, params)
        out = None
        if fetch == "one":
            out = cur.fetchone()
        elif fetch == "all":
            out = cur.fetchall()
        rowcount = cur.rowcount
        if commit:
            conn.commit()
        return out, rowcount
    finally:
        conn.close()


def _human_auth():
    """Appelle collector.api.require_human_auth AU MOMENT DE L'APPEL.

    Les modules de routes ne doivent pas importer require_human_auth
    directement : leur copie locale ne verrait pas le monkeypatch des tests
    (collector.api.require_human_auth) et les routes humaines repondraient 401.
    """
    import collector.api as _pkg
    return _pkg.require_human_auth()


# ── Sérialisation des events (Trajectory Timeline) ──────────────────────────

_EVENT_JSON_FIELDS = ["arguments", "arguments_sanitized", "result", "policy_chain", "risk_contributors"]


def _serialize_event(r, full=True):
    for f in _EVENT_JSON_FIELDS:
        r[f] = _as_json(r.get(f), {} if f != "risk_contributors" else [])
    if not full:
        # Ligne allégée pour la liste de la timeline : pas d'arguments/result
        # bruts (potentiellement volumineux/sensibles), juste de quoi
        # afficher la ligne et savoir sur quoi cliquer pour l'expand.
        for f in ("arguments", "arguments_sanitized", "result", "policy_chain"):
            r.pop(f, None)
    return r


# ── Registre d'agents (kill switch, dashboard) ──────────────────────────────

_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_.:@\- ]{1,64}$")
_AGENT_SEEN = {}      # (org, agent) -> dernier upsert (limite l'écriture en base)
_AGENT_STATUS = {}    # (org, agent) -> (ts, status) cache court de lecture
_AGENT_TOUCH_EVERY = 15.0
# Anciens SDK (sans en-tête) : seuls ces endpoints d'ingestion font apparaître l'agent
_INGEST_ENDPOINTS = {"api.receive_span", "api.decide", "api.api_sdk_create_approval"}
_AGENT_STATUS_TTL = 3.0


def _request_agent_id():
    """Identité déclarée par le SDK (en-tête X-Agent-Id) ou identité de la clé agent."""
    raw = (request.headers.get("X-Agent-Id") or "").strip()
    if raw and _AGENT_ID_RE.match(raw):
        return raw
    identity = getattr(g, "agent_identity", None)
    if isinstance(identity, dict) and identity.get("agent_id"):
        return str(identity["agent_id"])[:64]
    # SDK < 0.4.1 : pas d'en-tête X-Agent-Id -> l'agent est identifié par le nom de sa clé API
    key_name = getattr(g, "api_key_name", None)
    if key_name:
        safe = re.sub(r"[^A-Za-z0-9_.:@\- ]", "-", key_name).strip()[:58]
        if safe:
            return "key:" + safe
    return None


def _agent_status(org_id, agent_id):
    """'connected' | 'disconnected' | None (agent inconnu). Fail-open si la base est KO."""
    key = (org_id, agent_id)
    hit = _AGENT_STATUS.get(key)
    now = time.time()
    if hit and now - hit[0] < _AGENT_STATUS_TTL:
        return hit[1]
    try:
        row, _ = _db_run(
            "SELECT status FROM connected_agents WHERE org_id = ? AND agent_id = ?",
            (org_id, agent_id), fetch="one",
        )
    except Exception as exc:
        logger.warning("agent_status_lookup_failed", error=str(exc))
        return None
    status = row[0] if row else None
    _AGENT_STATUS[key] = (now, status)
    return status


def _reject_if_agent_disconnected():
    """403 si l'agent a été déconnecté depuis le dashboard (kill switch)."""
    agent_id = _request_agent_id()
    org_id = getattr(g, "org_id", None)
    if agent_id and org_id and _agent_status(org_id, agent_id) == "disconnected":
        logger.warning("agent_request_refused_disconnected", agent_id=agent_id, org_id=org_id)
        return jsonify({
            "error": "agent_disconnected",
            "agent_id": agent_id,
            "message": "This agent was disconnected from the Cerbere dashboard.",
        }), 403
    return None


def _touch_agent(org_id, agent_id, sdk_version=None, name=None):
    """Enregistre / rafraîchit l'agent (upsert), au plus une fois par _AGENT_TOUCH_EVERY s."""
    key = (org_id, agent_id)
    now = time.time()
    if now - _AGENT_SEEN.get(key, 0) < _AGENT_TOUCH_EVERY:
        return
    _AGENT_SEEN[key] = now
    _db_run(
        """
        INSERT INTO connected_agents (org_id, agent_id, name, sdk_version)
        VALUES (?, ?, ?, ?)
        ON CONFLICT (org_id, agent_id) DO UPDATE SET
            last_seen_at = CURRENT_TIMESTAMP,
            sdk_version = COALESCE(excluded.sdk_version, connected_agents.sdk_version)
        """,
        (org_id, agent_id, name or agent_id, sdk_version), commit=True,
    )


@api_bp.after_app_request
def _register_agent_activity(response):
    """Toute requête authentifiée d'un SDK (X-Agent-Id) alimente le registre des agents."""
    try:
        endpoint = request.endpoint or ""
        if (
            response.status_code < 400
            and endpoint.startswith("api.")
            and (request.headers.get("X-Agent-Id") or endpoint in _INGEST_ENDPOINTS)
        ):
            org_id = getattr(g, "org_id", None)
            agent_id = _request_agent_id()
            if org_id and agent_id:
                sdk_version = (request.headers.get("X-Agent-Sdk") or "")[:32] or None
                name = getattr(g, "api_key_name", None) if agent_id.startswith("key:") else None
                _touch_agent(org_id, agent_id, sdk_version, name)
    except Exception as exc:  # ne jamais casser une réponse pour de la télémétrie
        logger.debug("agent_touch_failed", error=str(exc))
    return response


def _agent_state(status, last_seen):
    if status == "disconnected":
        return "disconnected"
    seen = _iso_utc(last_seen)
    if not seen:
        return "offline"
    try:
        dt = datetime.fromisoformat(seen.replace("Z", "+00:00"))
        idle = (datetime.now(dt.tzinfo) - dt).total_seconds()
    except ValueError:
        return "offline"
    if idle < 300:
        return "connected"
    if idle < 3600:
        return "idle"
    return "offline"


def _audit_human_action(event_name, resource, action, details):
    """Trace best-effort dans l'audit trail infalsifiable (onglet Compliance Audit)."""
    try:
        from collector.audit_routes import get_audit_log, AuditEventType
        audit = get_audit_log()
        if audit:
            audit.log_event(
                event_type=getattr(AuditEventType, event_name),
                org_id=g.org_id,
                actor=f"human:{getattr(g, 'human_email', None) or g.org_id}",
                resource=resource,
                action=action,
                details=details,
                risk_level="high",
            )
    except Exception as exc:
        logger.warning("audit_log_failed", error=str(exc))
