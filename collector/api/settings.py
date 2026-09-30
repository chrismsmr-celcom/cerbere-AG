"""Réglages du dashboard persistés en base : budgets par agent, règles de
politique, destinations d'alertes.

Les tables sont créées à la demande (CREATE TABLE IF NOT EXISTS, idempotent,
compatible SQLite et PostgreSQL). Le même SQL est fourni dans
migrations/2026_09_30_dashboard_settings.sql pour Supabase / psql.

Lecture : n'importe quelle authentification valide (session ou clé API).
Écriture : session humaine uniquement (un agent ne doit pas pouvoir
modifier son propre budget, ses règles ou ses destinations d'alerte).
"""

import ipaddress
import json
import math
import re
import secrets
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
from flask import jsonify, g, request

from collector.auth import require_auth
from collector.api.helpers import (
    api_bp, logger, _db_run, _iso_utc, _human_auth, _AGENT_ID_RE,
)

# ── Schéma (SQL portable SQLite + PostgreSQL) ───────────────────────────────

SETTINGS_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS agent_budgets (
        org_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        max_budget_usd DOUBLE PRECISION NOT NULL,
        period TEXT NOT NULL DEFAULT 'daily',
        action_on_exceed TEXT NOT NULL DEFAULT 'warn',
        updated_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (org_id, agent_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS policy_rules (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        agent_scope TEXT NOT NULL DEFAULT 'all',
        event_type TEXT NOT NULL DEFAULT 'all',
        tool_name TEXT,
        detection_type TEXT NOT NULL,
        operator TEXT NOT NULL DEFAULT '>',
        threshold TEXT,
        action TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_policy_rules_org ON policy_rules(org_id)",
    """
    CREATE TABLE IF NOT EXISTS alert_destinations (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        type TEXT NOT NULL,
        target TEXT NOT NULL,
        levels TEXT NOT NULL,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_alert_destinations_org ON alert_destinations(org_id)",
]


def ensure_settings_tables():
    """Idempotent ; appelé au début de chaque route (coût négligeable)."""
    for ddl in SETTINGS_SCHEMA:
        _db_run(ddl, commit=True)


# ── Validation ──────────────────────────────────────────────────────────────

PERIODS = ("daily", "weekly", "monthly")
BUDGET_ACTIONS = ("warn", "block")
RULE_EVENT_TYPES = ("all", "tool_call", "llm_call")
RULE_DETECTIONS = ("pii_detection", "prompt_injection", "tool_policy",
                   "budget_policy", "custom_regex")
RULE_OPERATORS = (">", "<", "==", "contains")
RULE_ACTIONS = ("allow", "require_approval", "block", "redact")
DEST_TYPES = ("slack", "discord", "webhook", "email")
DEST_LEVELS = ("critical", "high", "medium", "low")
MAX_RULES, MAX_DESTINATIONS, MAX_BUDGETS = 100, 20, 500

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[A-Za-z]{2,}$")


def _err(message, status=400):
    return jsonify({"error": message}), status


def _actor():
    return getattr(g, "human_email", None) or getattr(g, "org_id", None) or "human"


def _valid_agent_id(agent_id):
    return bool(agent_id) and bool(_AGENT_ID_RE.match(agent_id))


def _check_webhook_url(url, resolve):
    """HTTPS obligatoire, pas d'identifiants, pas d'hôte interne (anti-SSRF).
    resolve=True : résout aussi le DNS et refuse toute IP non publique."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("URL must start with https://")
    if parsed.username or parsed.password:
        raise ValueError("URL must not contain credentials")
    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith((".local", ".internal")):
        raise ValueError("URL must point to a public host")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise ValueError("URL must point to a public host")
    if resolve and ip is None:
        try:
            infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise ValueError("Host cannot be resolved")
        for info in infos:
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise ValueError("URL must point to a public host")


def _mask_target(dest_type, target):
    """Une URL de webhook est un secret : on ne renvoie jamais l'URL complète."""
    if dest_type == "email":
        return target
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.hostname}/…{target[-4:]}"


# ═══════════════════════════════════════════════════════════════
# BUDGETS PAR AGENT
# ═══════════════════════════════════════════════════════════════

def _period_start(period):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "weekly":
        day -= timedelta(days=day.weekday())
    elif period == "monthly":
        day = day.replace(day=1)
    return day.strftime("%Y-%m-%d %H:%M:%S")


def _spent(org_id, agent_id, period):
    row, _ = _db_run(
        "SELECT COALESCE(SUM(cost_usd), 0) FROM spans "
        "WHERE org_id = ? AND agent_id = ? AND created_at >= ?",
        (org_id, agent_id, _period_start(period)), fetch="one")
    return float((row or [0])[0] or 0)


def _budget_dict(org_id, agent_id, max_usd, period, action):
    spent = _spent(org_id, agent_id, period)
    return {
        "agent_id": agent_id, "configured": True,
        "max_budget_usd": float(max_usd), "period": period,
        "action_on_exceed": action,
        "spent_usd": round(spent, 6),
        "pct": round(min(100.0, spent / max_usd * 100), 1) if max_usd else 0,
        "exceeded": spent >= max_usd,
    }


@api_bp.route("/api/budgets", methods=["GET"], endpoint="api_list_budgets")
def api_list_budgets():
    if not require_auth():
        return _err("Unauthorized", 401)
    try:
        ensure_settings_tables()
        rows, _ = _db_run(
            "SELECT agent_id, max_budget_usd, period, action_on_exceed "
            "FROM agent_budgets WHERE org_id = ? ORDER BY agent_id",
            (g.org_id,), fetch="all")
        budgets = [_budget_dict(g.org_id, r[0], r[1], r[2], r[3]) for r in rows]
    except Exception as exc:
        logger.error("budgets_list_failed", error=str(exc))
        return _err(f"Database error: {exc}", 500)
    return jsonify({"budgets": budgets, "total": len(budgets)})


@api_bp.route("/api/budgets/<agent_id>", methods=["GET"], endpoint="api_get_budget")
def api_get_budget(agent_id):
    if not require_auth():
        return _err("Unauthorized", 401)
    if not _valid_agent_id(agent_id):
        return _err("Invalid agent id")
    try:
        ensure_settings_tables()
        row, _ = _db_run(
            "SELECT max_budget_usd, period, action_on_exceed FROM agent_budgets "
            "WHERE org_id = ? AND agent_id = ?", (g.org_id, agent_id), fetch="one")
        if row:
            return jsonify(_budget_dict(g.org_id, agent_id, row[0], row[1], row[2]))
        return jsonify({"agent_id": agent_id, "configured": False,
                        "max_budget_usd": None, "period": "daily",
                        "action_on_exceed": "warn",
                        "spent_usd": round(_spent(g.org_id, agent_id, "daily"), 6),
                        "pct": 0, "exceeded": False})
    except Exception as exc:
        logger.error("budget_get_failed", error=str(exc))
        return _err(f"Database error: {exc}", 500)


@api_bp.route("/api/budgets/<agent_id>", methods=["PUT"], endpoint="api_put_budget")
def api_put_budget(agent_id):
    if not _human_auth():
        return _err("Human session required", 401)
    if not _valid_agent_id(agent_id):
        return _err("Invalid agent id")
    body = request.get_json(silent=True) or {}
    try:
        amount = float(body.get("max_budget_usd"))
    except (TypeError, ValueError):
        return _err("max_budget_usd must be a number")
    if not math.isfinite(amount) or amount <= 0 or amount > 1e6:
        return _err("max_budget_usd must be between 0 and 1,000,000")
    period = str(body.get("period") or "daily")
    action = str(body.get("action_on_exceed") or "warn")
    if period not in PERIODS:
        return _err(f"period must be one of {list(PERIODS)}")
    if action not in BUDGET_ACTIONS:
        return _err(f"action_on_exceed must be one of {list(BUDGET_ACTIONS)}")
    try:
        ensure_settings_tables()
        count, _ = _db_run("SELECT COUNT(*) FROM agent_budgets WHERE org_id = ?",
                           (g.org_id,), fetch="one")
        exists, _ = _db_run("SELECT 1 FROM agent_budgets WHERE org_id = ? AND agent_id = ?",
                            (g.org_id, agent_id), fetch="one")
        if not exists and count[0] >= MAX_BUDGETS:
            return _err("Budget limit reached for this organization", 409)
        _db_run(
            """INSERT INTO agent_budgets
                   (org_id, agent_id, max_budget_usd, period, action_on_exceed, updated_by)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (org_id, agent_id) DO UPDATE SET
                   max_budget_usd = excluded.max_budget_usd,
                   period = excluded.period,
                   action_on_exceed = excluded.action_on_exceed,
                   updated_by = excluded.updated_by,
                   updated_at = CURRENT_TIMESTAMP""",
            (g.org_id, agent_id, amount, period, action, _actor()), commit=True)
        logger.info("budget_saved", org_id=g.org_id, agent_id=agent_id,
                    max_budget_usd=amount, period=period, action=action, by=_actor())
        return jsonify(_budget_dict(g.org_id, agent_id, amount, period, action))
    except Exception as exc:
        logger.error("budget_save_failed", error=str(exc))
        return _err(f"Database error: {exc}", 500)


@api_bp.route("/api/budgets/<agent_id>", methods=["DELETE"], endpoint="api_delete_budget")
def api_delete_budget(agent_id):
    if not _human_auth():
        return _err("Human session required", 401)
    try:
        ensure_settings_tables()
        _, n = _db_run("DELETE FROM agent_budgets WHERE org_id = ? AND agent_id = ?",
                       (g.org_id, agent_id), commit=True)
    except Exception as exc:
        return _err(f"Database error: {exc}", 500)
    if not n:
        return _err("Budget not found", 404)
    return jsonify({"deleted": agent_id})


# ═══════════════════════════════════════════════════════════════
# RÈGLES DE POLITIQUE
# ═══════════════════════════════════════════════════════════════

def _rule_dict(r):
    return {"id": r[0], "agent_scope": r[1], "event_type": r[2], "tool_name": r[3],
            "detection_type": r[4], "operator": r[5], "threshold": r[6],
            "action": r[7], "enabled": bool(r[8]), "created_by": r[9],
            "created_at": _iso_utc(r[10])}


_RULE_COLS = ("id, agent_scope, event_type, tool_name, detection_type, operator, "
              "threshold, action, enabled, created_by, created_at")


@api_bp.route("/api/policy-rules", methods=["GET"], endpoint="api_list_policy_rules")
def api_list_policy_rules():
    if not require_auth():
        return _err("Unauthorized", 401)
    try:
        ensure_settings_tables()
        rows, _ = _db_run(
            f"SELECT {_RULE_COLS} FROM policy_rules WHERE org_id = ? ORDER BY created_at DESC",
            (g.org_id,), fetch="all")
    except Exception as exc:
        return _err(f"Database error: {exc}", 500)
    return jsonify({"rules": [_rule_dict(r) for r in rows], "total": len(rows)})


@api_bp.route("/api/policy-rules", methods=["POST"], endpoint="api_create_policy_rule")
def api_create_policy_rule():
    if not _human_auth():
        return _err("Human session required", 401)
    b = request.get_json(silent=True) or {}
    scope = str(b.get("agent_scope") or "all").strip()
    event_type = str(b.get("event_type") or "all")
    tool_name = (str(b["tool_name"]).strip()[:128] or None) if b.get("tool_name") else None
    detection = str(b.get("detection_type") or "")
    operator = str(b.get("operator") or ">")
    threshold = str(b.get("threshold") if b.get("threshold") is not None else "")[:200]
    action = str(b.get("action") or "")

    if scope != "all" and not _valid_agent_id(scope):
        return _err("Invalid agent_scope")
    if event_type not in RULE_EVENT_TYPES:
        return _err(f"event_type must be one of {list(RULE_EVENT_TYPES)}")
    if detection not in RULE_DETECTIONS:
        return _err(f"detection_type must be one of {list(RULE_DETECTIONS)}")
    if operator not in RULE_OPERATORS:
        return _err(f"operator must be one of {list(RULE_OPERATORS)}")
    if action not in RULE_ACTIONS:
        return _err(f"action must be one of {list(RULE_ACTIONS)}")
    if operator in (">", "<"):
        try:
            if not math.isfinite(float(threshold)):
                raise ValueError
        except ValueError:
            return _err("threshold must be a number for this operator")

    rule_id = "rule_" + secrets.token_hex(6)
    try:
        ensure_settings_tables()
        count, _ = _db_run("SELECT COUNT(*) FROM policy_rules WHERE org_id = ?",
                           (g.org_id,), fetch="one")
        if count[0] >= MAX_RULES:
            return _err("Rule limit reached for this organization", 409)
        _db_run(
            """INSERT INTO policy_rules
                   (id, org_id, agent_scope, event_type, tool_name, detection_type,
                    operator, threshold, action, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (rule_id, g.org_id, scope, event_type, tool_name, detection,
             operator, threshold, action, _actor()), commit=True)
        row, _ = _db_run(f"SELECT {_RULE_COLS} FROM policy_rules WHERE id = ?",
                         (rule_id,), fetch="one")
    except Exception as exc:
        logger.error("policy_rule_create_failed", error=str(exc))
        return _err(f"Database error: {exc}", 500)
    logger.info("policy_rule_created", org_id=g.org_id, rule_id=rule_id, by=_actor())
    return jsonify(_rule_dict(row)), 201


@api_bp.route("/api/policy-rules/<rule_id>", methods=["PATCH"], endpoint="api_patch_policy_rule")
def api_patch_policy_rule(rule_id):
    if not _human_auth():
        return _err("Human session required", 401)
    b = request.get_json(silent=True) or {}
    if "enabled" not in b:
        return _err("Only 'enabled' can be updated")
    try:
        ensure_settings_tables()
        _, n = _db_run("UPDATE policy_rules SET enabled = ? WHERE id = ? AND org_id = ?",
                       (1 if b["enabled"] else 0, rule_id, g.org_id), commit=True)
    except Exception as exc:
        return _err(f"Database error: {exc}", 500)
    if not n:
        return _err("Rule not found", 404)
    return jsonify({"id": rule_id, "enabled": bool(b["enabled"])})


@api_bp.route("/api/policy-rules/<rule_id>", methods=["DELETE"], endpoint="api_delete_policy_rule")
def api_delete_policy_rule(rule_id):
    if not _human_auth():
        return _err("Human session required", 401)
    try:
        ensure_settings_tables()
        _, n = _db_run("DELETE FROM policy_rules WHERE id = ? AND org_id = ?",
                       (rule_id, g.org_id), commit=True)
    except Exception as exc:
        return _err(f"Database error: {exc}", 500)
    if not n:
        return _err("Rule not found", 404)
    return jsonify({"deleted": rule_id})


# ═══════════════════════════════════════════════════════════════
# DESTINATIONS D'ALERTES
# ═══════════════════════════════════════════════════════════════

def _dest_dict(r):
    return {"id": r[0], "type": r[1], "url": _mask_target(r[1], r[2]),
            "levels": [x for x in (r[3] or "").split(",") if x],
            "created_at": _iso_utc(r[4])}


def _parse_destination(b):
    """Renvoie (type, target, levels) ou lève ValueError."""
    dest_type = str(b.get("type") or "")
    target = str(b.get("url") or "").strip()
    if dest_type not in DEST_TYPES:
        raise ValueError(f"type must be one of {list(DEST_TYPES)}")
    if dest_type == "email":
        if not _EMAIL_RE.match(target):
            raise ValueError("Invalid email address")
    else:
        if len(target) > 2000:
            raise ValueError("URL too long")
        _check_webhook_url(target, resolve=False)
    return dest_type, target


@api_bp.route("/api/alert-destinations", methods=["GET"], endpoint="api_list_alert_destinations")
def api_list_alert_destinations():
    if not require_auth():
        return _err("Unauthorized", 401)
    try:
        ensure_settings_tables()
        rows, _ = _db_run(
            "SELECT id, type, target, levels, created_at FROM alert_destinations "
            "WHERE org_id = ? ORDER BY created_at DESC", (g.org_id,), fetch="all")
    except Exception as exc:
        return _err(f"Database error: {exc}", 500)
    return jsonify({"destinations": [_dest_dict(r) for r in rows], "total": len(rows)})


@api_bp.route("/api/alert-destinations", methods=["POST"], endpoint="api_create_alert_destination")
def api_create_alert_destination():
    if not _human_auth():
        return _err("Human session required", 401)
    b = request.get_json(silent=True) or {}
    try:
        dest_type, target = _parse_destination(b)
    except ValueError as exc:
        return _err(str(exc))
    levels = b.get("levels")
    if not isinstance(levels, list) or not levels or any(l not in DEST_LEVELS for l in levels):
        return _err(f"levels must be a non-empty subset of {list(DEST_LEVELS)}")
    levels = [l for l in DEST_LEVELS if l in levels]

    dest_id = "dest_" + secrets.token_hex(6)
    try:
        ensure_settings_tables()
        count, _ = _db_run("SELECT COUNT(*) FROM alert_destinations WHERE org_id = ?",
                           (g.org_id,), fetch="one")
        if count[0] >= MAX_DESTINATIONS:
            return _err("Destination limit reached for this organization", 409)
        _db_run(
            "INSERT INTO alert_destinations (id, org_id, type, target, levels, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (dest_id, g.org_id, dest_type, target, ",".join(levels), _actor()), commit=True)
        row, _ = _db_run("SELECT id, type, target, levels, created_at FROM alert_destinations "
                         "WHERE id = ?", (dest_id,), fetch="one")
    except Exception as exc:
        logger.error("alert_destination_create_failed", error=str(exc))
        return _err(f"Database error: {exc}", 500)
    logger.info("alert_destination_created", org_id=g.org_id, dest_id=dest_id,
                dest_type=dest_type, by=_actor())
    return jsonify(_dest_dict(row)), 201


@api_bp.route("/api/alert-destinations/<dest_id>", methods=["DELETE"],
              endpoint="api_delete_alert_destination")
def api_delete_alert_destination(dest_id):
    if not _human_auth():
        return _err("Human session required", 401)
    try:
        ensure_settings_tables()
        _, n = _db_run("DELETE FROM alert_destinations WHERE id = ? AND org_id = ?",
                       (dest_id, g.org_id), commit=True)
    except Exception as exc:
        return _err(f"Database error: {exc}", 500)
    if not n:
        return _err("Destination not found", 404)
    return jsonify({"deleted": dest_id})


@api_bp.route("/api/alert-destinations/test", methods=["POST"],
              endpoint="api_test_alert_destination")
def api_test_alert_destination():
    """Envoie vraiment un message de test (Slack / Discord / webhook générique)."""
    if not _human_auth():
        return _err("Human session required", 401)
    b = request.get_json(silent=True) or {}
    try:
        dest_type, target = _parse_destination(b)
        if dest_type == "email":
            return _err("Email test is not available yet: no email sender is configured "
                        "for alerts. Slack, Discord and webhooks can be tested.")
        _check_webhook_url(target, resolve=True)
    except ValueError as exc:
        return _err(str(exc))

    text = "Cerbere AG test alert: this destination is connected."
    payload = {"slack": {"text": text}, "discord": {"content": text}}.get(
        dest_type, {"event": "cerbere.test", "message": text})
    try:
        resp = requests.post(target, json=payload, timeout=5, allow_redirects=False)
    except requests.RequestException as exc:
        logger.warning("alert_destination_test_failed", error=type(exc).__name__)
        return jsonify({"ok": False, "error": "Could not reach the destination"}), 502
    ok = 200 <= resp.status_code < 300
    return jsonify({"ok": ok, "status": resp.status_code}), (200 if ok else 502)
