"""Registre d'agents : kill switch depuis le dashboard, statuts, test agent."""

import re
import secrets
import json

from flask import jsonify, g

from collector.auth import require_auth
from collector.api.helpers import (
    api_bp, logger, _db_run, _iso_utc, _agent_state, _audit_human_action, _human_auth,
    _request_agent_id, _agent_status, _AGENT_STATUS,
)


@api_bp.route("/api/agents", methods=["GET"], endpoint="api_list_agents")
def api_list_agents():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    org_id = getattr(g, "org_id", None) or "default"

    try:
        rows, _ = _db_run(
            """
            SELECT agent_id, name, status, sdk_version, first_seen_at, last_seen_at,
                   disconnected_at, disconnected_by
            FROM connected_agents WHERE org_id = ?
            ORDER BY last_seen_at DESC
            """, (org_id,), fetch="all")
        stat_rows, _ = _db_run(
            """
            SELECT agent_id, COUNT(*),
                   SUM(CASE WHEN blocked THEN 1 ELSE 0 END),
                   COALESCE(SUM(cost_usd), 0)
            FROM spans WHERE org_id = ? AND agent_id IS NOT NULL
            GROUP BY agent_id
            """, (org_id,), fetch="all")
        pend_rows, _ = _db_run(
            """
            SELECT agent_id, COUNT(*) FROM approval_requests
            WHERE org_id = ? AND status = 'pending' GROUP BY agent_id
            """, (org_id,), fetch="all")
    except Exception as exc:
        logger.error("agents_list_failed", error=str(exc), org_id=org_id)
        return jsonify({"error": f"Database error: {str(exc)}"}), 500

    stats = {r[0]: {"calls": int(r[1] or 0), "blocked": int(r[2] or 0), "cost_usd": float(r[3] or 0)}
             for r in stat_rows}
    pending = {r[0]: int(r[1] or 0) for r in pend_rows}

    agents, counts = [], {"connected": 0, "idle": 0, "offline": 0, "disconnected": 0}
    for r in rows:
        agent_id, name, status, sdk_version, first_seen, last_seen, disc_at, disc_by = r
        state = _agent_state(status, last_seen)
        counts[state] += 1
        st = stats.get(agent_id, {})
        agents.append({
            "agent_id": agent_id,
            "name": name or agent_id,
            "status": status,
            "state": state,
            "sdk_version": sdk_version,
            "first_seen_at": _iso_utc(first_seen),
            "last_seen_at": _iso_utc(last_seen),
            "disconnected_at": _iso_utc(disc_at),
            "disconnected_by": disc_by,
            "calls": st.get("calls", 0),
            "blocked": st.get("blocked", 0),
            "cost_usd": round(st.get("cost_usd", 0.0), 4),
            "pending_approvals": pending.get(agent_id, 0),
        })
    agents.sort(key=lambda a: a["agent_id"].lower())   # ordre stable : le bouton ne bouge pas sous la souris
    return jsonify({"agents": agents, "counts": counts, "total": len(agents)}), 200


def _set_agent_status(agent_id, new_status):
    # Décision humaine uniquement : un agent ne doit pas pouvoir se (re)connecter lui-même.
    if not _human_auth():
        return jsonify({"error": "Human session required"}), 401
    org_id = g.org_id
    actor = getattr(g, "human_email", None) or f"org:{org_id}"

    try:
        if new_status == "disconnected":
            _, n = _db_run(
                """UPDATE connected_agents
                   SET status = 'disconnected', disconnected_at = CURRENT_TIMESTAMP, disconnected_by = ?
                   WHERE org_id = ? AND agent_id = ?""",
                (actor, org_id, agent_id), commit=True)
        else:
            _, n = _db_run(
                """UPDATE connected_agents
                   SET status = 'connected', disconnected_at = NULL, disconnected_by = NULL
                   WHERE org_id = ? AND agent_id = ?""",
                (org_id, agent_id), commit=True)
    except Exception as exc:
        logger.error("agent_status_update_failed", error=str(exc), agent_id=agent_id)
        return jsonify({"error": f"Database error: {str(exc)}"}), 500

    if n == 0:
        return jsonify({"error": "Agent not found"}), 404

    _AGENT_STATUS.pop((org_id, agent_id), None)
    logger.warning("agent_status_changed", agent_id=agent_id, status=new_status, by=actor, org_id=org_id)
    _audit_human_action(
        "AGENT_DISCONNECTED" if new_status == "disconnected" else "AGENT_RECONNECTED",
        f"agent:{agent_id}", new_status, {"agent_id": agent_id, "by": actor})
    return jsonify({"agent_id": agent_id, "status": new_status}), 200


@api_bp.route("/api/agents/<agent_id>/disconnect", methods=["POST"], endpoint="api_agent_disconnect")
def api_agent_disconnect(agent_id):
    return _set_agent_status(agent_id, "disconnected")


@api_bp.route("/api/agents/<agent_id>/reconnect", methods=["POST"], endpoint="api_agent_reconnect")
def api_agent_reconnect(agent_id):
    return _set_agent_status(agent_id, "connected")


# ── Boutons "test" du dashboard : vérifier la chaîne complète sans écrire une ligne de code ──
TEST_AGENT_ID = "cerbere-test-agent"


def _ensure_test_agent(org_id):
    _db_run(
        """INSERT INTO connected_agents (org_id, agent_id, name, status, sdk_version)
           VALUES (?, ?, ?, 'connected', ?)
           ON CONFLICT (org_id, agent_id) DO UPDATE SET last_seen_at = CURRENT_TIMESTAMP""",
        (org_id, TEST_AGENT_ID, "Cerbere test agent", "test"), commit=True)


@api_bp.route("/api/agents/test", methods=["POST"], endpoint="api_test_agent")
def api_test_agent():
    if not _human_auth():
        return jsonify({"error": "Human session required"}), 401
    try:
        _ensure_test_agent(g.org_id)
    except Exception as exc:
        return jsonify({"error": f"Database error: {str(exc)}"}), 500
    return jsonify({"agent_id": TEST_AGENT_ID, "status": "connected"}), 201


@api_bp.route("/api/approvals/test", methods=["POST"], endpoint="api_test_approval")
def api_test_approval():
    """Crée une demande d'approbation factice, pour voir la file et la décision de bout en bout."""
    if not _human_auth():
        return jsonify({"error": "Human session required"}), 401
    approval_id = "test_" + secrets.token_hex(4)
    try:
        _ensure_test_agent(g.org_id)
        _db_run(
            """INSERT INTO approval_requests (id, org_id, agent_id, tool_name, params, reason, status)
               VALUES (?, ?, ?, ?, ?, ?, 'pending')""",
            (approval_id, g.org_id, TEST_AGENT_ID, "send_email",
             json.dumps({"to": "partner@gmail.com", "subject": "Q3 customer export",
                         "attachments": ["customers_q3.csv"]}),
             "Test request from the dashboard: external recipient on a personal domain"),
            commit=True)
    except Exception as exc:
        return jsonify({"error": f"Database error: {str(exc)}"}), 500
    return jsonify({"id": approval_id, "status": "pending"}), 201


@api_bp.route("/api/agent/status", methods=["GET"], endpoint="api_agent_status")
def api_agent_status():
    """Appelé par le SDK (clé API) pour savoir s'il a été déconnecté depuis le dashboard."""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    agent_id = _request_agent_id()
    if not agent_id:
        return jsonify({"agent_id": None, "status": "connected"}), 200
    status = _agent_status(g.org_id, agent_id)
    return jsonify({
        "agent_id": agent_id,
        "status": "disconnected" if status == "disconnected" else "connected",
    }), 200
