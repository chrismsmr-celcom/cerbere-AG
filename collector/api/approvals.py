"""HITL — file d'attente d'approbations."""

import json

from flask import g, jsonify, request

from agentguard.signing import params_digest
from collector.api.helpers import (
    _as_json,
    _audit_human_action,
    _db_run,
    _human_decider_or_error,
    _iso_utc,
    _reject_if_agent_disconnected,
    _request_agent_id,
    api_bp,
    logger,
)
from collector.auth import require_auth

_APPROVAL_STATUSES = {"pending", "approved", "rejected"}


@api_bp.route("/api/approvals", methods=["GET"], endpoint="api_list_approvals")
def api_list_approvals():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None) or "default"
    status = request.args.get("status", "pending")
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except (TypeError, ValueError):
        limit = 50

    where, params = "org_id = ?", [org_id]
    if status in _APPROVAL_STATUSES:
        where += " AND status = ?"
        params.append(status)
    elif status == "history":
        where += " AND status <> 'pending'"
    elif status != "all":
        return jsonify(
            {"error": "status must be pending, approved, rejected, history or all"}
        ), 400
    order = (
        "created_at ASC"
        if status == "pending"
        else "COALESCE(resolved_at, created_at) DESC"
    )

    try:
        rows, _ = _db_run(
            f"""SELECT id, agent_id, tool_name, params, reason, created_at, status, resolved_at, resolved_by
                FROM approval_requests WHERE {where} ORDER BY {order} LIMIT ?""",
            (*params, limit),
            fetch="all",
        )
        count_rows, _ = _db_run(
            "SELECT status, COUNT(*) FROM approval_requests WHERE org_id = ? GROUP BY status",
            (org_id,),
            fetch="all",
        )
    except Exception as e:
        logger.error("approval_list_failed", error=str(e), org_id=org_id)
        return jsonify({"error": f"Database error: {e!s}"}), 500

    approvals = [
        {
            "id": r[0],
            "agent_id": r[1],
            "tool_name": r[2],
            "params": _as_json(r[3], {}),
            "reason": r[4],
            "created_at": _iso_utc(r[5]),
            "status": r[6],
            "resolved_at": _iso_utc(r[7]),
            "resolved_by": r[8],
        }
        for r in rows
    ]
    counts = {"pending": 0, "approved": 0, "rejected": 0}
    for st, n in count_rows:
        if st in counts:
            counts[st] = int(n)
    return jsonify(
        {"approvals": approvals, "count": len(approvals), "counts": counts}
    ), 200


def _resolve_approval(approval_id, new_status):
    # Un agent (clé API) ne doit JAMAIS pouvoir valider sa propre demande.
    refused = _human_decider_or_error()
    if refused:
        return refused

    org_id = g.org_id
    decided_by = getattr(g, "human_email", None) or f"org:{org_id}"
    try:
        row, _ = _db_run(
            "SELECT agent_id, tool_name FROM approval_requests WHERE id = ? AND org_id = ?",
            (approval_id, org_id),
            fetch="one",
        )
        _, n = _db_run(
            """UPDATE approval_requests
               SET status = ?, resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
               WHERE id = ? AND org_id = ? AND status = 'pending'""",
            (new_status, decided_by, approval_id, org_id),
            commit=True,
        )
    except Exception as e:
        logger.error(
            "approval_resolve_failed",
            error=str(e),
            approval_id=approval_id,
            org_id=org_id,
        )
        return jsonify({"error": f"Database error: {e!s}"}), 500

    if n == 0:
        return jsonify({"error": "Approval not found or already resolved"}), 404

    _audit_human_action(
        "APPROVAL_GRANTED" if new_status == "approved" else "APPROVAL_REJECTED",
        f"approval:{approval_id}",
        new_status,
        {
            "approval_id": approval_id,
            "agent_id": row[0] if row else None,
            "tool_name": row[1] if row else None,
            "decided_by": decided_by,
        },
    )
    return jsonify(
        {"status": new_status, "id": approval_id, "decided_by": decided_by}
    ), 200


@api_bp.route(
    "/api/approvals/<approval_id>/approve",
    methods=["POST"],
    endpoint="api_approve_approval",
)
def api_approve_approval(approval_id):
    return _resolve_approval(approval_id, "approved")


@api_bp.route(
    "/api/approvals/<approval_id>/reject",
    methods=["POST"],
    endpoint="api_reject_approval",
)
def api_reject_approval(approval_id):
    return _resolve_approval(approval_id, "rejected")


@api_bp.route(
    "/api/approvals/<approval_id>", methods=["GET"], endpoint="api_get_approval_status"
)
def api_get_approval_status(approval_id):
    """Statut d'une demande — interrogé par le SDK pour savoir quand exécuter."""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None) or "default"

    try:
        row, _ = _db_run(
            "SELECT id, status, resolved_by, resolved_at, consumed_at FROM approval_requests WHERE id = ? AND org_id = ?",
            (approval_id, org_id),
            fetch="one",
        )
    except Exception as e:
        return jsonify({"error": f"Database error: {e!s}"}), 500

    if not row:
        return jsonify({"error": "Approval not found"}), 404

    return jsonify(
        {
            "id": row[0],
            "status": row[1],
            "resolved_by": row[2],
            "resolved_at": _iso_utc(row[3]),
            # Une approbation déjà utilisée n'autorise plus rien.
            "consumed": row[4] is not None,
        }
    ), 200


@api_bp.route(
    "/api/approvals/<approval_id>/consume",
    methods=["POST"],
    endpoint="api_consume_approval",
)
def api_consume_approval(approval_id):
    """Consomme une approbation (USAGE UNIQUE, atomique).

    Réservé aux clés API (l'agent qui exécute) — un humain n'a pas à la consommer.
    Réussit uniquement si l'approbation est `approved`, jamais consommée, et si
    l'organisation, l'agent, l'outil ET les arguments correspondent exactement à
    ce qui a été approuvé. Sinon 409 : l'action doit être redemandée.
    """
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    refused = _reject_if_agent_disconnected()
    if refused:
        return refused

    org_id = getattr(g, "org_id", None) or "default"
    data = request.get_json(silent=True) or {}
    tool_name = data.get("tool_name")
    sent_digest = data.get("args_sha256")
    agent_id = _request_agent_id() or data.get("agent_id") or "unknown"

    if not tool_name or not sent_digest:
        return jsonify({"error": "tool_name and args_sha256 are required"}), 400

    try:
        row, _ = _db_run(
            "SELECT status, agent_id, tool_name, params, consumed_at FROM approval_requests WHERE id = ? AND org_id = ?",
            (approval_id, org_id),
            fetch="one",
        )
    except Exception as e:
        logger.error("approval_consume_lookup_failed", error=str(e))
        return jsonify({"error": "Database error"}), 500

    if not row:
        return jsonify({"error": "Approval not found"}), 404

    status, row_agent, row_tool, row_params, consumed_at = row
    stored_digest = params_digest(_as_json(row_params, {}))

    reason = None
    if status != "approved":
        reason = "not_approved"
    elif consumed_at is not None:
        reason = "already_consumed"
    elif str(row_agent) != str(agent_id)[:64]:
        reason = "agent_mismatch"
    elif row_tool != tool_name:
        reason = "tool_mismatch"
    elif stored_digest != sent_digest:
        reason = "arguments_mismatch"

    if reason:
        logger.warning(
            "approval_consume_refused",
            approval_id=approval_id,
            reason=reason,
            org_id=org_id,
        )
        return jsonify({"consumed": False, "error": reason}), 409

    # Atomique : une seule requête concurrente peut passer de NULL à une date.
    try:
        _, changed = _db_run(
            """UPDATE approval_requests SET consumed_at = CURRENT_TIMESTAMP
               WHERE id = ? AND org_id = ? AND status = 'approved' AND consumed_at IS NULL""",
            (approval_id, org_id),
            commit=True,
        )
    except Exception as e:
        logger.error("approval_consume_failed", error=str(e))
        return jsonify({"error": "Database error"}), 500

    if changed != 1:
        return jsonify({"consumed": False, "error": "already_consumed"}), 409

    logger.info("approval_consumed", approval_id=approval_id, org_id=org_id)
    return jsonify({"consumed": True, "id": approval_id}), 200


@api_bp.route("/api/approvals", methods=["POST"], endpoint="api_sdk_create_approval")
def hitl_sdk_create_approval():
    # Sans require_auth(), g.org_id n'est jamais posé -> toutes les demandes
    # tombaient dans l'org 'default', invisibles pour le dashboard du client.
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    refused = _reject_if_agent_disconnected()
    if refused:
        return refused

    data = request.get_json(silent=True) or {}
    approval_id = data.get("approval_id") or data.get("id")
    # Agent lié à la clé > identité déclarée > corps de requête (jamais l'inverse).
    agent_id = _request_agent_id() or data.get("agent_id") or "unknown"
    tool_name = data.get("tool_name")
    params = data.get("params", {})
    reason = data.get("reason", "Approval required by policy")

    if not approval_id:
        return jsonify({"error": "approval_id is required"}), 400

    org_id = getattr(g, "org_id", None) or "default"
    try:
        approval_id = str(approval_id)[:128]
        _, inserted = _db_run(
            """INSERT INTO approval_requests (id, org_id, agent_id, tool_name, params, reason, status)
               VALUES (?, ?, ?, ?, ?, ?, 'pending')
               ON CONFLICT (id) DO NOTHING""",
            (
                approval_id,
                org_id,
                str(agent_id)[:64],
                tool_name,
                json.dumps(params),
                reason,
            ),
            commit=True,
        )
        if inserted != 1:
            existing, _ = _db_run(
                "SELECT org_id, status, consumed_at FROM approval_requests WHERE id = ?",
                (approval_id,),
                fetch="one",
            )
            if existing and existing[0] != org_id:
                # Même identifiant dans une autre organisation : on ne ment pas
                # avec un 201 (l'ancien code répondait "succès" sans rien créer).
                logger.warning("approval_id_conflict", approval_id=approval_id)
                return jsonify({"error": "approval_id_conflict"}), 409
            if existing and existing[2] is not None:
                # L'approbation précédente a été CONSOMMÉE : cette nouvelle demande
                # identique repart de zéro et exige une nouvelle décision humaine.
                _db_run(
                    """UPDATE approval_requests
                       SET status = 'pending', consumed_at = NULL, resolved_at = NULL,
                           resolved_by = NULL, created_at = CURRENT_TIMESTAMP, reason = ?
                       WHERE id = ? AND org_id = ? AND consumed_at IS NOT NULL""",
                    (reason, approval_id, org_id),
                    commit=True,
                )
            else:
                return jsonify(
                    {"status": "success", "id": approval_id, "existing": True}
                ), 200
        logger.warning(
            "approval_request_created",
            approval_id=approval_id,
            tool=tool_name,
            org_id=org_id,
        )

        # Déclencher l'alerte Email/Webhook (brancher Resend/SendGrid/SMTP ici).
        org_email = getattr(g, "human_email", "admin@entreprise.com")
        logger.info("approval_alert_sent", to=org_email)

        return jsonify({"status": "success", "id": approval_id}), 201
    except Exception as e:
        logger.error("approval_request_failed", error=str(e))
        return jsonify({"error": str(e)}), 500
