"""CRUD alert rules."""

from flask import jsonify, g, request

from collector.auth import require_auth
from collector.alerts import (
    create_alert_rule,
    list_alert_rules,
    delete_alert_rule,
    VALID_METRICS,
    VALID_COMPARISONS,
)
from collector.api.helpers import api_bp, logger


@api_bp.route("/api/alert-rules", methods=["GET"])
def api_list_alert_rules():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)
    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    try:
        rules = list_alert_rules(org_id=org_id)
        return jsonify({"alert_rules": rules, "count": len(rules)}), 200
    except Exception as e:
        logger.error("alert_rules_list_failed", error=str(e), org_id=org_id)
        return jsonify({"error": "Failed to list alert rules"}), 500


@api_bp.route("/api/alert-rules", methods=["POST"])
def api_create_alert_rule():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)
    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    data = request.get_json(silent=True) or {}
    metric = data.get("metric")
    comparison = data.get("comparison", "above")
    threshold = data.get("threshold")
    label = data.get("label")

    if metric not in VALID_METRICS:
        return jsonify({"error": f"metric must be one of {sorted(VALID_METRICS)}"}), 400
    if comparison not in VALID_COMPARISONS:
        return jsonify({"error": f"comparison must be one of {sorted(VALID_COMPARISONS)}"}), 400
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        return jsonify({"error": "threshold must be a number"}), 400

    try:
        rule = create_alert_rule(
            org_id=org_id,
            metric=metric,
            comparison=comparison,
            threshold=threshold,
            label=label,
            created_by=getattr(g, "authenticated_user", None),
        )
        return jsonify({"alert_rule": rule}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("alert_rule_create_failed", error=str(e), org_id=org_id)
        return jsonify({"error": "Failed to create alert rule"}), 500


@api_bp.route("/api/alert-rules/<alert_id>", methods=["DELETE"])
def api_delete_alert_rule(alert_id):
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    org_id = getattr(g, "org_id", None)
    if not org_id:
        return jsonify({"error": "Organization context required"}), 400

    try:
        deleted = delete_alert_rule(alert_id, org_id=org_id)
        if not deleted:
            return jsonify({"error": "Alert rule not found"}), 404
        return jsonify({"status": "deleted", "alert_id": alert_id}), 200
    except Exception as e:
        logger.error("alert_rule_delete_failed", error=str(e), org_id=org_id)
        return jsonify({"error": "Failed to delete alert rule"}), 500