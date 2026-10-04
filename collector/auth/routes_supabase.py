"""Routes Supabase Auth : config publique + échange de token contre cookie de session."""

import structlog
from flask import jsonify, request

from collector.supabase_auth import (
    SUPABASE_ANON_KEY,
    SUPABASE_ENABLED,
    SUPABASE_URL,
    SupabaseAuthError,
    get_or_provision_user,
    verify_supabase_jwt,
)

from .audit_helpers import _audit_login
from .blueprint import auth_bp
from .sessions import _set_human_session

logger = structlog.get_logger("agentguard.auth")


@auth_bp.get("/api/auth/config")
def supabase_public_config():
    """Expose la config publique (URL + anon key) au front — jamais le JWT secret."""
    return jsonify({
        "supabase_enabled": SUPABASE_ENABLED,
        "supabase_url": SUPABASE_URL,
        "supabase_anon_key": SUPABASE_ANON_KEY,
    })


@auth_bp.post("/api/auth/supabase-session")
def supabase_session():
    """
    Échange un access_token Supabase (vérifié côté serveur) contre le
    cookie de session httpOnly existant. Provisionne tenant/org/user
    au premier login. Endpoint public (avant login, forcément).
    """
    if not SUPABASE_ENABLED:
        return jsonify({"error": "Supabase auth not configured"}), 503

    data = request.get_json(silent=True) or {}
    token = str(data.get("access_token", "")).strip()

    if not token:
        return jsonify({"error": "access_token required"}), 400

    try:
        payload = verify_supabase_jwt(token)
        user = get_or_provision_user(payload)
    except SupabaseAuthError as exc:
        logger.warning("supabase_session_rejected", error=str(exc))
        return jsonify({"error": "Invalid or expired session"}), 401
    except Exception as exc:
        logger.error("supabase_session_failed", error=str(exc))
        return jsonify({"error": "Unable to establish session"}), 500

    user_id, org_id, _, email, _, _, active = user

    if not active:
        return jsonify({"error": "Account disabled"}), 403

    response = jsonify({"status": "ok"})
    _set_human_session(response, user_id)

    _audit_login(success=True, email=email, org_id=org_id)

    logger.info("supabase_login_success", user_id=user_id, org_id=org_id)

    return response
