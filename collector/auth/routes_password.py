"""Route POST /auth/password : connexion locale email + mot de passe."""

import structlog
from flask import g, redirect, render_template_string, request, url_for

from collector.extensions import limiter

from .audit_helpers import _audit_login
from .blueprint import auth_bp
from .config import PASSWORD_LOGIN_ENABLED
from .local_password import verify_credentials
from .pages import LOGIN_HTML
from .sessions import _set_human_session
from .utils import _normalize_email

logger = structlog.get_logger("agentguard.auth")

_GENERIC_ERROR = "Invalid email or password."


@auth_bp.post("/auth/password")
@limiter.limit("10 per minute")
def password_login():
    if not PASSWORD_LOGIN_ENABLED:
        return render_template_string(
            LOGIN_HTML,
            error="Password login is disabled on this instance.",
            success=None,
        ), 503

    email = _normalize_email(request.form.get("email", ""))
    password = request.form.get("password", "")

    try:
        user = verify_credentials(email, password)
    except Exception as exc:  # erreur DB : ne rien révéler au client
        logger.error("password_login_failed", error=str(exc))
        return render_template_string(
            LOGIN_HTML,
            error="Unable to sign in. Please try again.",
            success=None,
        ), 500

    if not user:
        _audit_login(
            success=False,
            email=email or None,
            reason="invalid_credentials",
            method="password",
        )
        logger.warning("password_login_rejected", ip=request.remote_addr)
        return render_template_string(
            LOGIN_HTML, error=_GENERIC_ERROR, success=None
        ), 401

    user_id, org_id = user[0], user[1]
    response = redirect(url_for("auth.dashboard"))
    _set_human_session(response, user_id)

    g.authenticated_user = user
    g.org_id = org_id

    _audit_login(success=True, email=user[3], org_id=org_id, method="password")
    logger.info(
        "password_login_success",
        user_id=user_id,
        org_id=org_id,
        ip=request.remote_addr,
    )
    return response
