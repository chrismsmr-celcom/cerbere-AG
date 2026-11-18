"""Routes SSO OIDC : /auth/sso/login et /auth/sso/callback.

Cerbere Enterprise Edition : sous licence ee/LICENSE.md (et non Apache-2.0).
"""

import os

import structlog
from flask import current_app, redirect, render_template_string, request, url_for

from collector.auth.audit_helpers import _audit_login
from collector.auth.blueprint import auth_bp
from collector.auth.pages import LOGIN_HTML
from collector.auth.sessions import _set_human_session
from collector.extensions import limiter
from ee.sso.oidc import (
    OidcError,
    authorization_url,
    blocked_by_license,
    discover,
    exchange_code,
    get_config,
    new_login_state,
    resolve_user,
    verify_id_token,
)

logger = structlog.get_logger("agentguard.auth.sso")

_COOKIE = "ag_oidc"
_COOKIE_PATH = "/auth/sso"
_STATE_TTL = 600


def _sso_unavailable():
    if blocked_by_license():
        return render_template_string(
            LOGIN_HTML,
            error="Company SSO is part of the Team and Enterprise plans. Ask your administrator to install a license.",
            success=None,
        ), 403
    return render_template_string(
        LOGIN_HTML, error="SSO is not configured on this instance.", success=None
    ), 404


def _redirect_uri() -> str:
    base = (os.environ.get("AGENTGUARD_PUBLIC_URL") or request.url_root).rstrip("/")
    return base + "/auth/sso/callback"


def _fail(message: str, status: int, reason: str, email: str | None = None):
    _audit_login(success=False, email=email, reason=reason, method="sso")
    response = current_app.make_response(
        (render_template_string(LOGIN_HTML, error=message, success=None), status)
    )
    response.delete_cookie(_COOKIE, path=_COOKIE_PATH)
    return response


@auth_bp.get("/auth/sso/login")
@limiter.limit("30 per minute")
def sso_login():
    cfg = get_config()
    if not cfg:
        return _sso_unavailable()

    try:
        meta = discover(cfg)
    except Exception as exc:
        logger.error("sso_discovery_failed", error=str(exc))
        return render_template_string(
            LOGIN_HTML,
            error="Unable to reach the identity provider. Please try again.",
            success=None,
        ), 502

    st = new_login_state()
    response = redirect(authorization_url(cfg, meta, _redirect_uri(), st))
    token = current_app.auth_serializer.dumps(
        {
            "type": "oidc",
            "state": st["state"],
            "nonce": st["nonce"],
            "verifier": st["verifier"],
        }
    )
    response.set_cookie(
        _COOKIE,
        token,
        max_age=_STATE_TTL,
        httponly=True,
        secure=bool(getattr(current_app, "auth_cookie_secure", True)),
        samesite="Lax",
        path=_COOKIE_PATH,
    )
    return response


@auth_bp.get("/auth/sso/callback")
@limiter.limit("30 per minute")
def sso_callback():
    cfg = get_config()
    if not cfg:
        return _sso_unavailable()

    if request.args.get("error"):
        logger.warning(
            "sso_provider_error",
            error=request.args.get("error"),
            description=request.args.get("error_description", "")[:200],
        )
        return _fail(
            "Sign-in was cancelled or refused by the identity provider.",
            401,
            "idp_error",
        )

    try:
        saved = current_app.auth_serializer.loads(
            request.cookies.get(_COOKIE, ""), max_age=_STATE_TTL
        )
    except Exception:
        saved = None
    if not saved or saved.get("type") != "oidc":
        return _fail(
            "Your sign-in session expired. Please try again.", 400, "missing_state"
        )

    import secrets

    if not secrets.compare_digest(
        str(saved.get("state", "")), request.args.get("state", "")
    ):
        return _fail(
            "Your sign-in session expired. Please try again.", 400, "state_mismatch"
        )

    code = request.args.get("code", "")
    if not code:
        return _fail("Sign-in failed. Please try again.", 400, "missing_code")

    email = None
    try:
        meta = discover(cfg)
        tokens = exchange_code(cfg, meta, _redirect_uri(), code, saved["verifier"])
        claims = verify_id_token(cfg, meta, tokens["id_token"], saved["nonce"])
        email = claims.get("email")
        user = resolve_user(cfg, claims)
    except OidcError as exc:
        logger.warning("sso_login_rejected", reason=str(exc), ip=request.remote_addr)
        return _fail(
            "Sign-in was refused. Contact your administrator if you should have access.",
            401,
            "rejected",
            email=email,
        )
    except Exception as exc:
        logger.error("sso_login_failed", error=str(exc))
        return _fail(
            "Unable to complete sign-in. Please try again.", 502, "error", email=email
        )

    user_id, org_id = user[0], user[1]
    response = redirect(url_for("auth.dashboard"))
    _set_human_session(response, user_id)
    response.delete_cookie(_COOKIE, path=_COOKIE_PATH)

    _audit_login(success=True, email=user[3], org_id=org_id, method="sso")
    logger.info(
        "sso_login_success", user_id=user_id, org_id=org_id, ip=request.remote_addr
    )
    return response
