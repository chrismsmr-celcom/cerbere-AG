"""Middleware d'authentification : require_auth, require_human_auth, hook before_app_request.

NB : les appels à resolve_org_id / _resolve_human_session passent par le package
`collector.auth` (via _auth_pkg) afin que monkeypatch.setattr(collector.auth, ...)
continue de fonctionner dans les tests.
"""

import structlog
from flask import current_app, g, jsonify, redirect, request, url_for

from .blueprint import auth_bp
from .config import MAGIC_LINK_COOKIE, PROTECTED_ENDPOINTS
from .identity_resolution import resolve_full_identity
from .sessions import _session_org_id
from .utils import safe_compare

logger = structlog.get_logger("agentguard.auth")


def _auth_pkg():
    from collector import auth as _pkg

    return _pkg


def require_auth():
    """
    Authenticate:
      1. Agent/platform API key
      2. Human magic-link session
      3. Legacy API-key session

    Human sessions populate:
      g.org_id
      g.authenticated_user
      g.user_identity
      g.identity
    """
    api_key = current_app.config.get("API_KEY")

    # ── API KEY ─────────────────────────────────────────────

    key = request.headers.get(
        "X-API-Key",
        "",
    ).strip()

    if key:
        # Explicitly reject global legacy key in production
        if (
            api_key
            and safe_compare(key, api_key)
        ):
            environment = current_app.config.get(
                "ENVIRONMENT",
                "development",
            )

            allow_legacy = current_app.config.get(
                "ALLOW_LEGACY_SYSTEM_KEY",
                False,
            )

            if (
                environment == "production"
                and not allow_legacy
            ):
                logger.warning(
                    "legacy_system_key_rejected_in_production",
                    ip=request.remote_addr,
                    endpoint=request.endpoint,
                )
                return False

        org_id = _auth_pkg().resolve_org_id(key)

        if org_id:
            g.org_id = org_id

            try:
                resolve_full_identity()
            except Exception as exc:
                logger.debug(
                    "identity_resolution_failed",
                    error=str(exc),
                )

            return True

    # ── HUMAN SESSION ───────────────────────────────────────

    auth_cookie = current_app.config.get(
        "AUTH_COOKIE",
        MAGIC_LINK_COOKIE,
    )

    cookie_value = request.cookies.get(
        auth_cookie,
        "",
    )

    user = _auth_pkg()._resolve_human_session(
        cookie_value
    )

    if user:
        g.authenticated_user = user
        g.org_id = user[1]

        try:
            resolve_full_identity()
        except Exception as exc:
            logger.debug(
                "human_identity_resolution_failed",
                error=str(exc),
            )

        return True

    # ── LEGACY API KEY SESSION ──────────────────────────────

    org_id = _session_org_id(
        cookie_value
    )

    if org_id:
        g.org_id = org_id

        try:
            resolve_full_identity()
        except Exception as exc:
            logger.debug(
                "legacy_identity_resolution_failed",
                error=str(exc),
            )

        return True

    return False


def require_human_auth():
    """
    Session HUMAINE uniquement (cookie du dashboard) - les clés API sont refusées.

    À utiliser pour toute décision qu'un agent ne doit JAMAIS pouvoir prendre
    lui-même : approuver/rejeter une action, déconnecter un agent. Avec
    require_auth(), un agent détenant sa clé API pouvait appeler
    POST /api/approvals/<id>/approve et s'auto-approuver.
    """
    auth_cookie = current_app.config.get("AUTH_COOKIE", MAGIC_LINK_COOKIE)
    cookie_value = request.cookies.get(auth_cookie, "")

    user = _auth_pkg()._resolve_human_session(cookie_value)
    if user:
        g.authenticated_user = user
        g.org_id = user[1]
        g.human_email = user[3]
        try:
            resolve_full_identity()
        except Exception as exc:
            logger.debug("human_identity_resolution_failed", error=str(exc))
        return True

    org_id = _session_org_id(cookie_value)
    if org_id:
        g.org_id = org_id
        g.human_email = None
        try:
            resolve_full_identity()
        except Exception as exc:
            logger.debug("legacy_identity_resolution_failed", error=str(exc))
        return True

    return False


@auth_bp.before_app_request
def check_auth():
    if request.method == "OPTIONS":
        return None

    public_endpoints = {
        "auth.login",
        "auth.signup",
        "auth.healthz",
        "auth.auth_login",
        "auth.verify_magic_link",
        "auth.logout",
    }

    if request.endpoint in public_endpoints:
        return None

    if request.endpoint not in PROTECTED_ENDPOINTS:
        return None

    try:
        if not require_auth():
            if request.endpoint in {
                "auth.dashboard",
                "trace.trace_detail",
            }:
                return redirect(
                    url_for("auth.login")
                )

            return jsonify(
                {
                    "error": "Unauthorized"
                }
            ), 401

    except Exception as exc:
        logger.error(
            "auth_middleware_error",
            error=str(exc),
        )

        return jsonify(
            {
                "error": "Unauthorized"
            }
        ), 401
