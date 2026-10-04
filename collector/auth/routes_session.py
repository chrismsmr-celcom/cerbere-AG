"""Routes de session : /api/auth-login, /api/auth/me, /logout, /healthz, dashboard (/)."""

import secrets
from datetime import timedelta

import structlog
from flask import current_app, g, jsonify, redirect, render_template_string, request, url_for

from collector.db import is_postgres

from .blueprint import auth_bp
from .config import (
    MAGIC_LINK_COOKIE,
    MAGIC_LINK_ENABLED,
    MAGIC_LINK_TOKEN_BYTES,
    MAGIC_LINK_TTL_SECONDS,
)
from .identity_resolution import resolve_full_identity
from .magic_link import (
    _build_magic_link,
    _ensure_magic_link_table,
    _invalidate_existing_magic_links,
    _send_magic_link_email,
    _store_magic_link,
)
from .middleware import _auth_pkg, require_auth
from .sessions import _clear_human_session, _session_token
from .users import _user_by_email
from .utils import _hash_magic_token, _normalize_email, _utcnow, _valid_email, hash_key

logger = structlog.get_logger("agentguard.auth")


@auth_bp.post("/api/auth-login")
def auth_login():
    """
    JSON authentication endpoint.

    Preferred:
        {"email": "user@company.com"}

    Legacy compatibility:
        {"api_key": "..."}
    """
    data = request.get_json(
        silent=True
    ) or {}

    email = _normalize_email(
        data.get("email", "")
    )

    # ── Magic link ──────────────────────────────────────────

    if email:
        if not MAGIC_LINK_ENABLED:
            return jsonify(
                {
                    "error":
                    "Magic-link authentication disabled"
                }
            ), 503

        if not _valid_email(email):
            return jsonify(
                {
                    "error":
                    "Invalid email address"
                }
            ), 400

        try:
            _ensure_magic_link_table()

            user = _user_by_email(email)

            if user and bool(user[6]):
                user_id = user[0]

                _invalidate_existing_magic_links(
                    user_id
                )

                raw_token = secrets.token_urlsafe(
                    MAGIC_LINK_TOKEN_BYTES
                )

                _store_magic_link(
                    user_id=user_id,
                    token_hash=_hash_magic_token(
                        raw_token
                    ),
                    expires_at=(
                        _utcnow()
                        + timedelta(
                            seconds=MAGIC_LINK_TTL_SECONDS
                        )
                    ),
                )

                link = _build_magic_link(
                    raw_token
                )

                _send_magic_link_email(
                    email,
                    link,
                )

                logger.info(
                    "magic_link_api_requested",
                    user_id=user_id,
                    org_id=user[1],
                    ip=request.remote_addr,
                )

            return jsonify(
                {
                    "status": "ok",
                    "message": (
                        "If an account exists for this "
                        "email, a secure sign-in link "
                        "has been sent."
                    ),
                }
            ), 200

        except Exception as exc:
            logger.error(
                "magic_link_api_failed",
                error=str(exc),
            )

            return jsonify(
                {
                    "error":
                    "Unable to process sign-in request"
                }
            ), 500

    # ── Legacy API key compatibility ───────────────────────

    key = str(
        data.get(
            "api_key",
            "",
        )
    ).strip()

    if not key:
        return jsonify(
            {
                "error":
                "Email is required"
            }
        ), 400

    org_id = _auth_pkg().resolve_org_id(key)

    if not org_id:
        return jsonify(
            {
                "error":
                "Unauthorized"
            }
        ), 401

    if (
        org_id == "default"
        and current_app.config.get(
            "ENVIRONMENT"
        ) == "production"
        and not current_app.config.get(
            "ALLOW_LEGACY_SYSTEM_KEY",
            False,
        )
    ):
        return jsonify(
            {
                "error":
                "Legacy system API key disabled"
            }
        ), 401

    response = jsonify(
        {
            "status": "ok",
            "org_id": org_id,
        }
    )

    cookie_name = current_app.config.get(
        "AUTH_COOKIE",
        MAGIC_LINK_COOKIE,
    )

    response.set_cookie(
        cookie_name,
        _session_token(
            org_id,
            hash_key(key),
        ),
        httponly=True,
        secure=bool(
            getattr(
                current_app,
                "auth_cookie_secure",
                True,
            )
        ),
        samesite="Lax",
        max_age=getattr(current_app, "auth_session_ttl", 3600),
        path="/",
    )

    return response


@auth_bp.get("/api/auth/me")
def auth_me():
    if not require_auth():
        return jsonify(
            {
                "authenticated": False
            }
        ), 401

    identity = resolve_full_identity()

    user = getattr(
        g,
        "authenticated_user",
        None,
    )

    if user:
        return jsonify(
            {
                "authenticated": True,
                "type": "human",
                "user": {
                    "user_id": user[0],
                    "org_id": user[1],
                    "tenant_id": user[2],
                    "email": user[3],
                    "display_name": user[4],
                    "role": user[5],
                },
            }
        ), 200

    return jsonify(
        {
            "authenticated": True,
            "type": (
                "agent"
                if getattr(
                    g,
                    "agent_identity",
                    None,
                )
                else "api_key"
            ),
            "org_id": getattr(
                g,
                "org_id",
                None,
            ),
            "identity": (
                identity.to_dict()
                if identity
                and hasattr(
                    identity,
                    "to_dict",
                )
                else None
            ),
        }
    ), 200


@auth_bp.route(
    "/logout",
    methods=["GET", "POST"],
)
def logout():
    response = redirect(
        url_for("auth.login")
    )

    _clear_human_session(
        response
    )

    logger.info(
        "logout",
        ip=request.remote_addr,
    )

    return response


@auth_bp.get("/healthz")
def healthz():
    try:
        from collector.db import get_db

        conn = get_db()

        try:
            if is_postgres():
                cur = conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            else:
                conn.execute("SELECT 1")
        finally:
            conn.close()

        return jsonify(
            {
                "status": "ok"
            }
        ), 200

    except Exception as exc:
        return jsonify(
            {
                "status": "degraded",
                "error": str(exc)[:120],
            }
        ), 503


@auth_bp.route("/")
def dashboard():
    from collector.dashboard import DASHBOARD_HTML
    from flask import make_response

    return make_response(
        render_template_string(
            DASHBOARD_HTML
        )
    )
