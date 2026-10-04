"""Routes /login (GET Supabase / POST magic link legacy) et /auth/verify."""

from datetime import timedelta
import secrets

import structlog
from flask import g, redirect, render_template_string, request, url_for

from collector.supabase_auth import SUPABASE_ANON_KEY, SUPABASE_ENABLED, SUPABASE_URL

from .audit_helpers import _audit_login
from .blueprint import auth_bp
from .config import MAGIC_LINK_ENABLED, MAGIC_LINK_TOKEN_BYTES, MAGIC_LINK_TTL_SECONDS
from .magic_link import (
    _build_magic_link,
    _consume_magic_link,
    _ensure_magic_link_table,
    _invalidate_existing_magic_links,
    _send_magic_link_email,
    _store_magic_link,
)
from .pages import LOGIN_HTML, SUPABASE_LOGIN_HTML
from .sessions import _set_human_session
from .users import _user_by_email
from .utils import _hash_magic_token, _normalize_email, _utcnow, _valid_email

logger = structlog.get_logger("agentguard.auth")


@auth_bp.route(
    "/login",
    methods=["GET", "POST"],
)
def login():
    if request.method == "GET":
        if SUPABASE_ENABLED:
            return render_template_string(
                SUPABASE_LOGIN_HTML,
                supabase_url=SUPABASE_URL,
                supabase_anon_key=SUPABASE_ANON_KEY,
            )

        # Secours : Supabase pas encore configuré -> ancien flow SMTP maison.
        return render_template_string(
            LOGIN_HTML,
            error=None,
            success=None,
        )

    if not MAGIC_LINK_ENABLED:
        return render_template_string(
            LOGIN_HTML,
            error="Passwordless login is currently disabled.",
            success=None,
        ), 503

    email = _normalize_email(
        request.form.get("email", "")
    )

    if not _valid_email(email):
        return render_template_string(
            LOGIN_HTML,
            error="Enter a valid work email address.",
            success=None,
        ), 400

    try:
        _ensure_magic_link_table()

        user = _user_by_email(email)

        # Do not reveal whether an email belongs to an account.
        if not user:
            logger.info(
                "magic_link_requested_unknown_email",
                email_domain=email.split("@", 1)[-1],
                ip=request.remote_addr,
            )

            return render_template_string(
                LOGIN_HTML,
                error=None,
                success=(
                    "If an account exists for this email, "
                    "a secure sign-in link has been sent."
                ),
            )

        if not bool(user[6]):
            logger.warning(
                "magic_link_requested_inactive_user",
                user_id=user[0],
                ip=request.remote_addr,
            )

            return render_template_string(
                LOGIN_HTML,
                error=None,
                success=(
                    "If an account exists for this email, "
                    "a secure sign-in link has been sent."
                ),
            )

        user_id = user[0]

        # Invalidate previous links.
        _invalidate_existing_magic_links(
            user_id
        )

        raw_token = secrets.token_urlsafe(
            MAGIC_LINK_TOKEN_BYTES
        )

        token_hash = _hash_magic_token(
            raw_token
        )

        expires_at = (
            _utcnow()
            + timedelta(
                seconds=MAGIC_LINK_TTL_SECONDS
            )
        )

        _store_magic_link(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )

        link = _build_magic_link(
            raw_token
        )

        _send_magic_link_email(
            email,
            link,
        )

        logger.info(
            "magic_link_requested",
            user_id=user_id,
            org_id=user[1],
            ip=request.remote_addr,
        )

        return render_template_string(
            LOGIN_HTML,
            error=None,
            success=(
                "Check your inbox. "
                "Your secure sign-in link expires in "
                "10 minutes."
            ),
        )

    except Exception as exc:
        logger.error(
            "magic_link_request_failed",
            error=str(exc),
        )

        return render_template_string(
            LOGIN_HTML,
            error=(
                "Unable to send the sign-in link. "
                "Please try again."
            ),
            success=None,
        ), 500


@auth_bp.get("/auth/verify")
def verify_magic_link():
    token = str(
        request.args.get(
            "token",
            "",
        )
    ).strip()

    if not token:
        return render_template_string(
            LOGIN_HTML,
            error="Invalid or expired sign-in link.",
            success=None,
        ), 400

    try:
        _ensure_magic_link_table()

        user = _consume_magic_link(
            token
        )

        if not user:
            _audit_login(
                success=False,
                reason="invalid_or_expired_magic_link",
            )

            return render_template_string(
                LOGIN_HTML,
                error=(
                    "This sign-in link is invalid, "
                    "expired, or has already been used."
                ),
                success=None,
            ), 401

        user_id = user[0]
        org_id = user[1]
        email = user[3]

        response = redirect(
            url_for("auth.dashboard")
        )

        _set_human_session(
            response,
            user_id,
        )

        g.authenticated_user = user
        g.org_id = org_id

        _audit_login(
            success=True,
            email=email,
            org_id=org_id,
        )

        logger.info(
            "magic_link_login_success",
            user_id=user_id,
            org_id=org_id,
            ip=request.remote_addr,
        )

        return response

    except Exception as exc:
        logger.error(
            "magic_link_verification_failed",
            error=str(exc),
        )

        return render_template_string(
            LOGIN_HTML,
            error="Unable to verify the sign-in link.",
            success=None,
        ), 500
