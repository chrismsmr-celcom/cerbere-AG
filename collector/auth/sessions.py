"""Sessions : cookie humain signé et session historique par clé API."""

import secrets
import sqlite3

from flask import current_app

from collector.db import _get_db_path, get_pg_conn, is_postgres, sql_placeholder

from .config import HUMAN_SESSION_TTL_SECONDS, MAGIC_LINK_COOKIE
from .users import _user_by_id
from .utils import hash_key, safe_compare


def _human_session_token(user_id: str) -> str:
    """
    Signed server-generated session.

    The signing serializer is configured by collector/app.py.
    """
    payload = {
        "type": "human",
        "user_id": user_id,
        "nonce": secrets.token_urlsafe(16),
    }

    return current_app.auth_serializer.dumps(payload)


def _resolve_human_session(token: str):
    if not token:
        return None

    try:
        payload = current_app.auth_serializer.loads(
            token,
            max_age=HUMAN_SESSION_TTL_SECONDS,
        )
    except Exception:
        return None

    if payload.get("type") != "human":
        return None

    user_id = payload.get("user_id")

    if not user_id:
        return None

    user = _user_by_id(user_id)

    if not user:
        return None

    if not bool(user[6]):
        return None

    return user


def _set_human_session(response, user_id: str):
    cookie_name = current_app.config.get(
        "AUTH_COOKIE",
        MAGIC_LINK_COOKIE,
    )

    token = _human_session_token(user_id)

    response.set_cookie(
        cookie_name,
        token,
        httponly=True,
        secure=bool(
            getattr(
                current_app,
                "auth_cookie_secure",
                True,
            )
        ),
        samesite="Lax",
        max_age=HUMAN_SESSION_TTL_SECONDS,
        path="/",
    )

    return response


def _clear_human_session(response):
    cookie_name = current_app.config.get(
        "AUTH_COOKIE",
        MAGIC_LINK_COOKIE,
    )

    response.delete_cookie(
        cookie_name,
        path="/",
    )

    return response


def _session_token(org_id: str, key_hash: str) -> str:
    return current_app.auth_serializer.dumps(
        {
            "type": "api_key",
            "org_id": org_id,
            "key_hash": key_hash,
        }
    )


def _session_org_id(token: str):
    if not token:
        return None

    try:
        # ✅ FIX: use current_app.auth_session_ttl
        ttl = getattr(current_app, "auth_session_ttl", 3600)
        payload = current_app.auth_serializer.loads(token, max_age=ttl)
    except Exception:
        return None

    if payload.get("type") not in {
        None,
        "api_key",
    }:
        return None

    org_id = payload.get("org_id")
    key_hash = payload.get("key_hash")

    if not org_id or not key_hash:
        return None

    if org_id == "default":
        api_key = current_app.config.get("API_KEY")

        if api_key and safe_compare(
            key_hash,
            hash_key(api_key),
        ):
            return "default"

        return None

    p = sql_placeholder()

    if is_postgres():
        conn = get_pg_conn()

        try:
            cur = conn.cursor()
            cur.execute(
                f"""
                SELECT 1
                FROM api_keys
                WHERE org_id = {p}
                  AND key_hash = {p}
                  AND active = TRUE
                LIMIT 1
                """,
                (
                    org_id,
                    key_hash,
                ),
            )

            return (
                org_id
                if cur.fetchone()
                else None
            )
        finally:
            conn.close()

    conn = sqlite3.connect(_get_db_path())

    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT 1
            FROM api_keys
            WHERE org_id = ?
              AND key_hash = ?
              AND active = 1
            LIMIT 1
            """,
            (
                org_id,
                key_hash,
            ),
        )

        return (
            org_id
            if cur.fetchone()
            else None
        )
    finally:
        conn.close()
