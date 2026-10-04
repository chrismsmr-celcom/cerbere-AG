"""Magic link : stockage, consommation atomique et envoi d'email (flow SMTP historique)."""

import smtplib
import sqlite3
from datetime import datetime
from email.message import EmailMessage

import structlog
from flask import current_app

from collector.db import _get_db_path, get_pg_conn, is_postgres, sql_placeholder

from .config import (
    APP_BASE_URL,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_USE_TLS,
)
from .utils import _hash_magic_token, _parse_datetime, _utc_iso, _utcnow, safe_compare

logger = structlog.get_logger("agentguard.auth")


def _ensure_magic_link_table():
    """
    Defensive migration.

    collector/db.py should create this table during normal startup.
    This fallback prevents authentication from breaking if an older
    database was created before the migration.
    """

    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS magic_link_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    expires_at TIMESTAMPTZ NOT NULL,
                    used_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_magic_link_tokens_user
                ON magic_link_tokens(user_id)
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_magic_link_tokens_expires
                ON magic_link_tokens(expires_at)
                """
            )

            conn.commit()
        finally:
            conn.close()

        return

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS magic_link_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_magic_link_tokens_user
            ON magic_link_tokens(user_id)
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_magic_link_tokens_expires
            ON magic_link_tokens(expires_at)
            """
        )

        conn.commit()
    finally:
        conn.close()


def _invalidate_existing_magic_links(user_id: str):
    p = sql_placeholder()

    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                f"""
                UPDATE magic_link_tokens
                SET used_at = CURRENT_TIMESTAMP
                WHERE user_id = {p}
                  AND used_at IS NULL
                """,
                (user_id,),
            )
            conn.commit()
        finally:
            conn.close()

        return

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE magic_link_tokens
            SET used_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
              AND used_at IS NULL
            """,
            (user_id,),
        )
        conn.commit()
    finally:
        conn.close()


def _store_magic_link(
    user_id: str,
    token_hash: str,
    expires_at: datetime,
):
    p = sql_placeholder()

    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()

            cur.execute(
                f"""
                INSERT INTO magic_link_tokens
                    (token_hash, user_id, expires_at)
                VALUES
                    ({p}, {p}, {p})
                """,
                (
                    token_hash,
                    user_id,
                    expires_at,
                ),
            )

            conn.commit()
        finally:
            conn.close()

        return

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO magic_link_tokens
                (token_hash, user_id, expires_at)
            VALUES
                (?, ?, ?)
            """,
            (
                token_hash,
                user_id,
                _utc_iso(expires_at),
            ),
        )

        conn.commit()
    finally:
        conn.close()


def _consume_magic_link(token: str):
    """
    Atomically validates and consumes a magic link.

    Returns the user row or None.
    """
    if not token:
        return None

    token_hash = _hash_magic_token(token)
    now = _utcnow()
    p = sql_placeholder()

    if is_postgres():
        conn = get_pg_conn()

        try:
            cur = conn.cursor()

            cur.execute(
                f"""
                SELECT
                    token_hash,
                    user_id,
                    expires_at,
                    used_at
                FROM magic_link_tokens
                WHERE token_hash = {p}
                FOR UPDATE
                """,
                (token_hash,),
            )

            row = cur.fetchone()

            if not row:
                conn.rollback()
                return None

            stored_hash = row[0]
            user_id = row[1]
            expires_at = _parse_datetime(row[2])
            used_at = row[3]

            if not safe_compare(stored_hash, token_hash):
                conn.rollback()
                return None

            if used_at is not None:
                conn.rollback()
                return None

            if expires_at is None or expires_at <= now:
                conn.rollback()
                return None

            cur.execute(
                f"""
                UPDATE magic_link_tokens
                SET used_at = CURRENT_TIMESTAMP
                WHERE token_hash = {p}
                  AND used_at IS NULL
                """,
                (token_hash,),
            )

            if cur.rowcount != 1:
                conn.rollback()
                return None

            cur.execute(
                f"""
                SELECT
                    user_id,
                    org_id,
                    tenant_id,
                    email,
                    display_name,
                    role,
                    active
                FROM users
                WHERE user_id = {p}
                LIMIT 1
                """,
                (user_id,),
            )

            user = cur.fetchone()

            if not user or not bool(user[6]):
                conn.rollback()
                return None

            conn.commit()
            return user

        finally:
            conn.close()

    conn = sqlite3.connect(
        _get_db_path(),
        timeout=10,
    )

    try:
        conn.execute("BEGIN IMMEDIATE")

        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                token_hash,
                user_id,
                expires_at,
                used_at
            FROM magic_link_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        )

        row = cur.fetchone()

        if not row:
            conn.rollback()
            return None

        stored_hash = row[0]
        user_id = row[1]
        expires_at = _parse_datetime(row[2])
        used_at = row[3]

        if not safe_compare(stored_hash, token_hash):
            conn.rollback()
            return None

        if used_at is not None:
            conn.rollback()
            return None

        if expires_at is None or expires_at <= now:
            conn.rollback()
            return None

        cur.execute(
            """
            UPDATE magic_link_tokens
            SET used_at = ?
            WHERE token_hash = ?
              AND used_at IS NULL
            """,
            (
                _utc_iso(now),
                token_hash,
            ),
        )

        if cur.rowcount != 1:
            conn.rollback()
            return None

        cur.execute(
            """
            SELECT
                user_id,
                org_id,
                tenant_id,
                email,
                display_name,
                role,
                active
            FROM users
            WHERE user_id = ?
            LIMIT 1
            """,
            (user_id,),
        )

        user = cur.fetchone()

        if not user or not bool(user[6]):
            conn.rollback()
            return None

        conn.commit()
        return user

    finally:
        conn.close()


def _build_magic_link(token: str) -> str:
    return (
        f"{APP_BASE_URL}/auth/verify"
        f"?token={token}"
    )


def _send_magic_link_email(email: str, link: str):
    subject = "Sign in to Cerbere"

    text = f"""Sign in to Cerbere

Use the secure link below to access your security console:

{link}

This link expires in 10 minutes and can only be used once.

If you did not request this email, you can safely ignore it.
"""

    html = f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Sign in to Cerbere</title>
</head>
<body style="
    margin:0;
    padding:40px 20px;
    background:#07111f;
    color:#eef5ff;
    font-family:Arial,Helvetica,sans-serif;
">
<div style="
    max-width:520px;
    margin:0 auto;
    background:#0d1b2d;
    border:1px solid #21334a;
    border-radius:18px;
    padding:32px;
">
    <div style="
        font-size:14px;
        color:#38bdf8;
        font-weight:700;
        letter-spacing:.08em;
        text-transform:uppercase;
    ">
        Cerbere
    </div>

    <h1 style="
        margin:16px 0 10px;
        color:#ffffff;
        font-size:26px;
    ">
        Sign in to your security console
    </h1>

    <p style="
        color:#a8bad0;
        line-height:1.6;
    ">
        Use the secure link below to continue.
    </p>

    <p style="margin:28px 0;">
        <a href="{link}" style="
            display:inline-block;
            padding:14px 22px;
            border-radius:10px;
            background:#2563eb;
            color:#ffffff;
            text-decoration:none;
            font-weight:700;
        ">
            Sign in to Cerbere
        </a>
    </p>

    <p style="
        color:#71859d;
        font-size:13px;
        line-height:1.6;
    ">
        This link expires in 10 minutes and can only be used once.
    </p>

    <p style="
        color:#71859d;
        font-size:12px;
        line-height:1.6;
    ">
        If you did not request this email, you can safely ignore it.
    </p>
</div>
</body>
</html>
"""

    if not SMTP_HOST:
        environment = current_app.config.get(
            "ENVIRONMENT",
            "development",
        )

        if environment == "production":
            raise RuntimeError(
                "SMTP_HOST must be configured in production "
                "to send magic-link emails."
            )

        logger.warning(
            "magic_link_email_not_sent_smtp_not_configured",
            email=email,
            magic_link=link,
        )
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = SMTP_FROM
    message["To"] = email

    message.set_content(text)
    message.add_alternative(
        html,
        subtype="html",
    )

    with smtplib.SMTP(
        SMTP_HOST,
        SMTP_PORT,
        timeout=15,
    ) as smtp:
        if SMTP_USE_TLS:
            smtp.starttls()

        if SMTP_USERNAME:
            smtp.login(
                SMTP_USERNAME,
                SMTP_PASSWORD,
            )

        smtp.send_message(message)

    logger.info(
        "magic_link_email_sent",
        email_domain=email.split("@", 1)[-1],
    )

    return True
