"""Accès base de données aux utilisateurs humains."""

import sqlite3

from collector.db import (
    _get_db_path,
    get_pg_conn,
    get_sqlite_conn,
    is_postgres,
    sql_placeholder,
)

from .utils import _normalize_email


def _db_execute(query: str, params=(), fetchone=False, fetchall=False):
    """
    Execute a SELECT query against PostgreSQL or SQLite.

    This helper deliberately keeps connection handling local so
    authentication does not leak database connections.
    """
    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
            cur.execute(query, params)

            if fetchone:
                return cur.fetchone()

            if fetchall:
                return cur.fetchall()

            conn.commit()
            return None
        finally:
            conn.close()

    conn = get_sqlite_conn()
    try:
        cur = conn.cursor()
        cur.execute(query, params)

        if fetchone:
            return cur.fetchone()

        if fetchall:
            return cur.fetchall()

        conn.commit()
        return None
    finally:
        conn.close()


def _user_by_email(email: str):
    email = _normalize_email(email)

    if not email:
        return None

    p = sql_placeholder()

    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
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
                WHERE LOWER(email) = {p}
                LIMIT 1
                """,
                (email,),
            )
            return cur.fetchone()
        finally:
            conn.close()

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()
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
            WHERE LOWER(email) = ?
            LIMIT 1
            """,
            (email,),
        )
        return cur.fetchone()
    finally:
        conn.close()


def _user_by_id(user_id: str):
    if not user_id:
        return None

    p = sql_placeholder()

    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
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
            return cur.fetchone()
        finally:
            conn.close()

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()
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
        return cur.fetchone()
    finally:
        conn.close()


def _user_is_active(user_id: str) -> bool:
    row = _user_by_id(user_id)

    if not row:
        return False

    return bool(row[6])
