"""Résolution des clés API (plateforme, système legacy, agent, tables api_keys/user_api_keys)."""

import sqlite3

import structlog
from flask import current_app, g, request

from collector.db import (
    _get_db_path,
    get_pg_conn,
    is_postgres,
    resolve_agent_identity,
    sql_placeholder,
)

from .utils import hash_key, safe_compare

logger = structlog.get_logger("agentguard.auth")


def _ensure_api_keys_table():
    """Crée la table api_keys si elle n'existe pas encore."""
    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        finally:
            conn.close()    


def _ensure_api_keys_table_safe():
    """Crée la table user_api_keys si elle n'existe pas, de manière sécurisée."""
    try:
        if is_postgres():
            conn = get_pg_conn()
            try:
                cur = conn.cursor()
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_api_keys (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        active BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(_get_db_path())
            try:
                cur = conn.cursor()
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_api_keys (
                        id TEXT PRIMARY KEY,
                        org_id TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        active INTEGER DEFAULT 1,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        logger.error("api_keys_table_creation_failed", error=str(e))


def _lookup_org_by_key(key: str):
    """Résout une clé API en organisation.

    Cherche dans `api_keys` (clés admin / historiques) PUIS dans `user_api_keys` (clés générées
    depuis le dashboard). Avant ce correctif, seule la première table était consultée : un agent
    utilisant une clé du dashboard recevait 401 sur /span et /api/approvals, donc rien
    n'apparaissait jamais dans le dashboard (0 approbation, 0 agent)."""
    if not key:
        return None

    key_hash = hash_key(key)
    p = sql_placeholder()
    active = "TRUE" if is_postgres() else "1"

    for table, has_name in (("api_keys", False), ("user_api_keys", True)):
        try:
            conn = get_pg_conn() if is_postgres() else sqlite3.connect(_get_db_path())
            try:
                cur = conn.cursor()
                cols = "org_id, name" if has_name else "org_id"
                cur.execute(
                    f"SELECT {cols} FROM {table} WHERE key_hash = {p} AND active = {active} LIMIT 1",
                    (key_hash,),
                )
                row = cur.fetchone()
            finally:
                conn.close()
        except Exception as exc:
            logger.debug("api_key_lookup_failed", table=table, error=str(exc))
            continue

        if row:
            if has_name:
                try:
                    g.api_key_name = str(row[1])   # sert à nommer les agents des anciens SDK
                except RuntimeError:
                    pass
            return row[0]

    return None


def resolve_org_id(key: str):
    """
    Resolve an API key to an organization.

    Supported:
      - agp_* platform identity
      - configured legacy system key
      - ag_* agent key
      - legacy api_keys table
    """
    if not key:
        return None

    # Platform identity
    try:
        from collector.platform_identity import (
            PLATFORM_KEY_PREFIX,
            resolve_platform_identity,
        )

        if key.startswith(PLATFORM_KEY_PREFIX):
            platform_identity = resolve_platform_identity(key)

            if platform_identity:
                g.platform_identity = platform_identity

                logger.info(
                    "platform_identity_resolved",
                    service=platform_identity.get(
                        "service_name"
                    ),
                )

                return "platform"

    except Exception as exc:
        logger.warning(
            "platform_identity_resolution_failed",
            error=str(exc),
        )

    # Legacy global key
    api_key = current_app.config.get("API_KEY")

    if api_key and safe_compare(key, api_key):
        logger.warning(
            "legacy_system_key_used",
            ip=request.remote_addr,
            endpoint=request.endpoint,
            note="Deprecated.",
        )

        return "default"

    # Agent key
    try:
        identity = resolve_agent_identity(key)
    except Exception as exc:
        logger.warning(
            "agent_identity_resolution_failed",
            error=str(exc),
        )
        identity = None

    if identity:
        g.agent_identity = identity
        return identity["org_id"]

    # Legacy api_keys table
    try:
        return _lookup_org_by_key(key)
    except Exception as exc:
        logger.warning(
            "legacy_api_key_lookup_failed",
            error=str(exc),
        )
        return None
