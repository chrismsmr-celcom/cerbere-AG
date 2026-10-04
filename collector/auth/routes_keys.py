"""Gestion des clés API du dashboard : création, liste, révocation."""

import secrets
import sqlite3
import uuid

import structlog
from flask import g, jsonify, request

from collector.db import _get_db_path, get_pg_conn, is_postgres, sql_placeholder

from .api_keys import _ensure_api_keys_table_safe
from .blueprint import auth_bp
from .middleware import require_auth
from .utils import hash_key

logger = structlog.get_logger("agentguard.auth")


@auth_bp.post("/api/keys")
def create_api_key():
    try:
        if not require_auth():
            return jsonify({"error": "Unauthorized"}), 401

        org_id = getattr(g, "org_id", None)
        if not org_id:
            return jsonify({"error": "Organization ID not found in session. Please log in again."}), 403

        data = request.get_json(silent=True) or {}
        name = data.get("name", "Default API Key").strip() or "Default API Key"

        # 1. Générer et hasher
        raw_key = "ag_live_" + secrets.token_urlsafe(32)
        key_hash = hash_key(raw_key)
        key_id = str(uuid.uuid4())

        # 2. S'assurer que la table existe (appel unique et sûr)
        _ensure_api_keys_table_safe()

        # 3. Insérer en base
        p = sql_placeholder()
        if is_postgres():
            conn = get_pg_conn()
            try:
                cur = conn.cursor()
                cur.execute(f"""
                    INSERT INTO user_api_keys (id, org_id, key_hash, name, active, created_at)
                    VALUES ({p}, {p}, {p}, {p}, TRUE, CURRENT_TIMESTAMP)
                """, (key_id, org_id, key_hash, name))
                conn.commit()
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(_get_db_path())
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO user_api_keys (id, org_id, key_hash, name, active, created_at)
                    VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                """, (key_id, org_id, key_hash, name))
                conn.commit()
            finally:
                conn.close()

        logger.info("api_key_created", org_id=org_id, key_id=key_id)

        return jsonify({
            "status": "success",
            "key": raw_key,
            "key_id": key_id,
            "name": name,
            "message": "⚠️ IMPORTANT : Copiez cette clé maintenant. Elle ne sera plus jamais affichée."
        }), 201

    except Exception as e:
        logger.error("create_api_key_crashed", error=str(e), exc_info=True)
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@auth_bp.get("/api/keys")
def list_api_keys():
    try:
        if not require_auth():
            return jsonify({"error": "Unauthorized"}), 401

        org_id = getattr(g, "org_id", None)
        if not org_id:
            return jsonify({"error": "Organization ID not found in session."}), 403

        _ensure_api_keys_table_safe()

        p = sql_placeholder()
        if is_postgres():
            conn = get_pg_conn()
            try:
                cur = conn.cursor()
                cur.execute(f"""
                    SELECT id, name, active, created_at
                    FROM user_api_keys
                    WHERE org_id = {p}
                    ORDER BY created_at DESC
                """, (org_id,))
                rows = cur.fetchall()
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(_get_db_path())
            try:
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, name, active, created_at
                    FROM user_api_keys
                    WHERE org_id = ?
                    ORDER BY created_at DESC
                """, (org_id,))
                rows = cur.fetchall()
            finally:
                conn.close()

        keys = []
        for row in rows:
            keys.append({
                "id": row[0],
                "name": row[1],
                "active": bool(row[2]),
                "created_at": row[3],
                "key_preview": "ag_live_..." + (str(row[0])[-4:] if row[0] else "????")
            })
        
        return jsonify({"keys": keys}), 200

    except Exception as e:
        logger.error("list_api_keys_crashed", error=str(e), exc_info=True)
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@auth_bp.delete("/api/keys/<key_id>")
def revoke_api_key(key_id):
    try:
        if not require_auth():
            return jsonify({"error": "Unauthorized"}), 401

        org_id = getattr(g, "org_id", None)
        if not org_id:
            return jsonify({"error": "Organization ID not found in session."}), 403

        p = sql_placeholder()
        if is_postgres():
            conn = get_pg_conn()
            try:
                cur = conn.cursor()
                cur.execute(f"""
                    UPDATE user_api_keys
                    SET active = FALSE
                    WHERE id = {p} AND org_id = {p}
                """, (key_id, org_id))
                conn.commit()
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(_get_db_path())
            try:
                cur = conn.cursor()
                cur.execute("""
                    UPDATE user_api_keys
                    SET active = 0
                    WHERE id = ? AND org_id = ?
                """, (key_id, org_id))
                conn.commit()
            finally:
                conn.close()

        return jsonify({"status": "success", "message": "Clé révoquée avec succès"}), 200

    except Exception as e:
        logger.error("revoke_api_key_crashed", error=str(e), exc_info=True)
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
