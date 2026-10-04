"""Route /signup (création tenant -> org -> user + magic link)."""

import secrets
import sqlite3
import uuid
from datetime import timedelta

import structlog
from flask import render_template_string, request

from collector.db import _get_db_path, get_pg_conn, is_postgres, sql_placeholder

from .blueprint import auth_bp
from .config import MAGIC_LINK_TOKEN_BYTES, MAGIC_LINK_TTL_SECONDS
from .magic_link import (
    _build_magic_link,
    _ensure_magic_link_table,
    _send_magic_link_email,
    _store_magic_link,
)
from .pages import SIGNUP_HTML
from .users import _user_by_email
from .utils import _hash_magic_token, _normalize_email, _utcnow, _valid_email

logger = structlog.get_logger("agentguard.auth")


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template_string(SIGNUP_HTML, error=None, success=None)

    email = _normalize_email(request.form.get("email", ""))
    display_name = request.form.get("name", "").strip()
    company_name = request.form.get("company", "").strip()

    if not _valid_email(email):
        return render_template_string(SIGNUP_HTML, error="Enter a valid work email address.", success=None), 400

    if not display_name:
        return render_template_string(SIGNUP_HTML, error="Full name is required.", success=None), 400

    try:
        _ensure_magic_link_table()

        # 1. Vérifier si l'utilisateur existe déjà
        existing_user = _user_by_email(email)
        if existing_user:
            return render_template_string(
                SIGNUP_HTML,
                error="An account with this email already exists. Please log in.",
                success=None
            ), 400

        # 2. Générer les identifiants uniques pour la chaîne Tenant -> Org -> User
        user_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())
        tenant_id = str(uuid.uuid4())

        tenant_name = company_name or f"{display_name}'s Workspace"
        org_name = company_name or "Default Organization"

        p = sql_placeholder()

        # 3. Insérer dans l'ordre des contraintes de clé étrangère (Foreign Keys)
        if is_postgres():
            conn = get_pg_conn()
            try:
                cur = conn.cursor()

                # Étape A : Créer le Tenant
                cur.execute(f"""
                    INSERT INTO tenants (tenant_id, name, created_at)
                    VALUES ({p}, {p}, CURRENT_TIMESTAMP)
                """, (tenant_id, tenant_name))

                # Étape B : Créer l'Organisation liée à ce Tenant
                cur.execute(f"""
                    INSERT INTO orgs (org_id, tenant_id, name, created_at)
                    VALUES ({p}, {p}, {p}, CURRENT_TIMESTAMP)
                """, (org_id, tenant_id, org_name))

                # Étape C : Créer l'Utilisateur lié à ce Tenant et cette Organisation
                cur.execute(f"""
                    INSERT INTO users (user_id, org_id, tenant_id, email, display_name, role, active, created_at)
                    VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, CURRENT_TIMESTAMP)
                """, (user_id, org_id, tenant_id, email, display_name, "admin", True))

                conn.commit()
            finally:
                conn.close()
        else:
            # Fallback SQLite pour le développement local
            conn = sqlite3.connect(_get_db_path())
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO tenants (tenant_id, name, created_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                """, (tenant_id, tenant_name))

                cur.execute("""
                    INSERT INTO orgs (org_id, tenant_id, name, created_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (org_id, tenant_id, org_name))

                cur.execute("""
                    INSERT INTO users (user_id, org_id, tenant_id, email, display_name, role, active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (user_id, org_id, tenant_id, email, display_name, "admin", 1))
                conn.commit()
            finally:
                conn.close()

        # 4. Générer et envoyer automatiquement le Magic Link pour une connexion immédiate
        raw_token = secrets.token_urlsafe(MAGIC_LINK_TOKEN_BYTES)
        token_hash = _hash_magic_token(raw_token)
        expires_at = _utcnow() + timedelta(seconds=MAGIC_LINK_TTL_SECONDS)

        _store_magic_link(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
        link = _build_magic_link(raw_token)
        _send_magic_link_email(email, link)

        logger.info(
            "user_registered_and_magic_link_sent",
            user_id=user_id,
            email=email,
            ip=request.remote_addr,
        )

        return render_template_string(
            SIGNUP_HTML,
            error=None,
            success="Account created successfully! A secure sign-in link has been sent to your email."
        )

    except Exception as exc:
        logger.error("signup_failed", error=str(exc), email=email)
        return render_template_string(
            SIGNUP_HTML,
            error="Unable to create account. Please try again.",
            success=None
        ), 500
