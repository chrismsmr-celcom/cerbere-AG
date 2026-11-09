"""Connexion locale par mot de passe (self-hosted).

Objectif : permettre à une instance installée chez un client de démarrer
sans Supabase ni SMTP. Le mot de passe est haché (scrypt via werkzeug) dans
`users.password_hash`. Aucun mot de passe n'est jamais journalisé.

Le même module sert à la CLI (`python -m collector.cli`) et à la route
`POST /auth/password`.
"""

from __future__ import annotations

import uuid

from werkzeug.security import check_password_hash, generate_password_hash

from collector.db import is_postgres, sql_placeholder
from collector.migrations import ensure_migrated

from .users import _db_execute, _user_by_email
from .utils import _normalize_email, _valid_email

MIN_PASSWORD_LENGTH = 12

# Hash factice : on vérifie toujours un hash, même pour un email inconnu,
# afin que le temps de réponse ne révèle pas l'existence d'un compte.
_DUMMY_HASH = generate_password_hash("not-a-real-password-for-timing-only")


class PasswordError(ValueError):
    """Mot de passe ou paramètres invalides (message affichable)."""


def ensure_password_column() -> None:
    """Garantit que le schéma est à jour (migration `users_password_hash`)."""
    ensure_migrated()


def validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )
    if len(password) > 256:
        raise PasswordError("Password is too long (max 256 characters).")


def hash_password(password: str) -> str:
    validate_password(password)
    return generate_password_hash(password)


def set_user_password(user_id: str, password: str) -> None:
    ensure_password_column()
    p = sql_placeholder()
    _db_execute(
        f"UPDATE users SET password_hash = {p} WHERE user_id = {p}",
        (hash_password(password), user_id),
    )


def verify_credentials(email: str, password: str):
    """Retourne le tuple user (comme `_user_by_email`) ou None.

    Refuse les comptes inactifs et ceux sans mot de passe défini.
    """
    ensure_password_column()
    email = _normalize_email(email)
    password = password or ""

    user = _user_by_email(email) if email else None
    stored = None
    if user:
        p = sql_placeholder()
        row = _db_execute(
            f"SELECT password_hash FROM users WHERE user_id = {p}",
            (user[0],),
            fetchone=True,
        )
        stored = row[0] if row else None

    # Toujours exécuter une vérification (temps constant approximatif).
    ok = check_password_hash(stored or _DUMMY_HASH, password)

    if not user or not stored or not ok:
        return None
    if not bool(user[6]):
        return None
    return user


def provision_workspace(
    email: str,
    password: str,
    display_name: str | None = None,
    org_name: str | None = None,
    role: str = "admin",
):
    """Crée tenant + org + utilisateur (admin par défaut) avec mot de passe.

    Retourne (user_id, org_id, tenant_id). Lève PasswordError si invalide ou
    si l'email existe déjà.
    """
    email = _normalize_email(email)
    if not _valid_email(email):
        raise PasswordError("Invalid email address.")
    validate_password(password)
    if role not in {"admin", "developer", "auditor", "viewer"}:
        raise PasswordError("Invalid role.")
    if _user_by_email(email):
        raise PasswordError("A user with this email already exists.")

    ensure_password_column()

    user_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())
    display_name = display_name or email.split("@", 1)[0]
    org_name = org_name or "Default Organization"
    p = sql_placeholder()
    active = True if is_postgres() else 1

    _db_execute(
        f"INSERT INTO tenants (tenant_id, name, created_at) "
        f"VALUES ({p}, {p}, CURRENT_TIMESTAMP)",
        (tenant_id, org_name),
    )
    _db_execute(
        f"INSERT INTO orgs (org_id, tenant_id, name, created_at) "
        f"VALUES ({p}, {p}, {p}, CURRENT_TIMESTAMP)",
        (org_id, tenant_id, org_name),
    )
    _db_execute(
        f"INSERT INTO users (user_id, org_id, tenant_id, email, display_name, "
        f"role, active, password_hash, created_at) "
        f"VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, CURRENT_TIMESTAMP)",
        (
            user_id,
            org_id,
            tenant_id,
            email,
            display_name,
            role,
            active,
            hash_password(password),
        ),
    )
    return user_id, org_id, tenant_id
