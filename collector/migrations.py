"""Migrations de schéma versionnées (SQLite et PostgreSQL), en avant uniquement.

Principe
--------
- `init_db()` continue de créer les tables avec `CREATE TABLE IF NOT EXISTS`
  (c'est la « baseline », enregistrée comme version 1).
- Toute évolution ultérieure d'une table existante (nouvelle colonne, index...)
  devient une migration numérotée ci-dessous, appliquée une seule fois, dans
  l'ordre, et enregistrée dans la table `schema_migrations`.
- Chaque migration s'exécute dans sa propre transaction : si elle échoue,
  rien n'est appliqué ni enregistré, et le démarrage s'arrête avec un message clair.
- Plusieurs workers qui démarrent en même temps ne se gênent pas : verrou
  consultatif PostgreSQL / `BEGIN IMMEDIATE` SQLite, puis relecture des versions
  appliquées une fois le verrou obtenu.
- Il n'y a pas de « retour arrière » : pour revenir en arrière, restaurer la
  sauvegarde faite avant la mise à jour (voir docs/SELF_HOSTING.md).

Ajouter une migration : écrire une fonction `_mNNNN_description(ctx)`, l'ajouter
à `MIGRATIONS` avec le numéro suivant, ne JAMAIS modifier ni renuméroter une
migration déjà publiée.

CLI : `python -m collector.cli migrate [--status]`
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

import structlog

from collector.db import (
    _get_db_config,
    _get_db_path,
    get_pg_conn,
    is_postgres,
)

logger = structlog.get_logger("agentguard.migrations")

# init_db() utilise 727271 : on prend un identifiant différent.
LOCK_ID = 727272


class MigrationError(RuntimeError):
    """Une migration a échoué ou la base est plus récente que le code."""


# ── Adaptateur SQLite / PostgreSQL ────────────────────────────────────────


class Ctx:
    """Petit adaptateur pour écrire une migration une seule fois.

    Le SQL s'écrit avec des `?` ; ils sont convertis en `%s` pour PostgreSQL.
    """

    def __init__(self, conn, postgres: bool):
        self._conn = conn
        self.postgres = postgres

    def execute(self, sql: str, params=()):
        if self.postgres:
            sql = sql.replace("?", "%s")
        cur = self._conn.cursor()
        cur.execute(sql, params)
        return cur

    def table_exists(self, table: str) -> bool:
        if self.postgres:
            row = self.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = current_schema() AND table_name = ?",
                (table,),
            ).fetchone()
        else:
            row = self.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table,),
            ).fetchone()
        return row is not None

    def column_exists(self, table: str, column: str) -> bool:
        if self.postgres:
            row = self.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?",
                (table, column),
            ).fetchone()
            return row is not None
        return column in {
            r[1] for r in self.execute(f"PRAGMA table_info({table})").fetchall()
        }

    def require_table(self, table: str) -> None:
        if not self.table_exists(table):
            raise MigrationError(
                f"table {table!r} does not exist: initialise the database first "
                "(`python -m collector.cli migrate` does it)"
            )

    def add_column(self, table: str, column: str, sql_type: str) -> None:
        """Ajoute la colonne si elle n'existe pas (idempotent)."""
        self.require_table(table)
        if not self.column_exists(table, column):
            self.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")

    def create_index(
        self, name: str, table: str, columns: str, unique: bool = False
    ) -> None:
        u = "UNIQUE " if unique else ""
        self.execute(f"CREATE {u}INDEX IF NOT EXISTS {name} ON {table}({columns})")


# ── Migrations ────────────────────────────────────────────────────────────


def _m0001_baseline(ctx: Ctx) -> None:
    """Schéma créé par init_db() : simple point de départ, rien à faire."""


def _m0002_users_password_hash(ctx: Ctx) -> None:
    """Connexion locale par mot de passe (self-hosted sans SMTP ni Supabase)."""
    ctx.add_column("users", "password_hash", "TEXT")


def _m0003_users_oidc_identity(ctx: Ctx) -> None:
    """SSO OIDC : identité du fournisseur (issuer + sub) rattachée à l'utilisateur."""
    ctx.add_column("users", "oidc_issuer", "TEXT")
    ctx.add_column("users", "oidc_sub", "TEXT")
    ctx.create_index("idx_users_oidc", "users", "oidc_issuer, oidc_sub", unique=True)


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[Ctx], None]


MIGRATIONS: list[Migration] = [
    Migration(1, "baseline", _m0001_baseline),
    Migration(2, "users_password_hash", _m0002_users_password_hash),
    Migration(3, "users_oidc_identity", _m0003_users_oidc_identity),
]

_CREATE_TABLE = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    "version INTEGER PRIMARY KEY, "
    "name TEXT NOT NULL, "
    "applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
)


# ── Exécution ─────────────────────────────────────────────────────────────


def _read_applied(ctx: Ctx) -> dict[int, str]:
    rows = ctx.execute(
        "SELECT version, name FROM schema_migrations ORDER BY version"
    ).fetchall()
    return {int(v): str(n) for v, n in rows}


def _apply_pending(
    ctx: Ctx, begin: Callable[[], None], commit, rollback, strict: bool
) -> list[int]:
    ctx.execute(_CREATE_TABLE)
    commit()

    known = {m.version for m in MIGRATIONS}
    applied_now: list[int] = []

    for migration in sorted(MIGRATIONS, key=lambda m: m.version):
        begin()
        try:
            # Relire sous verrou : un autre worker a peut-être déjà migré.
            done = _read_applied(ctx)
            unknown = sorted(set(done) - known)
            if unknown and strict:
                raise MigrationError(
                    f"database schema is newer than this version of the code "
                    f"(unknown migrations {unknown}). Upgrade Cerbere or restore an older backup."
                )
            if migration.version in done:
                rollback()
                continue
            migration.apply(ctx)
            ctx.execute(
                "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
                (migration.version, migration.name),
            )
            commit()
            applied_now.append(migration.version)
            logger.info(
                "migration_applied", version=migration.version, name=migration.name
            )
        except MigrationError:
            rollback()
            raise
        except Exception as exc:
            rollback()
            raise MigrationError(
                f"migration {migration.version} ({migration.name}) failed: {exc}"
            ) from exc
    return applied_now


def _run_postgres(strict: bool) -> list[int]:
    conn = get_pg_conn()
    cur = conn.cursor()
    cur.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
    conn.commit()
    try:
        ctx = Ctx(conn, postgres=True)
        return _apply_pending(ctx, lambda: None, conn.commit, conn.rollback, strict)
    finally:
        try:
            conn.rollback()  # sortir d'une éventuelle transaction avortée avant de déverrouiller
            cur.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
            conn.commit()
        finally:
            conn.close()


def _run_sqlite(strict: bool) -> list[int]:
    conn = sqlite3.connect(_get_db_path(), timeout=30)
    conn.isolation_level = None  # transactions gérées explicitement
    try:
        ctx = Ctx(conn, postgres=False)

        def begin():
            conn.execute("BEGIN IMMEDIATE")

        def commit():
            if conn.in_transaction:
                conn.execute("COMMIT")

        def rollback():
            if conn.in_transaction:
                conn.execute("ROLLBACK")

        return _apply_pending(ctx, begin, commit, rollback, strict)
    finally:
        conn.close()


def run_migrations(init: bool = False, strict: bool = True) -> list[int]:
    """Applique les migrations en attente ; retourne les versions appliquées.

    init=True : crée d'abord les tables de base (init_db), pour une base vierge.
    strict=True : refuse de continuer si la base contient des migrations inconnues
    du code (base migrée par une version plus récente).
    """
    if init:
        from collector.db import init_db

        init_db()
    return _run_postgres(strict) if is_postgres() else _run_sqlite(strict)


def status() -> dict:
    """{'applied': [(version, name)], 'pending': [(version, name)], 'unknown': [version]}"""
    known = {m.version: m.name for m in MIGRATIONS}
    applied: dict[int, str] = {}
    if is_postgres():
        conn = get_pg_conn()
        try:
            ctx = Ctx(conn, postgres=True)
            if ctx.table_exists("schema_migrations"):
                applied = _read_applied(ctx)
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(_get_db_path(), timeout=30)
        try:
            ctx = Ctx(conn, postgres=False)
            if ctx.table_exists("schema_migrations"):
                applied = _read_applied(ctx)
        finally:
            conn.close()
    return {
        "applied": sorted(applied.items()),
        "pending": [(v, n) for v, n in sorted(known.items()) if v not in applied],
        "unknown": sorted(set(applied) - set(known)),
    }


# ── Garantie à la demande (modules qui ont besoin d'une colonne récente) ──

_done: set[tuple] = set()


def db_key() -> tuple:
    db_type, url = _get_db_config()
    return (db_type, url if db_type == "postgres" else _get_db_path())


def ensure_migrated() -> None:
    """Applique les migrations en attente une fois par processus et par base."""
    key = db_key()
    if key in _done:
        return
    run_migrations(strict=False)
    _done.add(key)
