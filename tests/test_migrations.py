"""Migrations de schéma versionnées : mêmes tests sur SQLite et sur PostgreSQL.

AGENTGUARD_TEST_DATABASE_URL=postgresql://user@127.0.0.1:5432/testdb pytest tests/test_migrations.py
"""

import threading

import pytest

from collector import cli, migrations
from collector.migrations import MigrationError, run_migrations, status


@pytest.fixture
def db(tmp_path, monkeypatch):
    from tests.dbmode import configure_db

    configure_db(monkeypatch, tmp_path, "migrations")
    monkeypatch.setattr(migrations, "MIGRATIONS", list(migrations.MIGRATIONS))


def _exec(sql, params=(), fetchall=False):
    from collector.auth.users import _db_execute

    return _db_execute(sql, params, fetchall=fetchall)


def _columns(table):
    from collector.db import is_postgres

    if is_postgres():
        rows = _exec(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s",
            (table,),
            fetchall=True,
        )
        return {r[0] for r in rows}
    return {r[1] for r in _exec(f"PRAGMA table_info({table})", fetchall=True)}


def _index_exists(name):
    from collector.db import is_postgres

    if is_postgres():
        rows = _exec(
            "SELECT indexname FROM pg_indexes WHERE indexname = %s",
            (name,),
            fetchall=True,
        )
    else:
        rows = _exec(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
            (name,),
            fetchall=True,
        )
    return bool(rows)


ALL = [m.version for m in migrations.MIGRATIONS]


def test_fresh_database_applies_all_migrations_in_order(db):
    assert run_migrations(init=True) == ALL
    info = status()
    assert [v for v, _ in info["applied"]] == ALL
    assert info["pending"] == [] and info["unknown"] == []
    assert {"password_hash", "oidc_issuer", "oidc_sub"} <= _columns("users")
    assert _index_exists("idx_users_oidc")


def test_second_run_does_nothing(db):
    run_migrations(init=True)
    assert run_migrations() == []
    rows = _exec("SELECT COUNT(*) FROM schema_migrations", fetchall=True)
    assert rows[0][0] == len(ALL)


def test_status_before_any_migration(db):
    from collector.db import init_db

    init_db()
    info = status()
    assert info["applied"] == []
    assert [v for v, _ in info["pending"]] == ALL


def test_adopts_existing_database_that_was_patched_by_hand(db):
    """Une base d'avant le système de migrations, avec colonnes déjà ajoutées à la volée."""
    from collector.db import init_db

    init_db()
    for col in ("password_hash", "oidc_issuer", "oidc_sub"):
        _exec(f"ALTER TABLE users ADD COLUMN {col} TEXT")
    _exec("CREATE UNIQUE INDEX idx_users_oidc ON users(oidc_issuer, oidc_sub)")

    assert run_migrations() == ALL  # aucune erreur « column already exists »
    assert status()["pending"] == []


def test_failed_migration_is_rolled_back_and_not_recorded(db, monkeypatch):
    def broken(ctx):
        ctx.add_column("users", "half_done", "TEXT")
        raise RuntimeError("boom")

    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        [*migrations.MIGRATIONS, migrations.Migration(4, "broken", broken)],
    )
    with pytest.raises(MigrationError, match=r"migration 4 \(broken\) failed: boom"):
        run_migrations(init=True)

    assert "half_done" not in _columns("users")  # transaction annulée
    assert [v for v, _ in status()["applied"]] == ALL  # 1 à 3 sont conservées
    assert [v for v, _ in status()["pending"]] == [4]

    # Une fois corrigée, la migration s'applique (le verrou n'est pas resté bloqué).
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        [
            *migrations.MIGRATIONS[:3],
            migrations.Migration(
                4, "fixed", lambda c: c.add_column("users", "ok_col", "TEXT")
            ),
        ],
    )
    assert run_migrations() == [4]
    assert "ok_col" in _columns("users")


def test_migration_on_missing_table_gives_clear_error(db, monkeypatch):
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        [
            *migrations.MIGRATIONS,
            migrations.Migration(
                4, "ghost", lambda c: c.add_column("nope", "x", "TEXT")
            ),
        ],
    )
    with pytest.raises(MigrationError, match="does not exist"):
        run_migrations(init=True)


def test_concurrent_workers_apply_each_migration_exactly_once(db):
    from collector.db import init_db

    init_db()
    results, errors = [], []
    barrier = threading.Barrier(4)

    def worker():
        try:
            barrier.wait(timeout=10)
            results.append(run_migrations())
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert errors == []
    assert (
        sorted(v for r in results for v in r) == ALL
    )  # chaque version appliquée une seule fois
    assert status()["pending"] == []


def test_database_newer_than_code_is_refused(db):
    run_migrations(init=True)
    _exec(
        "INSERT INTO schema_migrations (version, name) VALUES (999, 'from_the_future')"
    )
    with pytest.raises(MigrationError, match="newer"):
        run_migrations()
    assert run_migrations(strict=False) == []
    assert status()["unknown"] == [999]


def test_ensure_password_column_applies_pending_migrations(db):
    from collector.auth.local_password import ensure_password_column
    from collector.db import init_db

    init_db()
    ensure_password_column()
    assert status()["pending"] == []
    assert "password_hash" in _columns("users")


def test_app_boot_applies_migrations(db):
    from collector.app import init_db as app_init_db

    app_init_db()
    assert status()["pending"] == []


def test_cli_migrate_and_status(db, capsys):
    assert cli.main(["migrate", "--status"]) == 0  # base vierge : tout est en attente
    assert "pending  0001  baseline" in capsys.readouterr().out

    assert cli.main(["migrate"]) == 0
    assert "Applied migrations: 0001, 0002, 0003" in capsys.readouterr().out

    assert cli.main(["migrate"]) == 0
    assert "up to date" in capsys.readouterr().out

    assert cli.main(["migrate", "--status"]) == 0
    out = capsys.readouterr().out
    assert "applied  0003  users_oidc_identity" in out and "pending" not in out

    _exec(
        "INSERT INTO schema_migrations (version, name) VALUES (999, 'from_the_future')"
    )
    assert cli.main(["migrate", "--status"]) == 1
    assert "UNKNOWN  0999" in capsys.readouterr().out
    assert cli.main(["migrate"]) == 1
    assert "newer" in capsys.readouterr().err
