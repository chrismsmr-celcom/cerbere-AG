"""Choix du moteur de base pour les tests.

Par défaut : SQLite (fichier temporaire). Pour exécuter les mêmes tests sur
PostgreSQL, définir AGENTGUARD_TEST_DATABASE_URL, par exemple :

    AGENTGUARD_TEST_DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/testdb pytest tests/test_oidc_sso.py

ATTENTION : le schéma `public` de cette base est supprimé et recréé avant chaque test.
"""

import os


def using_postgres() -> bool:
    return bool(os.environ.get("AGENTGUARD_TEST_DATABASE_URL"))


def configure_db(monkeypatch, tmp_path, name="test"):
    url = os.environ.get("AGENTGUARD_TEST_DATABASE_URL")
    from collector import db

    if db._PG_POOL is not None:
        db._PG_POOL.close()
        db._PG_POOL = None

    if url:
        import psycopg

        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("DROP SCHEMA public CASCADE")
            conn.execute("CREATE SCHEMA public")
        monkeypatch.setenv("AGENTGUARD_DB_TYPE", "postgres")
        monkeypatch.setenv("DATABASE_URL", url)
    else:
        monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
        monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / f"{name}.db"))

    from collector import migrations

    migrations._done.clear()  # la base vient d'être recréée : re-vérifier les migrations


def set_active(where_sql: str, params: tuple, active: bool) -> None:
    """UPDATE users SET active = ... (booléen PostgreSQL / entier SQLite)."""
    from collector.auth.users import _db_execute
    from collector.db import is_postgres, sql_placeholder

    p = sql_placeholder()
    value = active if is_postgres() else int(active)
    _db_execute(f"UPDATE users SET active = {p} WHERE {where_sql}", (value, *params))
