"""Auth locale (self-hosted) : CLI create-admin, login par mot de passe, signup désactivable."""

import io
import sys

import pytest

PASSWORD = "correct-horse-battery"


@pytest.fixture
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "local-auth.db"))
    monkeypatch.setenv("AGENTGUARD_FLASK_SECRET", "test-flask-secret-for-ci-only")
    monkeypatch.delenv("AGENTGUARD_ENVIRONMENT", raising=False)
    monkeypatch.delenv("AGENTGUARD_ADMIN_PASSWORD", raising=False)

    from collector.app import create_app
    from collector.db import init_db, init_identity_tables

    init_db()
    init_identity_tables()
    app = create_app()
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False
    return app


def _create_admin(email="admin@corp.example", password=PASSWORD):
    from collector import cli

    sys.stdin = io.StringIO(password + "\n")
    try:
        return cli.main(
            ["create-admin", "--email", email, "--org", "ACME", "--password-stdin"]
        )
    finally:
        sys.stdin = sys.__stdin__


def test_cli_create_admin_then_password_login(app_ctx):
    assert _create_admin() == 0
    with app_ctx.test_client() as c:
        r = c.post(
            "/auth/password",
            data={"email": "Admin@Corp.Example", "password": PASSWORD},
        )
        assert r.status_code == 302
        assert "ag_auth=" in r.headers.get("Set-Cookie", "")


def test_wrong_password_and_unknown_user_get_same_generic_error(app_ctx):
    assert _create_admin() == 0
    with app_ctx.test_client() as c:
        bad = c.post(
            "/auth/password",
            data={"email": "admin@corp.example", "password": "wrong-password-123"},
        )
        unknown = c.post(
            "/auth/password",
            data={"email": "nobody@corp.example", "password": PASSWORD},
        )
        assert bad.status_code == unknown.status_code == 401
        assert b"Invalid email or password." in bad.data
        assert b"Invalid email or password." in unknown.data
        assert "ag_auth=" not in bad.headers.get("Set-Cookie", "")


def test_short_password_rejected_by_cli(app_ctx):
    assert _create_admin(password="short") == 1


def test_duplicate_email_rejected(app_ctx):
    assert _create_admin() == 0
    assert _create_admin() == 1


def test_inactive_user_cannot_login(app_ctx):
    assert _create_admin() == 0
    from collector.auth.users import _db_execute

    _db_execute("UPDATE users SET active = 0")
    with app_ctx.test_client() as c:
        r = c.post(
            "/auth/password",
            data={"email": "admin@corp.example", "password": PASSWORD},
        )
        assert r.status_code == 401


def test_user_without_password_cannot_login(app_ctx):
    """Un compte créé par signup/Supabase (sans password_hash) ne peut pas se connecter ainsi."""
    assert _create_admin() == 0
    from collector.auth.users import _db_execute

    _db_execute("UPDATE users SET password_hash = NULL")
    with app_ctx.test_client() as c:
        r = c.post(
            "/auth/password", data={"email": "admin@corp.example", "password": ""}
        )
        assert r.status_code == 401


def test_password_login_can_be_disabled(app_ctx, monkeypatch):
    import collector.auth.routes_password as rp

    monkeypatch.setattr(rp, "PASSWORD_LOGIN_ENABLED", False)
    assert _create_admin() == 0
    with app_ctx.test_client() as c:
        r = c.post(
            "/auth/password",
            data={"email": "admin@corp.example", "password": PASSWORD},
        )
        assert r.status_code == 503


def test_signup_can_be_disabled(app_ctx, monkeypatch):
    import collector.auth.routes_signup as rs

    with app_ctx.test_client() as c:
        assert c.get("/signup").status_code == 200
        monkeypatch.setattr(rs, "SIGNUP_ENABLED", False)
        assert c.get("/signup").status_code == 403
        r = c.post("/signup", data={"email": "x@corp.example", "name": "X"})
        assert r.status_code == 403
    from collector.auth.users import _user_by_email

    assert _user_by_email("x@corp.example") is None


def test_login_page_exposes_password_form(app_ctx):
    with app_ctx.test_client() as c:
        html = c.get("/login").data.decode()
        assert 'action="/auth/password"' in html


def test_set_password_and_list_users(app_ctx, capsys):
    from collector import cli

    assert _create_admin() == 0
    sys.stdin = io.StringIO("another-strong-pass\n")
    try:
        assert (
            cli.main(
                ["set-password", "--email", "admin@corp.example", "--password-stdin"]
            )
            == 0
        )
    finally:
        sys.stdin = sys.__stdin__
    assert cli.main(["list-users"]) == 0
    assert "admin@corp.example" in capsys.readouterr().out
    with app_ctx.test_client() as c:
        ok = c.post(
            "/auth/password",
            data={"email": "admin@corp.example", "password": "another-strong-pass"},
        )
        old = c.post(
            "/auth/password",
            data={"email": "admin@corp.example", "password": PASSWORD},
        )
        assert ok.status_code == 302
        assert old.status_code == 401
