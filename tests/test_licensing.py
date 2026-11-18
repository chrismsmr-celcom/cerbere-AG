"""Licences signées : vérification, expiration, falsification, gating du SSO, CLI, API."""

import io
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from collector import cli, licensing
from tests.licensing_helpers import DAY, Issuer, install

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def clean_license_env(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_LICENSE_KEY", raising=False)
    monkeypatch.delenv("AGENTGUARD_LICENSE_FILE", raising=False)
    licensing._warned.clear()


@pytest.fixture
def issuer(monkeypatch):
    return Issuer(monkeypatch)


def _env_license(monkeypatch, token):
    monkeypatch.setenv("AGENTGUARD_LICENSE_KEY", token)


# ── Plans et fonctionnalités ──────────────────────────────────────────────


def test_no_license_is_community_with_no_paid_features():
    state = licensing.current()
    assert (state.status, state.plan) == ("community", "community")
    assert state.features == frozenset()
    assert not licensing.has_feature("sso_oidc")


@pytest.mark.parametrize(
    "plan,sso,retention",
    [("pro", False, True), ("team", True, True), ("enterprise", True, True)],
)
def test_plan_features(monkeypatch, issuer, plan, sso, retention):
    _env_license(monkeypatch, issuer.token(plan))
    assert licensing.current().plan == plan
    assert licensing.has_feature("sso_oidc") is sso
    assert licensing.has_feature("extended_retention") is retention


def test_extra_feature_can_be_granted_on_a_lower_plan(monkeypatch, issuer):
    _env_license(monkeypatch, issuer.token("pro", features=["sso_oidc"]))
    assert licensing.has_feature("sso_oidc")
    assert not licensing.has_feature("siem_export")


# ── Expiration ────────────────────────────────────────────────────────────


def test_expired_license_keeps_paid_features_during_grace(monkeypatch, issuer):
    _env_license(
        monkeypatch, issuer.token("team", days=30, issued_days_ago=35)
    )  # expirée il y a 5 jours
    state = licensing.current()
    assert state.status == "grace" and state.plan == "team"
    assert licensing.has_feature("sso_oidc")
    assert "Renew" in state.message


def test_license_falls_back_to_community_after_grace(monkeypatch, issuer):
    _env_license(
        monkeypatch, issuer.token("team", days=30, issued_days_ago=60)
    )  # expirée il y a 30 jours
    state = licensing.current()
    assert (state.status, state.plan) == ("expired", "community")
    assert not licensing.has_feature("sso_oidc")
    assert "Detection and blocking are unaffected" in state.message


def test_license_issued_in_the_future_is_ignored(monkeypatch, issuer):
    _env_license(monkeypatch, issuer.token("team", issued_days_ago=-10))
    assert licensing.current().status == "invalid"


# ── Falsification ─────────────────────────────────────────────────────────


def _swap_payload(token, **changes):
    prefix, kid, payload_b64, sig = token.split(".")
    data = json.loads(licensing._b64d(payload_b64))
    data.update(changes)
    forged = licensing._b64e(
        json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    )
    return f"{prefix}.{kid}.{forged}.{sig}"


def test_editing_the_payload_invalidates_the_signature(monkeypatch, issuer):
    token = issuer.token("pro")
    forged = _swap_payload(
        token, plan="enterprise", expires_at=int(time.time()) + 99 * 365 * DAY
    )
    _env_license(monkeypatch, forged)
    state = licensing.current()
    assert (state.status, state.plan) == ("invalid", "community")
    assert "signature" in state.message


def test_license_signed_by_an_unknown_key_is_rejected(monkeypatch, issuer):
    other_private, _ = licensing.generate_keypair()
    now = int(time.time())
    token = licensing.sign_license(
        other_private,
        "k1",
        {
            "id": "x",
            "customer": "Mallory",
            "plan": "enterprise",
            "issued_at": now,
            "expires_at": now + DAY,
        },
    )
    _env_license(monkeypatch, token)
    assert licensing.current().status == "invalid"


def test_unknown_key_id_is_rejected(monkeypatch, issuer):
    token = issuer.token("team").replace("cerbere_lic_v1.k1.", "cerbere_lic_v1.k9.")
    _env_license(monkeypatch, token)
    assert "does not trust" in licensing.current().message


def test_build_without_public_key_trusts_nothing(monkeypatch, issuer):
    token = issuer.token("team")
    monkeypatch.setattr(licensing, "PUBLIC_KEYS", {})
    _env_license(monkeypatch, token)
    state = licensing.current()
    assert state.status == "invalid" and "no licensing public key" in state.message


@pytest.mark.parametrize(
    "garbage",
    [
        "garbage",
        "cerbere_lic_v1.k1.AAAA",
        "cerbere_lic_v1.k1.AAAA.BBBB",
        "other_lic_v1.k1.AAAA.BBBB",
        "a.b.c.d",
        "cerbere_lic_v1.k1...",
    ],
)
def test_malformed_keys_never_raise(monkeypatch, issuer, garbage):
    _env_license(monkeypatch, garbage)
    state = licensing.current()
    assert (state.status, state.plan) == ("invalid", "community")


def test_payload_must_be_complete_and_sane(monkeypatch, issuer):
    now = int(time.time())
    bad_payloads = [
        {
            "id": "x",
            "customer": "A",
            "plan": "community",
            "issued_at": now,
            "expires_at": now + DAY,
        },
        {
            "id": "x",
            "customer": "A",
            "plan": "platinum",
            "issued_at": now,
            "expires_at": now + DAY,
        },
        {"id": "x", "customer": "A", "plan": "team", "issued_at": now},
        {
            "id": "x",
            "customer": "A",
            "plan": "team",
            "issued_at": now,
            "expires_at": now - DAY,
        },
    ]
    for payload in bad_payloads:
        token = licensing.sign_license(issuer.private, "k1", payload)
        _env_license(monkeypatch, token)
        assert licensing.current().status == "invalid", payload


def test_key_rotation_keeps_old_licenses_valid(monkeypatch, issuer):
    old_token = issuer.token("team")
    new_private, new_public = licensing.generate_keypair()
    monkeypatch.setitem(licensing.PUBLIC_KEYS, "k2", new_public)
    now = int(time.time())
    new_token = licensing.sign_license(
        new_private,
        "k2",
        {
            "id": "n",
            "customer": "B",
            "plan": "pro",
            "issued_at": now,
            "expires_at": now + DAY,
        },
    )
    for token, plan in ((old_token, "team"), (new_token, "pro")):
        _env_license(monkeypatch, token)
        assert licensing.current().plan == plan


# ── Chargement ────────────────────────────────────────────────────────────


def test_license_can_come_from_a_file(monkeypatch, tmp_path, issuer):
    path = tmp_path / "license.key"
    path.write_text(issuer.token("team") + "\n")
    monkeypatch.setenv("AGENTGUARD_LICENSE_FILE", str(path))
    assert licensing.current().plan == "team"


def test_missing_license_file_means_community(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTGUARD_LICENSE_FILE", str(tmp_path / "nope.key"))
    assert licensing.current().plan == "community"


def test_environment_key_wins_over_file(monkeypatch, tmp_path, issuer):
    path = tmp_path / "license.key"
    path.write_text(issuer.token("pro"))
    monkeypatch.setenv("AGENTGUARD_LICENSE_FILE", str(path))
    _env_license(monkeypatch, issuer.token("enterprise"))
    assert licensing.current().plan == "enterprise"


def test_status_dict_never_exposes_the_key(monkeypatch, issuer):
    token = issuer.token("team", limits={"agents": 50})
    _env_license(monkeypatch, token)
    info = licensing.status_dict()
    assert info["plan"] == "team" and info["customer"] == "ACME Corp"
    assert info["limits"] == {"agents": 50} and info["days_left"] >= 364
    assert token.split(".")[3] not in json.dumps(info)


# ── CLI ───────────────────────────────────────────────────────────────────


def test_cli_license_status(monkeypatch, issuer, capsys):
    assert cli.main(["license", "status"]) == 0
    assert "community" in capsys.readouterr().out
    _env_license(monkeypatch, issuer.token("team"))
    assert cli.main(["license", "status"]) == 0
    out = capsys.readouterr().out
    assert "team" in out and "ACME Corp" in out and "sso_oidc" in out


def test_cli_license_install_verifies_then_writes_atomically(
    monkeypatch, tmp_path, issuer, capsys
):
    dest = tmp_path / "data" / "license.key"
    monkeypatch.setenv("AGENTGUARD_LICENSE_FILE", str(dest))
    monkeypatch.setattr(sys, "stdin", io.StringIO(issuer.token("team")))
    assert cli.main(["license", "install", "-"]) == 0
    assert dest.exists()
    # Le mode 600 n'est vérifiable que sur les systèmes POSIX
    # (sous Windows, st_mode renvoie toujours 666 et chmod est sans effet).
    if sys.platform != "win32":
        assert oct(dest.stat().st_mode)[-3:] == "600"
    assert licensing.current().plan == "team"  # pris en compte sans redémarrage


def test_cli_license_install_rejects_invalid_key(monkeypatch, tmp_path, issuer, capsys):
    dest = tmp_path / "license.key"
    monkeypatch.setenv("AGENTGUARD_LICENSE_FILE", str(dest))
    monkeypatch.setattr(
        sys, "stdin", io.StringIO(_swap_payload(issuer.token("pro"), plan="enterprise"))
    )
    assert cli.main(["license", "install", "-"]) == 1
    assert not dest.exists()
    assert "signature" in capsys.readouterr().err


def test_cli_license_install_needs_a_destination(monkeypatch, issuer, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(issuer.token("team")))
    assert cli.main(["license", "install", "-"]) == 1
    assert "AGENTGUARD_LICENSE_FILE" in capsys.readouterr().err


# ── Outil d'émission (scripts/cerbere_license.py) ─────────────────────────


def test_issuer_tool_end_to_end(monkeypatch, tmp_path):
    tool = str(ROOT / "scripts" / "cerbere_license.py")
    key = tmp_path / "private.key"
    out = subprocess.run(
        [sys.executable, tool, "keygen", "--out", str(key)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    if sys.platform != "win32":
        assert oct(key.stat().st_mode)[-3:] == "600"
    public = out.stdout.split('"k1": "')[1].split('"')[0]

    again = subprocess.run(
        [sys.executable, tool, "keygen", "--out", str(key)],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert (
        again.returncode == 1 and "overwrite" in again.stderr
    )  # ne jamais écraser une clé

    monkeypatch.setitem(licensing.PUBLIC_KEYS, "k1", public)
    issued = subprocess.run(
        [
            sys.executable,
            tool,
            "issue",
            "--key",
            str(key),
            "--customer",
            "ACME",
            "--plan",
            "team",
            "--days",
            "30",
            "--limit",
            "agents=50",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert issued.returncode == 0, issued.stderr
    token = issued.stdout.strip().splitlines()[0]
    lic = licensing.verify_license(token)
    assert (lic.plan, lic.customer, lic.limits) == ("team", "ACME", {"agents": 50})
    assert 29 <= (lic.expires_at - lic.issued_at) / DAY <= 30


# ── Application : SSO réservé aux offres Team et Enterprise, API ──────────


SSO_ENV = {
    "AGENTGUARD_OIDC_ISSUER": "https://idp.example.com",
    "AGENTGUARD_OIDC_CLIENT_ID": "cerbere",
    "AGENTGUARD_OIDC_CLIENT_SECRET": "s3cret",
    "AGENTGUARD_OIDC_ALLOWED_DOMAINS": "acme.example",
}


@pytest.fixture
def app_ctx(tmp_path, monkeypatch):
    from tests.dbmode import configure_db

    configure_db(monkeypatch, tmp_path, "licensing")
    monkeypatch.setenv("AGENTGUARD_FLASK_SECRET", "test-flask-secret-for-ci-only")
    monkeypatch.setenv("AGENTGUARD_COOKIE_SECURE", "false")
    monkeypatch.delenv("AGENTGUARD_ENVIRONMENT", raising=False)
    for k, v in SSO_ENV.items():
        monkeypatch.setenv(k, v)

    from collector.app import create_app
    from collector.db import init_db, init_identity_tables

    init_db()
    init_identity_tables()
    app = create_app()
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False
    return app


def _user(email="admin@acme.example", role="admin", password="correct-horse-battery"):
    monkey_stdin = io.StringIO(password + "\n")
    old, sys.stdin = sys.stdin, monkey_stdin
    try:
        assert (
            cli.main(
                [
                    "create-admin",
                    "--email",
                    email,
                    "--role",
                    role,
                    "--org",
                    "ACME",
                    "--password-stdin",
                ]
            )
            == 0
        )
    finally:
        sys.stdin = old


def _sso_button(client):
    return 'href="/auth/sso/login"' in client.get("/login").data.decode()


def test_sso_is_hidden_and_explained_without_a_license(app_ctx):
    with app_ctx.test_client() as c:
        assert not _sso_button(c)
        r = c.get("/auth/sso/login")
        assert r.status_code == 403
        assert b"Team and Enterprise" in r.data


def test_sso_is_not_part_of_the_pro_plan(app_ctx, monkeypatch):
    install(monkeypatch, "pro")
    with app_ctx.test_client() as c:
        assert not _sso_button(c)
        assert c.get("/auth/sso/login").status_code == 403


@pytest.mark.parametrize("plan", ["team", "enterprise"])
def test_sso_is_available_on_team_and_enterprise(app_ctx, monkeypatch, plan):
    install(monkeypatch, plan)
    with app_ctx.test_client() as c:
        assert _sso_button(c)


def test_pro_license_with_sso_addon_enables_sso(app_ctx, monkeypatch):
    install(monkeypatch, "pro", features=["sso_oidc"])
    with app_ctx.test_client() as c:
        assert _sso_button(c)


def test_sso_survives_the_grace_period_then_stops(app_ctx, monkeypatch):
    install(monkeypatch, "team", days=30, issued_days_ago=35)  # grâce
    with app_ctx.test_client() as c:
        assert _sso_button(c)
    install(monkeypatch, "team", days=30, issued_days_ago=60)  # au-delà
    with app_ctx.test_client() as c:
        assert not _sso_button(c)
        assert c.get("/auth/sso/login").status_code == 403


def test_expired_license_never_locks_people_out(app_ctx, monkeypatch):
    """Mot de passe « désactivé » + SSO non couvert par la licence => le mot de passe reste disponible."""
    import collector.auth.config as cfg
    import collector.auth.routes_password as rp

    monkeypatch.setattr(cfg, "PASSWORD_LOGIN_ENABLED", False)
    monkeypatch.setattr(rp, "PASSWORD_LOGIN_ENABLED", False)
    _user()
    install(monkeypatch, "team", days=30, issued_days_ago=60)  # licence expirée
    with app_ctx.test_client() as c:
        assert 'action="/auth/password"' in c.get("/login").data.decode()
        r = c.post(
            "/auth/password",
            data={"email": "admin@acme.example", "password": "correct-horse-battery"},
        )
        assert r.status_code == 302


def test_password_can_be_hidden_only_while_sso_works(app_ctx, monkeypatch):
    import collector.auth.config as cfg
    import collector.auth.routes_password as rp

    monkeypatch.setattr(cfg, "PASSWORD_LOGIN_ENABLED", False)
    monkeypatch.setattr(rp, "PASSWORD_LOGIN_ENABLED", False)
    _user()
    install(monkeypatch, "team")
    with app_ctx.test_client() as c:
        assert 'action="/auth/password"' not in c.get("/login").data.decode()
        r = c.post(
            "/auth/password",
            data={"email": "admin@acme.example", "password": "correct-horse-battery"},
        )
        assert r.status_code == 503


def test_license_api_is_admin_only(app_ctx, monkeypatch):
    install(monkeypatch, "team")
    _user("admin@acme.example", "admin")
    with app_ctx.test_client() as anonymous:
        assert anonymous.get("/api/license").status_code == 401
    with app_ctx.test_client() as c:
        c.post(
            "/auth/password",
            data={"email": "admin@acme.example", "password": "correct-horse-battery"},
        )
        r = c.get("/api/license")
        assert r.status_code == 200
        body = r.get_json()
        assert (
            body["plan"] == "team"
            and body["status"] == "active"
            and "sso_oidc" in body["features"]
        )


def test_license_api_refuses_non_admins(app_ctx, monkeypatch):
    install(monkeypatch, "team")
    _user("admin@acme.example", "admin")
    _user("viewer@acme.example", "viewer")
    with app_ctx.test_client() as c:
        c.post(
            "/auth/password",
            data={"email": "viewer@acme.example", "password": "correct-horse-battery"},
        )
        assert c.get("/api/license").status_code in (401, 403)
