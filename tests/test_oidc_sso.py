"""SSO OIDC : flux complet contre un faux fournisseur d'identité (vraies signatures RSA)."""

import base64
import hashlib
import io
import sys
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://idp.example.com"
CLIENT_ID = "cerbere-client"
KID = "k1"


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _jwk(key, kid=KID):
    data = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    data.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return data


class FakeIdP:
    def __init__(self):
        self.key = _rsa()
        self.other_key = _rsa()
        self.issuer_in_metadata = ISSUER
        self.token = None
        self.posted = []

    def metadata(self):
        return {
            "issuer": self.issuer_in_metadata,
            "authorization_endpoint": ISSUER + "/authorize",
            "token_endpoint": ISSUER + "/token",
            "jwks_uri": ISSUER + "/keys",
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
        }

    def get(self, url):
        if url.endswith("/.well-known/openid-configuration"):
            return self.metadata()
        if url.endswith("/keys"):
            return {"keys": [_jwk(self.key)]}
        raise AssertionError(url)

    def post(self, url, data, basic_auth=None):
        self.posted.append(data)
        return {"id_token": self.token, "access_token": "at"}

    def mint(self, nonce, key=None, alg="RS256", **override):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "sub": "sub-jane",
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "email": "jane@acme.example",
            "email_verified": True,
            "name": "Jane Doe",
        }
        claims.update(override)
        claims = {k: v for k, v in claims.items() if v is not None}
        if alg == "HS256":
            return jwt.encode(
                claims,
                "shared-secret-shared-secret-1234",
                algorithm="HS256",
                headers={"kid": KID},
            )
        if alg == "none":
            return jwt.encode(claims, None, algorithm="none", headers={"kid": KID})
        return jwt.encode(
            claims, _pem(key or self.key), algorithm=alg, headers={"kid": KID}
        )


@pytest.fixture
def idp(monkeypatch):
    from collector.auth import oidc

    f = FakeIdP()
    monkeypatch.setattr(oidc, "_http_get", f.get)
    monkeypatch.setattr(oidc, "_http_post", f.post)
    oidc._cache.clear()
    oidc._ensured.clear()
    oidc._warned.clear()
    return f


@pytest.fixture
def app_ctx(tmp_path, monkeypatch, idp):
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "sso.db"))
    monkeypatch.setenv("AGENTGUARD_FLASK_SECRET", "test-flask-secret-for-ci-only")
    monkeypatch.setenv("AGENTGUARD_COOKIE_SECURE", "false")
    monkeypatch.delenv("AGENTGUARD_ENVIRONMENT", raising=False)
    for k, v in {
        "AGENTGUARD_OIDC_ISSUER": ISSUER,
        "AGENTGUARD_OIDC_CLIENT_ID": CLIENT_ID,
        "AGENTGUARD_OIDC_CLIENT_SECRET": "s3cret",
        "AGENTGUARD_OIDC_ALLOWED_DOMAINS": "acme.example",
        "AGENTGUARD_PUBLIC_URL": "https://cerbere.acme.example",
    }.items():
        monkeypatch.setenv(k, v)

    from collector.app import create_app
    from collector.db import init_db, init_identity_tables

    init_db()
    init_identity_tables()
    app = create_app()
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False
    return app


def _admin(email="admin@acme.example"):
    from collector import cli

    sys.stdin = io.StringIO("correct-horse-battery\n")
    try:
        assert (
            cli.main(
                ["create-admin", "--email", email, "--org", "ACME", "--password-stdin"]
            )
            == 0
        )
    finally:
        sys.stdin = sys.__stdin__


def _user(email):
    from collector.auth.oidc import ensure_oidc_columns
    from collector.auth.users import _db_execute

    ensure_oidc_columns()

    return _db_execute(
        "SELECT user_id, org_id, role, active, oidc_issuer, oidc_sub FROM users WHERE LOWER(email) = ?",
        (email,),
        fetchone=True,
    )


def _login_start(c):
    r = c.get("/auth/sso/login")
    assert r.status_code == 302, r.status_code
    loc = urlparse(r.headers["Location"])
    return r, parse_qs(loc.query)


def roundtrip(c, idp, state_override=None, **mint_kwargs):
    _, q = _login_start(c)
    nonce = mint_kwargs.pop("nonce", q["nonce"][0])  # permet de simuler un nonce rejoué
    idp.token = idp.mint(nonce, **mint_kwargs)
    state = state_override if state_override is not None else q["state"][0]
    return c.get(f"/auth/sso/callback?code=abc&state={state}")


def logged_in(r):
    return r.status_code == 302 and "ag_auth=" in r.headers.get("Set-Cookie", "")


# ── Flux nominal ──────────────────────────────────────────────────────────


def test_authorization_request_has_pkce_state_nonce(app_ctx, idp):
    with app_ctx.test_client() as c:
        r, q = _login_start(c)
        assert r.headers["Location"].startswith(ISSUER + "/authorize?")
        assert q["response_type"] == ["code"]
        assert q["client_id"] == [CLIENT_ID]
        assert q["code_challenge_method"] == ["S256"]
        assert q["redirect_uri"] == ["https://cerbere.acme.example/auth/sso/callback"]
        assert q["state"][0] and q["nonce"][0]
        assert "ag_oidc=" in r.headers["Set-Cookie"]

        idp.token = idp.mint(q["nonce"][0])
        c.get(f"/auth/sso/callback?code=abc&state={q['state'][0]}")
        sent = idp.posted[-1]
        challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(sent["code_verifier"].encode()).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        assert challenge == q["code_challenge"][0]
        assert sent["code"] == "abc"


def test_sso_login_provisions_user_in_existing_org(app_ctx, idp):
    _admin()
    admin_org = _user("admin@acme.example")[1]
    with app_ctx.test_client() as c:
        r = roundtrip(c, idp)
        assert logged_in(r)
        row = _user("jane@acme.example")
        assert row is not None
        assert row[1] == admin_org  # même organisation, pas de workspace séparé
        assert row[2] == "viewer"
        assert (row[4], row[5]) == (ISSUER, "sub-jane")
        assert c.get("/").status_code == 200  # session valide


def test_second_login_reuses_same_user(app_ctx, idp):
    _admin()
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp))
        first = _user("jane@acme.example")[0]
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp, email="jane.renamed@acme.example"))
    assert _user("jane@acme.example")[0] == first  # retrouvé par (issuer, sub)
    assert _user("jane.renamed@acme.example") is None


# ── Rejets ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kwargs",
    [
        {"key": "other"},  # mauvaise clé de signature
        {"exp": int(time.time()) - 3600},  # expiré
        {"aud": "someone-else"},  # mauvaise audience
        {"iss": "https://evil.example.com"},  # mauvais émetteur
        {"nonce": "not-the-nonce"},  # nonce rejoué
        {"alg": "HS256"},  # confusion d'algorithme
        {"alg": "none"},  # jeton non signé
        {"email": "mallory@evil.example"},  # domaine non autorisé
        {"email_verified": False},  # email non vérifié
        {"email": None, "email_verified": True},  # pas d'email
    ],
)
def test_invalid_tokens_are_rejected(app_ctx, idp, kwargs):
    _admin()
    kwargs = dict(kwargs)
    if kwargs.get("key") == "other":
        kwargs["key"] = idp.other_key
    with app_ctx.test_client() as c:
        r = roundtrip(c, idp, **kwargs)
        assert r.status_code == 401
        assert "ag_auth=" not in r.headers.get("Set-Cookie", "")
    assert _user("jane@acme.example") is None
    assert _user("mallory@evil.example") is None


def test_state_mismatch_rejected(app_ctx, idp):
    _admin()
    with app_ctx.test_client() as c:
        r = roundtrip(c, idp, state_override="forged-state")
        assert r.status_code == 400
        assert "ag_auth=" not in r.headers.get("Set-Cookie", "")


def test_callback_without_login_cookie_rejected(app_ctx, idp):
    _admin()
    with app_ctx.test_client() as c:
        assert c.get("/auth/sso/callback?code=abc&state=x").status_code == 400


def test_idp_error_parameter_rejected(app_ctx, idp):
    with app_ctx.test_client() as c:
        _login_start(c)
        r = c.get("/auth/sso/callback?error=access_denied&error_description=nope")
        assert r.status_code == 401


def test_no_organization_yet_is_rejected(app_ctx, idp):
    with (
        app_ctx.test_client() as c
    ):  # aucune organisation : create-admin pas encore lancé
        assert roundtrip(c, idp).status_code == 401
    assert _user("jane@acme.example") is None


def test_several_orgs_without_org_id_is_rejected(app_ctx, idp):
    _admin("a@acme.example")
    _admin("b@other.example")
    with app_ctx.test_client() as c:
        assert roundtrip(c, idp).status_code == 401


def test_org_id_selects_target_org(app_ctx, idp, monkeypatch):
    _admin("a@acme.example")
    _admin("b@other.example")
    org_b = _user("b@other.example")[1]
    monkeypatch.setenv("AGENTGUARD_OIDC_ORG_ID", org_b)
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp))
    assert _user("jane@acme.example")[1] == org_b


def test_inactive_user_rejected(app_ctx, idp):
    _admin()
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp))
    from collector.auth.users import _db_execute

    _db_execute("UPDATE users SET active = 0 WHERE email = 'jane@acme.example'")
    with app_ctx.test_client() as c:
        assert roundtrip(c, idp).status_code == 401


# ── Rattachement des comptes existants ────────────────────────────────────


def test_existing_account_linked_by_verified_email(app_ctx, idp):
    _admin("jane@acme.example")  # compte local existant (admin)
    before = _user("jane@acme.example")
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp))
    after = _user("jane@acme.example")
    assert after[0] == before[0]
    assert (after[4], after[5]) == (ISSUER, "sub-jane")


def test_account_linked_to_other_identity_is_not_taken_over(app_ctx, idp):
    _admin("jane@acme.example")
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp))  # lie sub-jane
    with app_ctx.test_client() as c:
        r = roundtrip(c, idp, sub="sub-attacker")  # même email, autre identité
        assert r.status_code == 401
        assert "ag_auth=" not in r.headers.get("Set-Cookie", "")


def test_email_of_other_org_is_not_linked(app_ctx, idp, monkeypatch):
    _admin("a@acme.example")
    _admin("jane@acme.example")  # crée une 2e organisation pour jane
    org_a = _user("a@acme.example")[1]
    monkeypatch.setenv("AGENTGUARD_OIDC_ORG_ID", org_a)
    with app_ctx.test_client() as c:
        assert roundtrip(c, idp).status_code == 401


# ── Rôles ─────────────────────────────────────────────────────────────────


def test_group_to_role_mapping_and_sync(app_ctx, idp, monkeypatch):
    _admin()
    monkeypatch.setenv(
        "AGENTGUARD_OIDC_GROUP_ROLE_MAP",
        "sec-admins=admin, devs=developer, bogus=superuser",
    )
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp, groups=["devs", "sec-admins"]))
    assert _user("jane@acme.example")[2] == "admin"  # le plus haut rôle l'emporte
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp, groups=["devs"]))
    assert _user("jane@acme.example")[2] == "developer"
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp, groups=[]))
    assert _user("jane@acme.example")[2] == "viewer"  # l'IdP fait foi


def test_default_role_applies_without_mapping(app_ctx, idp, monkeypatch):
    _admin()
    monkeypatch.setenv("AGENTGUARD_OIDC_DEFAULT_ROLE", "auditor")
    with app_ctx.test_client() as c:
        assert logged_in(roundtrip(c, idp))
    assert _user("jane@acme.example")[2] == "auditor"


def test_wildcard_domain_and_unverified_allowed_when_configured(
    app_ctx, idp, monkeypatch
):
    _admin()
    monkeypatch.setenv("AGENTGUARD_OIDC_ALLOWED_DOMAINS", "*")
    monkeypatch.setenv("AGENTGUARD_OIDC_REQUIRE_EMAIL_VERIFIED", "false")
    with app_ctx.test_client() as c:
        assert logged_in(
            roundtrip(c, idp, email="x@anywhere.example", email_verified=None)
        )


# ── Configuration et interface ────────────────────────────────────────────


def test_login_page_shows_real_sso_button_and_no_dead_links(app_ctx):
    with app_ctx.test_client() as c:
        html = c.get("/login").data.decode()
        assert 'href="/auth/sso/login"' in html
        assert "Sign in with company SSO" in html
        assert "ENTERPRISE SSO" not in html
        assert "/auth/google" not in html and "/auth/github" not in html


def test_custom_button_label(app_ctx, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_OIDC_BUTTON_LABEL", "Okta")
    with app_ctx.test_client() as c:
        assert "Sign in with Okta" in c.get("/login").data.decode()


def test_sso_not_configured_hides_button_and_returns_404(app_ctx, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_OIDC_ISSUER")
    with app_ctx.test_client() as c:
        assert 'href="/auth/sso/login"' not in c.get("/login").data.decode()
        assert c.get("/auth/sso/login").status_code == 404
        assert c.get("/auth/sso/callback?code=a&state=b").status_code == 404


@pytest.mark.parametrize(
    "var,value",
    [
        ("AGENTGUARD_OIDC_ALLOWED_DOMAINS", ""),  # domaines obligatoires
        ("AGENTGUARD_OIDC_ISSUER", "http://idp.internal"),  # http refusé par défaut
    ],
)
def test_misconfiguration_disables_sso(app_ctx, monkeypatch, var, value):
    monkeypatch.setenv(var, value)
    with app_ctx.test_client() as c:
        assert 'href="/auth/sso/login"' not in c.get("/login").data.decode()
        assert c.get("/auth/sso/login").status_code == 404


def test_enforce_sso_hides_password_and_magic_link(app_ctx, monkeypatch):
    import collector.auth.config as cfg

    monkeypatch.setattr(cfg, "PASSWORD_LOGIN_ENABLED", False)
    monkeypatch.setattr(cfg, "MAGIC_LINK_ENABLED", False)
    with app_ctx.test_client() as c:
        html = c.get("/login").data.decode()
        assert 'action="/auth/password"' not in html
        assert 'id="email-form"' not in html
        assert 'href="/auth/sso/login"' in html


def test_signup_link_hidden_when_signup_disabled(app_ctx, monkeypatch):
    import collector.auth.config as cfg

    monkeypatch.setattr(cfg, "SIGNUP_ENABLED", False)
    with app_ctx.test_client() as c:
        assert 'href="/signup"' not in c.get("/login").data.decode()


def test_discovery_issuer_mismatch_fails_safely(app_ctx, idp):
    idp.issuer_in_metadata = "https://evil.example.com"
    with app_ctx.test_client() as c:
        assert c.get("/auth/sso/login").status_code == 502


def test_password_and_sso_pages_coexist(app_ctx):
    with app_ctx.test_client() as c:
        html = c.get("/login").data.decode()
        assert 'action="/auth/password"' in html
        assert 'id="email-form"' in html
