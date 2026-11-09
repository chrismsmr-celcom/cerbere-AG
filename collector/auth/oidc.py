"""SSO d'entreprise via OpenID Connect (code d'autorisation + PKCE).

Fonctionne avec tout fournisseur OIDC : Okta, Microsoft Entra ID, Google
Workspace, Keycloak, Auth0, Authentik... Indépendant de Supabase : utilisable
en self-hosted comme en cloud.

Un fournisseur d'identité par instance, configuré par variables d'environnement
(voir docs/SELF_HOSTING.md) :

    AGENTGUARD_OIDC_ISSUER           https://acme.okta.com   (obligatoire)
    AGENTGUARD_OIDC_CLIENT_ID        ...                      (obligatoire)
    AGENTGUARD_OIDC_CLIENT_SECRET    ...                      (obligatoire)
    AGENTGUARD_OIDC_ALLOWED_DOMAINS  acme.com,acme.io | *     (obligatoire)
    AGENTGUARD_OIDC_SCOPES           "openid email profile"
    AGENTGUARD_OIDC_DEFAULT_ROLE     viewer
    AGENTGUARD_OIDC_GROUPS_CLAIM     groups
    AGENTGUARD_OIDC_GROUP_ROLE_MAP   "cerbere-admins=admin,cerbere-devs=developer"
    AGENTGUARD_OIDC_REQUIRE_EMAIL_VERIFIED  true
    AGENTGUARD_OIDC_ORG_ID           (optionnel si l'instance n'a qu'une organisation)
    AGENTGUARD_OIDC_BUTTON_LABEL     "company SSO"
    AGENTGUARD_OIDC_ALLOW_HTTP       false (http:// uniquement pour un IdP interne de test)

Garanties de sécurité :
  - state + nonce + PKCE (S256) ;
  - signature de l'id_token vérifiée avec les clés publiques du fournisseur
    (algorithmes asymétriques uniquement, jamais HS*/none), plus iss, aud,
    exp, iat et nonce ;
  - l'utilisateur est identifié par (issuer, sub), pas par l'email seul ;
  - un compte existant n'est rattaché par email que si le fournisseur affirme
    que l'adresse est vérifiée et que le compte appartient à la même organisation ;
  - l'utilisateur est créé dans l'organisation existante : pas de workspace
    séparé par personne.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field

import jwt
import requests
import structlog

from collector.db import is_postgres, sql_placeholder
from collector.migrations import ensure_migrated

from .users import _db_execute, _user_by_email
from .utils import _normalize_email

logger = structlog.get_logger("agentguard.auth.oidc")

ALLOWED_ALGS = [
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
]
ROLE_RANK = {"viewer": 0, "auditor": 1, "developer": 2, "admin": 3}
_HTTP_TIMEOUT = 8
_CACHE_TTL = 3600


class OidcError(Exception):
    """Échec d'authentification SSO (message pour les logs, jamais pour l'utilisateur)."""


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str
    scopes: str
    allowed_domains: frozenset
    default_role: str
    groups_claim: str
    group_role_map: dict = field(default_factory=dict)
    require_email_verified: bool = True
    org_id: str | None = None
    button_label: str = "company SSO"
    allow_http: bool = False


_warned: set[str] = set()


def _warn_once(key: str, **kw) -> None:
    if key not in _warned:
        _warned.add(key)
        logger.error(key, **kw)


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _truthy(value, default: bool) -> bool:
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def get_config() -> OidcConfig | None:
    """Config lue à chaque appel. None = SSO désactivé ou mal configuré."""
    issuer = _env("AGENTGUARD_OIDC_ISSUER").rstrip("/")
    client_id = _env("AGENTGUARD_OIDC_CLIENT_ID")
    client_secret = _env("AGENTGUARD_OIDC_CLIENT_SECRET")
    if not (issuer and client_id and client_secret):
        return None

    allow_http = _truthy(os.environ.get("AGENTGUARD_OIDC_ALLOW_HTTP"), False)
    if not issuer.startswith("https://") and not allow_http:
        _warn_once("oidc_disabled_issuer_not_https", issuer=issuer)
        return None

    domains = frozenset(
        d.strip().lower().lstrip("@")
        for d in _env("AGENTGUARD_OIDC_ALLOWED_DOMAINS").split(",")
        if d.strip()
    )
    if not domains:
        _warn_once(
            "oidc_disabled_no_allowed_domains",
            hint="set AGENTGUARD_OIDC_ALLOWED_DOMAINS (e.g. acme.com) or * to accept any verified email",
        )
        return None

    default_role = _env("AGENTGUARD_OIDC_DEFAULT_ROLE", "viewer").lower()
    if default_role not in ROLE_RANK:
        _warn_once("oidc_invalid_default_role", value=default_role)
        default_role = "viewer"

    role_map: dict[str, str] = {}
    for item in _env("AGENTGUARD_OIDC_GROUP_ROLE_MAP").split(","):
        if "=" not in item:
            continue
        group, role = (x.strip() for x in item.split("=", 1))
        if group and role.lower() in ROLE_RANK:
            role_map[group] = role.lower()

    return OidcConfig(
        issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        scopes=_env("AGENTGUARD_OIDC_SCOPES", "openid email profile"),
        allowed_domains=domains,
        default_role=default_role,
        groups_claim=_env("AGENTGUARD_OIDC_GROUPS_CLAIM", "groups"),
        group_role_map=role_map,
        require_email_verified=_truthy(
            os.environ.get("AGENTGUARD_OIDC_REQUIRE_EMAIL_VERIFIED"), True
        ),
        org_id=_env("AGENTGUARD_OIDC_ORG_ID") or None,
        button_label=_env("AGENTGUARD_OIDC_BUTTON_LABEL", "company SSO"),
        allow_http=allow_http,
    )


# ── HTTP (isolé pour pouvoir être remplacé dans les tests) ────────────────


def _http_get(url: str) -> dict:
    resp = requests.get(
        url, timeout=_HTTP_TIMEOUT, headers={"Accept": "application/json"}
    )
    resp.raise_for_status()
    return resp.json()


def _http_post(url: str, data: dict, basic_auth: tuple | None = None) -> dict:
    resp = requests.post(
        url,
        data=data,
        auth=basic_auth,
        timeout=_HTTP_TIMEOUT,
        headers={"Accept": "application/json"},
    )
    if resp.status_code >= 400:
        raise OidcError(f"token endpoint returned HTTP {resp.status_code}")
    return resp.json()


_cache: dict = {}


def _cached(key, loader, force: bool = False):
    now = time.time()
    hit = _cache.get(key)
    if hit and not force and now - hit[0] < _CACHE_TTL:
        return hit[1]
    value = loader()
    _cache[key] = (now, value)
    return value


def _check_url(cfg: OidcConfig, url: str, what: str) -> None:
    if not (
        url.startswith("https://") or (cfg.allow_http and url.startswith("http://"))
    ):
        raise OidcError(f"{what} must be https")


def discover(cfg: OidcConfig) -> dict:
    def load():
        meta = _http_get(cfg.issuer + "/.well-known/openid-configuration")
        if str(meta.get("issuer", "")).rstrip("/") != cfg.issuer:
            raise OidcError("issuer in discovery document does not match configuration")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not meta.get(key):
                raise OidcError(f"discovery document lacks {key}")
            _check_url(cfg, meta[key], key)
        return meta

    return _cached(("meta", cfg.issuer), load)


# ── Flux d'autorisation ───────────────────────────────────────────────────


def new_login_state() -> dict:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return {
        "state": secrets.token_urlsafe(24),
        "nonce": secrets.token_urlsafe(24),
        "verifier": verifier,
        "challenge": challenge,
    }


def authorization_url(cfg: OidcConfig, meta: dict, redirect_uri: str, st: dict) -> str:
    from urllib.parse import urlencode

    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": redirect_uri,
        "scope": cfg.scopes,
        "state": st["state"],
        "nonce": st["nonce"],
        "code_challenge": st["challenge"],
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in meta["authorization_endpoint"] else "?"
    return meta["authorization_endpoint"] + sep + urlencode(params)


def exchange_code(
    cfg: OidcConfig, meta: dict, redirect_uri: str, code: str, verifier: str
) -> dict:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": cfg.client_id,
        "code_verifier": verifier,
    }
    methods = meta.get("token_endpoint_auth_methods_supported") or [
        "client_secret_basic"
    ]
    if "client_secret_post" in methods:
        data["client_secret"] = cfg.client_secret
        tokens = _http_post(meta["token_endpoint"], data)
    else:
        tokens = _http_post(
            meta["token_endpoint"], data, basic_auth=(cfg.client_id, cfg.client_secret)
        )
    if not tokens.get("id_token"):
        raise OidcError("token response has no id_token")
    return tokens


def _signing_key(meta: dict, header: dict):
    kid = header.get("kid")

    def find(jwks: dict):
        keys = jwks.get("keys") or []
        if kid:
            return next((k for k in keys if k.get("kid") == kid), None)
        return keys[0] if len(keys) == 1 else None

    jwk = find(_cached(("jwks", meta["jwks_uri"]), lambda: _http_get(meta["jwks_uri"])))
    if jwk is None:  # rotation de clés : un seul rechargement
        jwk = find(
            _cached(
                ("jwks", meta["jwks_uri"]),
                lambda: _http_get(meta["jwks_uri"]),
                force=True,
            )
        )
    if jwk is None:
        raise OidcError("no matching signing key")
    return jwt.PyJWK(jwk).key


def verify_id_token(cfg: OidcConfig, meta: dict, id_token: str, nonce: str) -> dict:
    try:
        header = jwt.get_unverified_header(id_token)
        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:
            raise OidcError(f"unsupported signing algorithm {alg!r}")
        claims = jwt.decode(
            id_token,
            _signing_key(meta, header),
            algorithms=[alg],
            audience=cfg.client_id,
            issuer=meta["issuer"],
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            leeway=30,
        )
    except OidcError:
        raise
    except jwt.PyJWTError as exc:
        raise OidcError(f"invalid id_token: {exc}") from exc

    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != cfg.client_id:
        raise OidcError("azp does not match client_id")
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OidcError("nonce mismatch")
    return claims


# ── Utilisateurs ──────────────────────────────────────────────────────────


def ensure_oidc_columns() -> None:
    """Garantit que le schéma est à jour (migration `users_oidc_identity`)."""
    ensure_migrated()


def _is_true(value) -> bool:
    return value is True or str(value).strip().lower() == "true"


def _claim_email(claims: dict) -> str:
    for name in ("email", "preferred_username", "upn"):
        value = _normalize_email(str(claims.get(name) or ""))
        if "@" in value:
            return value
    return ""


def _role_for(claims: dict, cfg: OidcConfig) -> tuple[str, bool]:
    """(rôle, synchroniser). Avec une table groupe->rôle, l'IdP fait foi à chaque connexion."""
    if not cfg.group_role_map:
        return cfg.default_role, False
    raw = claims.get(cfg.groups_claim) or []
    groups = [raw] if isinstance(raw, str) else [str(g) for g in raw]
    best = cfg.default_role
    for g in groups:
        role = cfg.group_role_map.get(g)
        if role and ROLE_RANK[role] > ROLE_RANK[best]:
            best = role
    return best, True


def _target_org(cfg: OidcConfig):
    p = sql_placeholder()
    if cfg.org_id:
        row = _db_execute(
            f"SELECT org_id, tenant_id FROM orgs WHERE org_id = {p}",
            (cfg.org_id,),
            fetchone=True,
        )
        if not row:
            raise OidcError("AGENTGUARD_OIDC_ORG_ID does not match any organization")
        return row[0], row[1]
    rows = _db_execute("SELECT org_id, tenant_id FROM orgs LIMIT 2", fetchall=True)
    if not rows:
        raise OidcError(
            "no organization yet: run `python -m collector.cli create-admin` first"
        )
    if len(rows) > 1:
        raise OidcError("several organizations exist: set AGENTGUARD_OIDC_ORG_ID")
    return rows[0][0], rows[0][1]


_USER_COLS = "user_id, org_id, tenant_id, email, display_name, role, active"


def resolve_user(cfg: OidcConfig, claims: dict):
    """Retourne le tuple user (7 colonnes) à connecter, ou lève OidcError."""
    email = _claim_email(claims)
    if not email:
        raise OidcError("id_token carries no usable email")
    domain = email.rsplit("@", 1)[-1]
    if "*" not in cfg.allowed_domains and domain not in cfg.allowed_domains:
        raise OidcError(f"email domain {domain!r} is not allowed")
    if cfg.require_email_verified and not _is_true(claims.get("email_verified")):
        raise OidcError("email is not verified by the identity provider")

    ensure_oidc_columns()
    issuer = cfg.issuer
    sub = str(claims["sub"])
    org_id, tenant_id = _target_org(cfg)
    role, sync_role = _role_for(claims, cfg)
    p = sql_placeholder()

    row = _db_execute(
        f"SELECT {_USER_COLS} FROM users WHERE oidc_issuer = {p} AND oidc_sub = {p}",
        (issuer, sub),
        fetchone=True,
    )
    if row:
        if row[1] != org_id:
            raise OidcError("linked account belongs to another organization")
        user = row
    else:
        existing = _user_by_email(email)
        if existing:
            if existing[1] != org_id:
                raise OidcError(
                    "an account with this email belongs to another organization"
                )
            linked = _db_execute(
                f"SELECT oidc_issuer, oidc_sub FROM users WHERE user_id = {p}",
                (existing[0],),
                fetchone=True,
            )
            if linked and linked[1] and (linked[0], linked[1]) != (issuer, sub):
                raise OidcError("account is already linked to a different SSO identity")
            _db_execute(
                f"UPDATE users SET oidc_issuer = {p}, oidc_sub = {p} WHERE user_id = {p}",
                (issuer, sub, existing[0]),
            )
            user = existing
        else:
            user_id = str(uuid.uuid4())
            display = str(claims.get("name") or email.split("@", 1)[0])
            _db_execute(
                f"INSERT INTO users (user_id, org_id, tenant_id, email, display_name, "
                f"role, active, oidc_issuer, oidc_sub, created_at) "
                f"VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, CURRENT_TIMESTAMP)",
                (
                    user_id,
                    org_id,
                    tenant_id,
                    email,
                    display,
                    role,
                    True if is_postgres() else 1,
                    issuer,
                    sub,
                ),
            )
            logger.info(
                "sso_user_provisioned", user_id=user_id, org_id=org_id, role=role
            )
            user = (user_id, org_id, tenant_id, email, display, role, True)

    if not bool(user[6]):
        raise OidcError("account is disabled")

    if sync_role and user[5] != role:
        _db_execute(f"UPDATE users SET role = {p} WHERE user_id = {p}", (role, user[0]))
        logger.info("sso_role_synced", user_id=user[0], old=user[5], new=role)
        user = (user[0], user[1], user[2], user[3], user[4], role, user[6])
    return user
