"""Licences signées (Ed25519), vérifiées hors ligne.

Modèle commercial (open-core)
-----------------------------
Le collector est complet pour tout le monde : détection, dashboard, approbations
humaines, journal d'audit, clés API, alertes. Une licence payante n'enlève rien
au plan gratuit : elle AJOUTE ce qui sert une équipe ou une entreprise
(SSO, conformité, export SIEM, rétention longue, multi-workspace, support).

    Community  -> aucun fichier de licence (gratuit)
    Pro        -> licence signée, plan "pro"
    Team       -> licence signée, plan "team"
    Enterprise -> licence signée, plan "enterprise"

Principes
---------
- Aucune connexion réseau : la signature est vérifiée avec une clé publique
  embarquée (PUBLIC_KEYS). Marche en air-gapped.
- La sécurité de base n'est JAMAIS dégradée par l'état de la licence : à
  l'expiration, seules les fonctions payantes s'arrêtent. La détection, le
  blocage et la connexion par mot de passe continuent de fonctionner.
- Après expiration, 14 jours de grâce pendant lesquels tout continue (avertissement).
- Cette vérification protège contre la falsification d'une licence, pas contre un
  client qui modifierait le code source : le reste repose sur le contrat.

Format : cerbere_lic_v1.<kid>.<payload base64url>.<signature base64url>
La signature couvre "cerbere_lic_v1.<kid>.<payload base64url>".
Émission : scripts/cerbere_license.py (la clé privée ne quitte jamais votre poste).
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

logger = structlog.get_logger("agentguard.licensing")

PREFIX = "cerbere_lic_v1"
GRACE_SECONDS = 14 * 86400
CLOCK_SKEW_SECONDS = 86400

# Clés publiques de confiance : kid -> clé Ed25519 publique (32 octets, base64url sans padding).
# À renseigner avec la sortie de `python scripts/cerbere_license.py keygen`.
# Plusieurs entrées permettent de renouveler la clé sans invalider les licences existantes.
PUBLIC_KEYS: dict[str, str] = {}

COMMUNITY = "community"
PRO = "pro"
TEAM = "team"
ENTERPRISE = "enterprise"
PLAN_ORDER = [COMMUNITY, PRO, TEAM, ENTERPRISE]

# Fonctionnalité -> plan minimal.
# Seules celles marquées "en vigueur" sont réellement vérifiées dans le code aujourd'hui ;
# les autres réservent leur place dans la grille tarifaire pour quand elles existeront.
FEATURES: dict[str, str] = {
    "sso_oidc": TEAM,  # en vigueur : bouton SSO d'entreprise (collector/auth/oidc.py)
    "extended_retention": PRO,  # prévu : rétention et export longs des journaux d'audit
    "compliance_reports": TEAM,  # en vigueur : rapport de conformité PDF (collector/compliance_report.py)
    "siem_export": TEAM,  # prévu : export Splunk / Datadog / syslog
    "multi_workspace": TEAM,  # prévu : plusieurs workspaces par instance
}


class LicenseError(ValueError):
    """Licence illisible, mal signée ou incohérente (message pour l'administrateur)."""


@dataclass(frozen=True)
class License:
    license_id: str
    customer: str
    plan: str
    issued_at: int
    expires_at: int
    extra_features: tuple = ()
    limits: dict = field(default_factory=dict)
    kid: str = ""


@dataclass(frozen=True)
class LicenseState:
    status: str  # community | active | grace | expired | invalid
    plan: str  # plan effectif (community si expirée ou invalide)
    license: License | None
    message: str
    features: frozenset
    days_left: int | None = None


# ── Encodage ──────────────────────────────────────────────────────────────


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise LicenseError("license is not valid base64") from exc


def _signing_input(kid: str, payload_b64: str) -> bytes:
    return f"{PREFIX}.{kid}.{payload_b64}".encode()


# ── Émission (utilisée par scripts/cerbere_license.py et les tests) ───────


def generate_keypair() -> tuple[str, str]:
    """(clé privée, clé publique), 32 octets chacune en base64url."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64e(private), _b64e(public)


def sign_license(private_key_b64: str, kid: str, payload: dict) -> str:
    key = Ed25519PrivateKey.from_private_bytes(_b64d(private_key_b64))
    payload_b64 = _b64e(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    signature = key.sign(_signing_input(kid, payload_b64))
    return f"{PREFIX}.{kid}.{payload_b64}.{_b64e(signature)}"


# ── Vérification ──────────────────────────────────────────────────────────


def _rank(plan: str) -> int:
    return PLAN_ORDER.index(plan)


def _parse_payload(data: dict, kid: str) -> License:
    try:
        plan = str(data["plan"]).lower()
        if plan not in PLAN_ORDER or plan == COMMUNITY:
            raise LicenseError(f"unknown plan {plan!r}")
        lic = License(
            license_id=str(data["id"]),
            customer=str(data["customer"]),
            plan=plan,
            issued_at=int(data["issued_at"]),
            expires_at=int(data["expires_at"]),
            extra_features=tuple(str(f) for f in data.get("features", [])),
            limits=dict(data.get("limits", {})),
            kid=kid,
        )
    except KeyError as exc:
        raise LicenseError(f"license payload lacks {exc.args[0]!r}") from exc
    except (TypeError, ValueError) as exc:
        raise LicenseError(f"license payload is malformed: {exc}") from exc
    if lic.expires_at <= lic.issued_at:
        raise LicenseError("license expires before it was issued")
    return lic


@lru_cache(maxsize=64)
def _verify(token: str, keys: tuple) -> License:
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != PREFIX:
        raise LicenseError("not a Cerbere license key (expected cerbere_lic_v1.…)")
    _, kid, payload_b64, sig_b64 = parts
    trusted = dict(keys).get(kid)
    if not trusted:
        raise LicenseError(
            "this license was signed with a key this build does not trust"
            if keys
            else "no licensing public key is configured in this build"
        )
    try:
        public = Ed25519PublicKey.from_public_bytes(_b64d(trusted))
        public.verify(_b64d(sig_b64), _signing_input(kid, payload_b64))
    except InvalidSignature as exc:
        raise LicenseError(
            "license signature is invalid (key altered or corrupted)"
        ) from exc
    try:
        data = json.loads(_b64d(payload_b64))
    except ValueError as exc:
        raise LicenseError("license payload is not valid JSON") from exc
    if not isinstance(data, dict):
        raise LicenseError("license payload must be an object")
    return _parse_payload(data, kid)


def verify_license(token: str) -> License:
    """Retourne la licence si la signature est valide ; lève LicenseError sinon."""
    return _verify(token.strip(), tuple(sorted(PUBLIC_KEYS.items())))


def _features_for(plan: str, extra: tuple = ()) -> frozenset:
    base = {name for name, minimum in FEATURES.items() if _rank(plan) >= _rank(minimum)}
    return frozenset(base | set(extra))


def evaluate(token: str | None, now: float | None = None) -> LicenseState:
    """Calcule l'état effectif à partir d'une clé (ou de l'absence de clé)."""
    now = time.time() if now is None else now
    community = LicenseState(
        COMMUNITY, COMMUNITY, None, "Community edition", frozenset()
    )
    if not token or not token.strip():
        return community

    try:
        lic = verify_license(token)
    except LicenseError as exc:
        return LicenseState(
            "invalid", COMMUNITY, None, f"License ignored: {exc}", frozenset()
        )

    if lic.issued_at > now + CLOCK_SKEW_SECONDS:
        return LicenseState(
            "invalid",
            COMMUNITY,
            None,
            "License ignored: it is not valid yet",
            frozenset(),
        )

    days_left = int((lic.expires_at - now) // 86400)
    if now <= lic.expires_at:
        return LicenseState(
            "active",
            lic.plan,
            lic,
            f"{lic.plan.title()} license for {lic.customer}",
            _features_for(lic.plan, lic.extra_features),
            days_left,
        )
    if now <= lic.expires_at + GRACE_SECONDS:
        left = int((lic.expires_at + GRACE_SECONDS - now) // 86400)
        return LicenseState(
            "grace",
            lic.plan,
            lic,
            f"License expired; paid features stay on for {left} more day(s). Renew now.",
            _features_for(lic.plan, lic.extra_features),
            days_left,
        )
    return LicenseState(
        "expired",
        COMMUNITY,
        lic,
        "License expired: running as Community. Detection and blocking are unaffected.",
        frozenset(),
        days_left,
    )


# ── Chargement ────────────────────────────────────────────────────────────


def _read_token() -> str | None:
    token = (os.environ.get("AGENTGUARD_LICENSE_KEY") or "").strip()
    if token:
        return token
    path = (os.environ.get("AGENTGUARD_LICENSE_FILE") or "").strip()
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip() or None
        except FileNotFoundError:
            return None
        except OSError as exc:
            _warn_once(f"license_file_unreadable:{path}", error=str(exc))
    return None


_warned: set[str] = set()


def _warn_once(key: str, **kw) -> None:
    if key not in _warned:
        _warned.add(key)
        logger.warning(key.split(":")[0], **kw)


def current() -> LicenseState:
    """État de licence de cette instance (relu à chaque appel : pas de redémarrage requis)."""
    state = evaluate(_read_token())
    if state.status in {"invalid", "expired", "grace"}:
        _warn_once(f"license_{state.status}:{state.message}", message=state.message)
    return state


def has_feature(name: str) -> bool:
    return name in current().features


def status_dict() -> dict:
    """Résumé affichable (API, CLI, logs). Ne contient jamais la clé ni la signature."""
    state = current()
    lic = state.license

    def iso(ts: int) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")

    return {
        "status": state.status,
        "plan": state.plan,
        "message": state.message,
        "customer": lic.customer if lic else None,
        "license_id": lic.license_id if lic else None,
        "expires_on": iso(lic.expires_at) if lic else None,
        "days_left": state.days_left,
        "features": sorted(state.features),
        "limits": dict(lic.limits)
        if lic and state.status in {"active", "grace"}
        else {},
    }


def log_status() -> None:
    """Une ligne de journal au démarrage : plan et échéance (jamais la clé)."""
    info = status_dict()
    logger.info(
        "license_status",
        plan=info["plan"],
        status=info["status"],
        customer=info["customer"],
        expires_on=info["expires_on"],
    )
