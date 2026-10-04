"""Helpers cryptographiques, temps et validation d'email."""

import hashlib
import secrets
from datetime import datetime, timezone


def safe_compare(a: str, b: str) -> bool:
    if not a or not b:
        return False

    try:
        return secrets.compare_digest(
            str(a).encode("utf-8"),
            str(b).encode("utf-8"),
        )
    except Exception:
        return False


def hash_key(key: str) -> str:
    return hashlib.sha256(
        str(key).encode("utf-8")
    ).hexdigest()


def _hash_magic_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_datetime(value):
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    value = str(value)

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except Exception:
        return None


def _normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def _valid_email(email: str) -> bool:
    email = _normalize_email(email)

    if len(email) < 5 or len(email) > 254:
        return False

    if "@" not in email:
        return False

    local, domain = email.rsplit("@", 1)

    if not local or not domain:
        return False

    if "." not in domain:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    return True
