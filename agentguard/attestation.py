"""Portable signed evidence bundles using canonical JSON and optional Ed25519."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


def build_attestation(
    events: list[dict[str, Any]], *, subject: str, created_at: float,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "schema_version": "1.0", "subject": subject, "created_at": created_at,
        "event_count": len(events), "events": events, "metadata": metadata or {},
    }
    digest = hashlib.sha256(canonical_bytes(body)).hexdigest()
    return {"payload": body, "sha256": digest, "signature": None, "signature_algorithm": None}


def sign_attestation(bundle: dict[str, Any], private_key: bytes) -> dict[str, Any]:
    """Sign with a raw Ed25519 private key; requires optional cryptography dependency."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise RuntimeError("Install cryptography to sign attestations") from exc
    payload = bundle.get("payload")
    if not isinstance(payload, dict) or hashlib.sha256(canonical_bytes(payload)).hexdigest() != bundle.get("sha256"):
        raise ValueError("Attestation digest mismatch")
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    signed = dict(bundle)
    signed["signature"] = key.sign(bytes.fromhex(bundle["sha256"])).hex()
    signed["signature_algorithm"] = "Ed25519"
    return signed


def verify_attestation(bundle: dict[str, Any], public_key: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        payload = bundle["payload"]
        digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        if digest != bundle.get("sha256") or bundle.get("signature_algorithm") != "Ed25519":
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(bundle["signature"]), bytes.fromhex(digest)
        )
        return True
    except Exception:
        return False
