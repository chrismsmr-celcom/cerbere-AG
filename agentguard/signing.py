"""
Cerbere Signed Security Decisions

Ed25519 signatures:
the client cannot forge an ALLOW decision.
"""

import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

# Champs optionnels qui lient une décision à l'action exacte demandée. Ils sont
# inclus dans la charge signée : le SDK peut ainsi prouver que la décision reçue
# concerne CET outil, avec CES arguments, pour CETTE requête (anti-rejeu).
BINDING_FIELDS = ("tool_name", "agent_id", "org_id", "args_sha256", "nonce")


def params_digest(params) -> str:
    """Empreinte SHA-256 canonique des arguments d'un outil (SDK et collector)."""
    canonical = json.dumps(
        params if params is not None else {},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DecisionSigner:
    """Côté COLLECTOR : signe les décisions de sécurité."""

    def __init__(self, private_key_pem: str | None = None):
        """
        Initialize the signing key.

        Production MUST provide a persistent private key.

        Ephemeral key generation is allowed only when explicitly
        enabled for local development.
        """

        allow_ephemeral = os.getenv(
            "AGENTGUARD_ALLOW_EPHEMERAL_SIGNING_KEY",
            "false",
        ).lower() in {"1", "true", "yes", "on"}

        if private_key_pem:
            self._key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
            )

        elif allow_ephemeral:
            self._key = Ed25519PrivateKey.generate()

        else:
            raise RuntimeError(
                "Persistent signing key is required. "
                "Set AGENTGUARD_SIGNING_KEY (or legacy "
                "CERBERE_SIGNING_KEY). "
                "For local development only, explicitly set "
                "AGENTGUARD_ALLOW_EPHEMERAL_SIGNING_KEY=true."
            )

        self._public_pem = (
            self._key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def public_key_pem(self) -> str:
        """Return the public key in PEM format."""
        return self._public_pem

    def export_private_pem(self) -> str:
        """
        Export private key.

        WARNING:
        Store this only in AGENTGUARD_SIGNING_KEY or a secret manager.
        """
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def sign_decision(self, decision: dict, ttl: int | None = 300) -> dict:
        """
        Sign a security decision.

        The signed payload contains only security-authoritative fields.

        ttl: validity in seconds (runtime decisions). ``None`` = no expiry, for
        signatures that must stay verifiable for years (audit checkpoints). Such
        a payload is REJECTED by ``DecisionVerifier.verify()`` (expiry required),
        so it can never be used as a runtime decision.
        """

        now = int(time.time())

        payload = {
            "request_id": decision.get("request_id"),
            "action": decision.get("action"),
            "policy_name": decision.get("policy_name"),
            "policy_version": decision.get("policy_version"),
            "reason": decision.get("reason"),
            "issued_at": now,
        }
        if ttl is not None:
            payload["expires_at"] = now + int(ttl)

        # Liaison à l'action : seulement les champs fournis (anciens appelants OK).
        for field in BINDING_FIELDS:
            if decision.get(field) is not None:
                payload[field] = decision[field]

        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

        signature = self._key.sign(canonical.encode())

        payload["signature"] = base64.b64encode(signature).decode()

        return payload


class DecisionVerifier:
    """Côté SDK : vérifie qu'une décision vient bien du collector."""

    def __init__(self, public_key_pem: str):
        self._pub = serialization.load_pem_public_key(public_key_pem.encode())

    def verify(self, signed: dict, check_expiry: bool = True) -> bool:
        """Verify signature and expiration.

        check_expiry=False is for long-lived evidence (audit checkpoints) whose
        signature must remain verifiable after the runtime validity window.
        """

        if not isinstance(signed, dict):
            return False

        try:
            signature = base64.b64decode(
                signed.get("signature", ""),
                validate=True,
            )
        except Exception:
            return False

        if check_expiry:
            expires_at = signed.get("expires_at")

            try:
                if not expires_at:
                    return False

                if float(expires_at) < time.time():
                    return False
            except (TypeError, ValueError):
                return False

        payload = {key: value for key, value in signed.items() if key != "signature"}

        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

        try:
            self._pub.verify(
                signature,
                canonical.encode(),
            )
            return True

        except Exception:
            return False

    def verify_for(
        self,
        signed: dict,
        *,
        tool_name: str,
        params,
        nonce: str,
    ) -> bool:
        """Vérifie la signature ET que la décision concerne exactement cette action.

        Une décision valide mais émise pour un autre outil, d'autres arguments ou
        une autre requête (rejeu) est refusée. Les champs de liaison sont
        OBLIGATOIRES : une décision sans liaison n'est pas acceptée.
        """
        if not self.verify(signed):
            return False
        try:
            return (
                signed.get("tool_name") == tool_name
                and signed.get("args_sha256") == params_digest(params)
                and signed.get("nonce") == nonce
            )
        except Exception:
            return False
