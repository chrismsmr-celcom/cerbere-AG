"""Construction de l'identité résolue (agent, humain, clé système legacy)."""

import structlog
from flask import current_app, g, request

from .utils import safe_compare

logger = structlog.get_logger("agentguard.auth")


def _build_user_identity(user):
    try:
        from identity import (
            IdentityType,
            ResolvedIdentity,
            Role,
        )
    except ImportError:
        return None

    if not user:
        return None

    (
        user_id,
        org_id,
        tenant_id,
        email,
        display_name,
        role_value,
        active,
    ) = user

    if not active:
        return None

    try:
        role = Role(str(role_value).lower())
    except Exception:
        try:
            role = Role.VIEWER
        except Exception:
            role = role_value

    identity_type = None

    for candidate in (
        "USER",
        "HUMAN",
        "SESSION",
    ):
        try:
            identity_type = getattr(
                IdentityType,
                candidate,
            )
            break
        except Exception:
            continue

    if identity_type is None:
        try:
            identity_type = IdentityType.USER
        except Exception:
            return None

    kwargs = {
        "identity_type": identity_type,
        "tenant_id": tenant_id,
        "org_id": org_id,
        "subject_id": user_id,
        "role": role,
    }

    for field, value in (
        ("user_email", email),
        ("email", email),
        ("display_name", display_name),
    ):
        try:
            kwargs[field] = value
            return ResolvedIdentity(**kwargs)
        except TypeError:
            kwargs.pop(field, None)

    try:
        return ResolvedIdentity(**kwargs)
    except Exception as exc:
        logger.warning(
            "resolved_identity_build_failed",
            error=str(exc),
        )
        return None


def resolve_full_identity():
    """
    Resolve the complete identity for the current request.
    """
    try:
        from identity import (
            IdentityType,
            ResolvedIdentity,
            Role,
        )
    except ImportError:
        return None

    if getattr(g, "identity", None) is not None:
        return g.identity

    # Agent identity
    agent_info = getattr(
        g,
        "agent_identity",
        None,
    )

    if agent_info:
        try:
            identity = ResolvedIdentity(
                identity_type=IdentityType.AGENT,
                tenant_id=agent_info["tenant_id"],
                org_id=agent_info["org_id"],
                subject_id=agent_info["agent_id"],
                role=Role.DEVELOPER,
                agent_name=agent_info.get(
                    "agent_name"
                ),
            )

            g.identity = identity
            return identity

        except Exception as exc:
            logger.warning(
                "agent_resolved_identity_failed",
                error=str(exc),
            )

    # Human session
    user = getattr(
        g,
        "authenticated_user",
        None,
    )

    if user:
        identity = _build_user_identity(user)

        if identity:
            g.user_identity = identity
            g.identity = identity
            return identity

    # Legacy global system key
    api_key = current_app.config.get("API_KEY")

    key = request.headers.get(
        "X-API-Key",
        "",
    ).strip()

    if (
        api_key
        and key
        and safe_compare(key, api_key)
    ):
        environment = current_app.config.get(
            "ENVIRONMENT",
            "development",
        )

        allow_legacy = current_app.config.get(
            "ALLOW_LEGACY_SYSTEM_KEY",
            False,
        )

        if (
            environment == "production"
            and not allow_legacy
        ):
            return None

        try:
            identity = ResolvedIdentity(
                identity_type=IdentityType.SYSTEM,
                tenant_id="default",
                org_id="default",
                subject_id="system_legacy_key",
                role=Role.ADMIN,
            )

            g.identity = identity
            return identity

        except Exception:
            return None

    return None
