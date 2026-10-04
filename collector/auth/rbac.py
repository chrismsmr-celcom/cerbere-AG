"""RBAC : autorisation de ressource, require_role, require_permission."""

from functools import wraps
from typing import Optional

import structlog
from flask import jsonify

from .identity_resolution import resolve_full_identity
from .middleware import require_auth

logger = structlog.get_logger("agentguard.auth")


def authorize_resource_access(
    target_tenant_id: str,
    target_org_id: Optional[str] = None,
    allow_cross_org: bool = False,
) -> bool:
    try:
        from identity import (
            IdentityType,
            Role,
        )
    except ImportError:
        return False

    identity = resolve_full_identity()

    if not identity:
        return False

    if identity.identity_type == IdentityType.SYSTEM:
        return True

    if identity.tenant_id != target_tenant_id:
        logger.warning(
            "authz_denied_cross_tenant",
            actor_tenant=identity.tenant_id,
            target_tenant=target_tenant_id,
        )
        return False

    if target_org_id is None:
        return identity.role == Role.ADMIN

    if identity.role == Role.ADMIN:
        return True

    if not allow_cross_org:
        return identity.org_id == target_org_id

    return True


def require_role(*required_roles: str):
    try:
        from identity import Role

        required = [
            Role(r)
            for r in required_roles
        ]

    except (ImportError, ValueError):
        required = []

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not require_auth():
                return jsonify(
                    {"error": "Unauthorized"}
                ), 401

            if not required:
                return func(*args, **kwargs)

            identity = resolve_full_identity()

            if not identity:
                return jsonify(
                    {"error": "Identity not resolved"}
                ), 401

            for role in required:
                try:
                    if identity.has_role(role):
                        return func(
                            *args,
                            **kwargs,
                        )
                except Exception:
                    if identity.role == role:
                        return func(
                            *args,
                            **kwargs,
                        )

            return jsonify(
                {
                    "error": "Forbidden",
                    "required_roles": [
                        r.value
                        if hasattr(r, "value")
                        else str(r)
                        for r in required
                    ],
                    "your_role": (
                        identity.role.value
                        if hasattr(
                            identity.role,
                            "value",
                        )
                        else str(identity.role)
                    ),
                }
            ), 403

        return wrapper

    return decorator


def require_permission(permission: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not require_auth():
                return jsonify(
                    {"error": "Unauthorized"}
                ), 401

            identity = resolve_full_identity()

            if not identity:
                return jsonify(
                    {"error": "Identity not resolved"}
                ), 401

            try:
                from identity import role_has_permission

                if not role_has_permission(
                    identity.role,
                    permission,
                ):
                    return jsonify(
                        {
                            "error": "Forbidden",
                            "required_permission": permission,
                            "your_role": (
                                identity.role.value
                                if hasattr(
                                    identity.role,
                                    "value",
                                )
                                else str(
                                    identity.role
                                )
                            ),
                        }
                    ), 403

            except ImportError:
                pass

            return func(
                *args,
                **kwargs,
            )

        return wrapper

    return decorator
