"""
Admin endpoints: customer management.

Security properties:

- Admin secret is accepted ONLY through X-Admin-Secret.
- Admin secrets are never accepted through query parameters.
- Customer API keys are stored hashed.
- Customer creation and revocation are audited.
- Revocation is performed by org_id and applies to all active
  API keys belonging to that organization.
"""

import os
import secrets
import sqlite3

import structlog
from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
)

from collector.auth import hash_key, safe_compare
from collector.db import get_pg_conn, is_postgres


logger = structlog.get_logger(
    "agentguard.admin"
)

admin_bp = Blueprint(
    "admin",
    __name__,
)


# ==============================================================
# SQLITE
# ==============================================================

DB_SQLITE_PATH = os.environ.get(
    "AGENTGUARD_DB_PATH",
    "/tmp/agentguard.db",
)


# ==============================================================
# ADMIN AUTHENTICATION
# ==============================================================

def _verify_admin_secret() -> bool:
    """
    Verify the administrator secret.

    SECURITY:
    The secret is accepted ONLY through:

        X-Admin-Secret: <secret>

    It is intentionally NOT accepted through:

        ?admin=<secret>

    Query parameters can leak through access logs, browser
    history, referrer headers, monitoring systems, etc.
    """

    admin_secret = current_app.config.get(
        "ADMIN_SECRET"
    )

    if not admin_secret:
        return False

    # ----------------------------------------------------------
    # ONLY ACCEPT THE HEADER
    # ----------------------------------------------------------

    provided = request.headers.get(
        "X-Admin-Secret",
        "",
    )

    # ----------------------------------------------------------
    # DETECT FORBIDDEN QUERY-PARAMETER USAGE
    # ----------------------------------------------------------

    query_secret = request.args.get("admin")

    if query_secret:
        logger.warning(
            "admin_secret_query_parameter_rejected",
            ip=request.remote_addr,
            endpoint=request.endpoint,
            user_agent=request.headers.get(
                "User-Agent",
                "",
            )[:100],
        )

        # Never accept it, even if the value is correct.
        return False

    # ----------------------------------------------------------
    # CONSTANT-TIME COMPARISON
    # ----------------------------------------------------------

    if not provided:
        return False

    return safe_compare(
        provided,
        admin_secret,
    )


# ==============================================================
# GET GLOBAL API KEY
# ==============================================================

@admin_bp.route(
    "/api/key",
    methods=["GET"],
)
def show_key():
    """
    Return the global API key.

    Admin authentication is mandatory.
    """

    if not current_app.config.get(
        "ADMIN_SECRET"
    ):
        return jsonify(
            {
                "error": (
                    "AGENTGUARD_ADMIN_SECRET "
                    "not configured"
                )
            }
        ), 404

    if not _verify_admin_secret():
        return jsonify(
            {
                "error": (
                    "Admin secret required "
                    "(X-Admin-Secret header)"
                )
            }
        ), 403

    return jsonify(
        {
            "api_key": current_app.config[
                "API_KEY"
            ]
        }
    ), 200


# ==============================================================
# CREATE CUSTOMER
# ==============================================================

@admin_bp.route(
    "/admin/customers",
    methods=["POST"],
)
def create_customer():
    """
    Create a customer organization and its API key.

    The plaintext API key is returned exactly once.
    """

    # ----------------------------------------------------------
    # ADMIN AUTH
    # ----------------------------------------------------------

    if not current_app.config.get(
        "ADMIN_SECRET"
    ):
        return jsonify(
            {
                "error": (
                    "AGENTGUARD_ADMIN_SECRET "
                    "not configured"
                )
            }
        ), 404

    if not _verify_admin_secret():
        return jsonify(
            {
                "error": "Admin secret required",
                "hint": (
                    "Use X-Admin-Secret header "
                    "(never query parameters)"
                ),
            }
        ), 403

    # ----------------------------------------------------------
    # INPUT
    # ----------------------------------------------------------

    payload = request.get_json(
        silent=True
    ) or {}

    org_name = str(
        payload.get(
            "org_name",
            "",
        )
    ).strip()

    plan = str(
        payload.get(
            "plan",
            "free",
        )
    ).strip().lower()

    if not org_name:
        return jsonify(
            {
                "error": "org_name is required"
            }
        ), 400

    if len(org_name) > 200:
        return jsonify(
            {
                "error": (
                    "org_name must be "
                    "200 characters or less"
                )
            }
        ), 400

    allowed_plans = {
        "free",
        "pro",
        "startup",
        "enterprise",
    }

    if plan not in allowed_plans:
        return jsonify(
            {
                "error": (
                    "plan must be one of: "
                    "free, pro, startup, enterprise"
                )
            }
        ), 400

    # ----------------------------------------------------------
    # GENERATE CREDENTIALS
    # ----------------------------------------------------------

    org_id = (
        "org_"
        + secrets.token_urlsafe(8)
    )

    new_key = (
        "ag_"
        + secrets.token_urlsafe(32)
    )

    key_hash = hash_key(new_key)

    # ----------------------------------------------------------
    # DATABASE INSERT
    # ----------------------------------------------------------

    try:

        if is_postgres():

            conn = get_pg_conn()

            try:
                cur = conn.cursor()

                cur.execute(
                    """
                    INSERT INTO api_keys
                        (
                            key_hash,
                            org_id,
                            org_name,
                            plan
                        )
                    VALUES
                        (
                            %s,
                            %s,
                            %s,
                            %s
                        )
                    """,
                    (
                        key_hash,
                        org_id,
                        org_name,
                        plan,
                    ),
                )

                conn.commit()

            except Exception:
                conn.rollback()
                raise

            finally:
                conn.close()

        else:

            conn = sqlite3.connect(
                DB_SQLITE_PATH
            )

            try:
                cur = conn.cursor()

                cur.execute(
                    """
                    INSERT INTO api_keys
                        (
                            key_hash,
                            org_id,
                            org_name,
                            plan
                        )
                    VALUES
                        (
                            ?,
                            ?,
                            ?,
                            ?
                        )
                    """,
                    (
                        key_hash,
                        org_id,
                        org_name,
                        plan,
                    ),
                )

                conn.commit()

            except Exception:
                conn.rollback()
                raise

            finally:
                conn.close()

    except Exception:
        logger.exception(
            "customer_creation_db_failed",
            org_id=org_id,
        )

        return jsonify(
            {
                "error": "database error"
            }
        ), 500

    # ----------------------------------------------------------
    # AUDIT
    # ----------------------------------------------------------

    try:

        from collector.audit_routes import (
            get_audit_log,
            AuditEventType,
        )

        audit = get_audit_log()

        if audit:
            audit.log_event(
                event_type=(
                    AuditEventType.API_KEY_CREATED
                ),
                org_id=org_id,
                actor="admin",
                resource=f"api_key:{org_id}",
                action="created",
                details={
                    "org_name": org_name,
                    "plan": plan,
                    "ip": request.remote_addr,
                },
                risk_level="info",
            )

    except Exception:
        logger.exception(
            "audit_log_failed",
            event="customer_created",
            org_id=org_id,
        )

    # ----------------------------------------------------------
    # LOG
    # ----------------------------------------------------------

    logger.info(
        "customer_created",
        org_id=org_id,
        org_name=org_name,
        plan=plan,
    )

    # ----------------------------------------------------------
    # RESPONSE
    # ----------------------------------------------------------

    return jsonify(
        {
            "org_id": org_id,
            "org_name": org_name,
            "plan": plan,
            "api_key": new_key,
            "warning": (
                "This API key will NEVER be shown "
                "again. Store it securely now."
            ),
        }
    ), 201


# ==============================================================
# REVOKE CUSTOMER
# ==============================================================

@admin_bp.route(
    "/admin/customers/<org_id>/revoke",
    methods=["POST"],
)
def revoke_customer(org_id):
    """
    Revoke all API keys belonging to an organization.

    Important:
    the authentication layer must check the `active` state
    on EVERY authenticated request. This endpoint changes that
    state; it does not itself invalidate an already-created
    session unless the authentication layer checks the database
    again.
    """

    # ----------------------------------------------------------
    # ADMIN AUTH
    # ----------------------------------------------------------

    if not current_app.config.get(
        "ADMIN_SECRET"
    ):
        return jsonify(
            {
                "error": (
                    "AGENTGUARD_ADMIN_SECRET "
                    "not configured"
                )
            }
        ), 404

    if not _verify_admin_secret():
        return jsonify(
            {
                "error": "Admin secret required",
                "hint": (
                    "Use X-Admin-Secret header "
                    "(never query parameters)"
                ),
            }
        ), 403

    # ----------------------------------------------------------
    # VALIDATE ORG ID
    # ----------------------------------------------------------

    org_id = str(org_id).strip()

    if not org_id:
        return jsonify(
            {
                "error": "org_id is required"
            }
        ), 400

    if len(org_id) > 128:
        return jsonify(
            {
                "error": "invalid org_id"
            }
        ), 400

    # ----------------------------------------------------------
    # REVOKE ALL KEYS
    # ----------------------------------------------------------

    try:

        if is_postgres():

            conn = get_pg_conn()

            try:
                cur = conn.cursor()

                cur.execute(
                    """
                    UPDATE api_keys
                    SET active = FALSE
                    WHERE org_id = %s
                    """,
                    (org_id,),
                )

                affected = cur.rowcount

                conn.commit()

            except Exception:
                conn.rollback()
                raise

            finally:
                conn.close()

        else:

            conn = sqlite3.connect(
                DB_SQLITE_PATH
            )

            try:
                cur = conn.cursor()

                cur.execute(
                    """
                    UPDATE api_keys
                    SET active = 0
                    WHERE org_id = ?
                    """,
                    (org_id,),
                )

                affected = cur.rowcount

                conn.commit()

            except Exception:
                conn.rollback()
                raise

            finally:
                conn.close()

    except Exception:
        logger.exception(
            "customer_revocation_db_failed",
            org_id=org_id,
        )

        return jsonify(
            {
                "error": "database error"
            }
        ), 500

    # ----------------------------------------------------------
    # AUDIT
    # ----------------------------------------------------------

    try:

        from collector.audit_routes import (
            get_audit_log,
            AuditEventType,
        )

        audit = get_audit_log()

        if audit:
            audit.log_event(
                event_type=(
                    AuditEventType.API_KEY_REVOKED
                ),
                org_id=org_id,
                actor="admin",
                resource=f"api_key:{org_id}",
                action="revoked",
                details={
                    "keys_revoked": affected,
                    "ip": request.remote_addr,
                },
                risk_level="warning",
            )

    except Exception:
        logger.exception(
            "audit_log_failed",
            event="customer_revoked",
            org_id=org_id,
        )

    # ----------------------------------------------------------
    # LOG
    # ----------------------------------------------------------

    logger.info(
        "customer_revoked",
        org_id=org_id,
        keys_revoked=affected,
    )

    # ----------------------------------------------------------
    # RESPONSE
    # ----------------------------------------------------------

    return jsonify(
        {
            "org_id": org_id,
            "keys_revoked": affected,
        }
    ), 200
