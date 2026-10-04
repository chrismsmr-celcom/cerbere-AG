"""Audit des connexions."""

from typing import Optional


def _audit_login(
    success: bool,
    email: Optional[str] = None,
    org_id: str = "unknown",
    reason: Optional[str] = None,
):
    try:
        from collector.audit_routes import (
            AuditEventType,
            get_audit_log,
        )

        audit = get_audit_log()

        if not audit:
            return

        event_type = (
            AuditEventType.LOGIN_SUCCESS
            if success
            else AuditEventType.LOGIN_FAILED
        )

        details = {
            "method": "magic_link",
        }

        if reason:
            details["reason"] = reason

        audit.log_event(
            event_type=event_type,
            org_id=org_id,
            actor=(
                f"user:{email}"
                if email
                else "unknown"
            ),
            resource="dashboard",
            action=(
                "login"
                if success
                else "login_failed"
            ),
            details=details,
            risk_level=(
                "info"
                if success
                else "warning"
            ),
        )

    except Exception:
        pass
