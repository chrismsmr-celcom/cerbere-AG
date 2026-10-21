"""
Approval lifecycle storage for Cerbere / AgentGuard.

HITL flow:
    ToolGuard -> REQUIRE_APPROVAL -> create_approval() -> PENDING -> APPROVED/REJECTED/EXPIRED
    APPROVED -> consume_approval() -> usable exactly once, within a short window

This module only manages the approval lifecycle. It does NOT execute tools.

Security properties enforced here:
- an approval is SINGLE-USE: consume_approval() is atomic (UPDATE ... WHERE
  consumed_at IS NULL) so two concurrent retries cannot both succeed;
- an approval is only usable for a limited time after the human decision
  (AGENTGUARD_APPROVED_USE_TTL_SECONDS, default 600 s);
- consuming requires an explicit org_id (no cross-organization use).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import get_db, is_postgres, sql_placeholder

APPROVAL_TTL_SECONDS = int(os.getenv("AGENTGUARD_APPROVAL_TTL_SECONDS", "600"))

# How long an APPROVED decision stays usable before the agent must ask again.
APPROVED_USE_TTL_SECONDS = int(os.getenv("AGENTGUARD_APPROVED_USE_TTL_SECONDS", "600"))

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
EXPIRED = "expired"

VALID_STATUSES = {PENDING, APPROVED, REJECTED, EXPIRED}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _serialize_arguments(arguments: Any) -> str:
    try:
        return json.dumps(
            arguments if arguments is not None else {},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            default=str,
        )
    except Exception:
        return json.dumps(
            {"_serialization_error": True},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def _arguments_hash(arguments: Any) -> str:
    serialized = _serialize_arguments(arguments)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _deserialize_arguments(value: Any) -> Any:
    if value is None:
        return {}
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except Exception:
        return {"_raw": str(value)}


def _row_to_dict(row: Any) -> dict[str, Any]:
    if row is None:
        return {}
    if hasattr(row, "keys"):
        data = {key: row[key] for key in row}
    else:
        columns = [
            "approval_id",
            "org_id",
            "tenant_id",
            "agent_id",
            "session_id",
            "trace_id",
            "span_id",
            "tool_name",
            "arguments",
            "arguments_hash",
            "risk_score",
            "reason",
            "policy_name",
            "status",
            "requested_at",
            "expires_at",
            "decided_at",
            "decided_by",
            "decision_reason",
            "consumed_at",
        ]
        data = dict(zip(columns, row))
    data["arguments"] = _deserialize_arguments(data.get("arguments"))
    return data


def _ensure_arguments_hash_column() -> None:
    db = get_db()
    sql_placeholder()

    if is_postgres():
        db.execute(
            "ALTER TABLE hitl_approvals ADD COLUMN IF NOT EXISTS arguments_hash TEXT"
        )
        db.commit()
        return

    cursor = db.execute("PRAGMA table_info(hitl_approvals)")
    columns = {str(row[1]) for row in cursor.fetchall()}
    if "arguments_hash" not in columns:
        db.execute("ALTER TABLE hitl_approvals ADD COLUMN arguments_hash TEXT")
        db.commit()


def _ensure_consumed_at_column() -> None:
    """Add the single-use marker column to tables created before this change."""
    db = get_db()

    if is_postgres():
        db.execute(
            "ALTER TABLE hitl_approvals ADD COLUMN IF NOT EXISTS consumed_at TEXT"
        )
        db.commit()
        return

    cursor = db.execute("PRAGMA table_info(hitl_approvals)")
    columns = {str(row[1]) for row in cursor.fetchall()}
    if "consumed_at" not in columns:
        db.execute("ALTER TABLE hitl_approvals ADD COLUMN consumed_at TEXT")
        db.commit()


def ensure_approval_schema() -> None:
    """Create the approval table if it does not exist, or fix it if it has the wrong schema."""
    db = get_db()

    # Table PROPRE à ce module (hitl_approvals). Elle portait autrefois le nom `hitl_approvals`,
    # déjà utilisé par les routes /api/approvals avec un autre schéma : chaque module supprimait puis
    # recréait la table de l'autre -> erreurs 500 en boucle. Les deux tables sont désormais séparées.
    # 2. Create the correct table
    query = """
        CREATE TABLE IF NOT EXISTS hitl_approvals (
            approval_id TEXT PRIMARY KEY,
            org_id TEXT,
            tenant_id TEXT,
            agent_id TEXT,
            session_id TEXT,
            trace_id TEXT,
            span_id TEXT,
            tool_name TEXT NOT NULL,
            arguments TEXT NOT NULL,
            arguments_hash TEXT,
            risk_score REAL,
            reason TEXT,
            policy_name TEXT,
            status TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            decided_at TEXT,
            decided_by TEXT,
            decision_reason TEXT,
            consumed_at TEXT
        )
    """
    db.execute(query)
    db.commit()

    # 3. Upgrade existing tables
    _ensure_arguments_hash_column()
    _ensure_consumed_at_column()

    # 4. Backfill hashes for existing records
    cursor = db.execute(
        "SELECT approval_id, arguments FROM hitl_approvals WHERE arguments_hash IS NULL"
    )
    rows = cursor.fetchall()
    if rows:
        placeholder = sql_placeholder()
        update_query = f"UPDATE hitl_approvals SET arguments_hash = {placeholder} WHERE approval_id = {placeholder}"
        for row in rows:
            if hasattr(row, "keys"):
                approval_id = row["approval_id"]
                arguments = row["arguments"]
            else:
                approval_id = row[0]
                arguments = row[1]

            parsed_arguments = _deserialize_arguments(arguments)
            db.execute(update_query, (_arguments_hash(parsed_arguments), approval_id))
        db.commit()


def create_approval(
    *,
    tool_name: str,
    arguments: Any,
    org_id: str | None = None,
    tenant_id: str | None = None,
    agent_id: str | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    span_id: str | None = None,
    risk_score: float | None = None,
    reason: str | None = None,
    policy_name: str | None = None,
    ttl_seconds: int | None = None,
) -> dict[str, Any]:
    ensure_approval_schema()
    now = _now()
    ttl = APPROVAL_TTL_SECONDS if ttl_seconds is None else max(1, int(ttl_seconds))
    expires_at = now + timedelta(seconds=ttl)
    approval_id = f"apr_{secrets.token_urlsafe(18)}"

    serialized_arguments = _serialize_arguments(arguments)
    arguments_hash = _arguments_hash(arguments)

    db = get_db()
    p = sql_placeholder()
    query = f"""
        INSERT INTO hitl_approvals (
            approval_id, org_id, tenant_id, agent_id, session_id, trace_id, span_id,
            tool_name, arguments, arguments_hash, risk_score, reason, policy_name,
            status, requested_at, expires_at, decided_at, decided_by, decision_reason,
            consumed_at
        ) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})
    """
    params = (
        approval_id,
        org_id,
        tenant_id,
        agent_id,
        session_id,
        trace_id,
        span_id,
        tool_name,
        serialized_arguments,
        arguments_hash,
        risk_score,
        reason,
        policy_name,
        PENDING,
        _iso(now),
        _iso(expires_at),
        None,
        None,
        None,
        None,
    )
    db.execute(query, params)
    db.commit()

    result = get_approval(approval_id)
    if result is None:
        raise RuntimeError("Approval was created but could not be retrieved")
    return result


def _expire_if_needed(approval: dict[str, Any]) -> dict[str, Any]:
    if approval.get("status") != PENDING:
        return approval
    expires_at = _parse_datetime(approval.get("expires_at"))
    if expires_at is None or _now() < expires_at:
        return approval

    db = get_db()
    p = sql_placeholder()
    query = f"""
        UPDATE hitl_approvals
        SET status = {p}, decided_at = {p}, decision_reason = {p}
        WHERE approval_id = {p} AND status = {p}
    """
    db.execute(
        query,
        (
            EXPIRED,
            _iso(_now()),
            "Approval request expired",
            approval["approval_id"],
            PENDING,
        ),
    )
    db.commit()
    return get_approval(approval["approval_id"]) or approval


def get_approval(
    approval_id: str, *, org_id: str | None = None
) -> dict[str, Any] | None:
    """
    Fetch one approval.

    SECURITY: org_id=None performs an UNSCOPED lookup (any organization).
    Only internal code paths that have no organization context may call it
    that way. Anything that authorizes an action must pass an explicit org_id.
    """
    ensure_approval_schema()
    db = get_db()
    p = sql_placeholder()

    if org_id is None:
        query = f"SELECT * FROM hitl_approvals WHERE approval_id = {p} LIMIT 1"
        cursor = db.execute(query, (approval_id,))
    else:
        query = f"SELECT * FROM hitl_approvals WHERE approval_id = {p} AND org_id = {p} LIMIT 1"
        cursor = db.execute(query, (approval_id, org_id))

    row = cursor.fetchone()
    if row is None:
        return None
    return _expire_if_needed(_row_to_dict(row))


def list_approvals(
    *, org_id: str | None = None, status: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    ensure_approval_schema()
    limit = max(1, min(int(limit), 200))
    db = get_db()
    p = sql_placeholder()

    conditions = []
    params = []
    if org_id is not None:
        conditions.append(f"org_id = {p}")
        params.append(org_id)
    if status is not None:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid approval status: {status}")
        conditions.append(f"status = {p}")
        params.append(status)

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
    query = f"SELECT * FROM hitl_approvals {where_clause} ORDER BY requested_at DESC LIMIT {limit}"

    cursor = db.execute(query, tuple(params))
    approvals = [_expire_if_needed(_row_to_dict(row)) for row in cursor.fetchall()]

    if status is not None:
        approvals = [a for a in approvals if a.get("status") == status]
    return approvals


def decide_approval(
    approval_id: str,
    *,
    decision: str,
    decided_by: str | None = None,
    decision_reason: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    ensure_approval_schema()
    normalized = str(decision).strip().lower()
    if normalized not in {APPROVED, REJECTED}:
        raise ValueError("decision must be 'approved' or 'rejected'")

    approval = get_approval(approval_id, org_id=org_id)
    if approval is None:
        raise KeyError(f"Approval not found: {approval_id}")
    if approval["status"] == EXPIRED:
        raise ValueError("Approval request has expired")
    if approval["status"] != PENDING:
        raise ValueError(f"Approval request is already {approval['status']}")

    db = get_db()
    p = sql_placeholder()
    query = f"""
        UPDATE hitl_approvals
        SET status = {p}, decided_at = {p}, decided_by = {p}, decision_reason = {p}
        WHERE approval_id = {p} AND status = {p}
    """
    params = (
        normalized,
        _iso(_now()),
        decided_by,
        decision_reason,
        approval_id,
        PENDING,
    )
    if org_id is not None:
        query += f" AND org_id = {p}"
        params = params + (org_id,)

    cursor = db.execute(query, params)
    db.commit()

    if getattr(cursor, "rowcount", 1) == 0:
        current = get_approval(approval_id, org_id=org_id)
        if current is None:
            raise KeyError(f"Approval not found: {approval_id}")
        if current["status"] == EXPIRED:
            raise ValueError("Approval request has expired")
        raise ValueError(f"Approval request is already {current['status']}")

    result = get_approval(approval_id, org_id=org_id)
    if result is None:
        raise RuntimeError("Approval was updated but could not be retrieved")
    return result


def approve_approval(
    approval_id: str,
    *,
    decided_by: str | None = None,
    decision_reason: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    return decide_approval(
        approval_id,
        decision=APPROVED,
        decided_by=decided_by,
        decision_reason=decision_reason,
        org_id=org_id,
    )


def reject_approval(
    approval_id: str,
    *,
    decided_by: str | None = None,
    decision_reason: str | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    return decide_approval(
        approval_id,
        decision=REJECTED,
        decided_by=decided_by,
        decision_reason=decision_reason,
        org_id=org_id,
    )


def consume_approval(approval_id: str, *, org_id: str) -> bool:
    """
    Spend an APPROVED approval. Returns True exactly once per approval.

    Fails closed (returns False) when:
    - org_id is missing or does not own the approval,
    - the approval is not in the APPROVED state,
    - it was already consumed,
    - the human decision is older than APPROVED_USE_TTL_SECONDS,
    - another caller consumed it first (atomic UPDATE, rowcount must be 1).
    """
    if not org_id:
        return False

    approval = get_approval(approval_id, org_id=org_id)
    if approval is None or approval.get("status") != APPROVED:
        return False
    if approval.get("consumed_at"):
        return False

    decided_at = _parse_datetime(approval.get("decided_at"))
    if decided_at is None:
        return False
    if _now() > decided_at + timedelta(seconds=APPROVED_USE_TTL_SECONDS):
        return False

    db = get_db()
    p = sql_placeholder()
    query = f"""
        UPDATE hitl_approvals
        SET consumed_at = {p}
        WHERE approval_id = {p} AND org_id = {p}
          AND status = {p} AND consumed_at IS NULL
    """
    cursor = db.execute(query, (_iso(_now()), approval_id, org_id, APPROVED))
    db.commit()
    return getattr(cursor, "rowcount", 0) == 1