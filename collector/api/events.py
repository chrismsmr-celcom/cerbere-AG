"""Authenticated ingestion for the canonical AgentEvent contract."""

from __future__ import annotations

import json

from flask import current_app, g, jsonify, request

from agentguard.event_contract import AgentEvent, EventKind
from collector.api.helpers import (
    _reject_if_agent_disconnected,
    _request_agent_id,
    _sqlite_connect,
    _db_run,
    api_bp,
)
from collector.db import get_db, is_postgres, redact_pii, sql_placeholder
from collector.extensions import limiter


@api_bp.route("/events", methods=["POST"])
@limiter.limit("120 per minute")
def receive_agent_event():
    """Validate and persist an event; authenticated identity always wins."""
    refused = _reject_if_agent_disconnected()
    if refused:
        return refused

    raw = request.get_json(silent=True)
    if not isinstance(raw, dict):
        return jsonify({"error": "Body must be a JSON object"}), 400
    if len(request.get_data(cache=True)) > current_app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"error": "Payload too large"}), 413

    org_id = getattr(g, "org_id", None)
    tenant_id = getattr(g, "tenant_id", None)
    if org_id and not tenant_id:
        row, _ = _db_run(
            "SELECT tenant_id FROM orgs WHERE org_id = ?",
            (org_id,),
            fetch="one",
        )
        tenant_id = row[0] if row else None
    agent_id = _request_agent_id()
    if not org_id or not tenant_id or not agent_id:
        return jsonify({"error": "Authenticated tenant, org and agent identity required"}), 403

    # Never accept tenant/org/agent identity from the event body.
    payload = dict(raw)
    for key in ("tenant_id", "org_id", "agent_id"):
        payload.pop(key, None)
    payload["tenant_id"] = str(tenant_id)
    payload["org_id"] = str(org_id)
    payload["agent_id"] = str(agent_id)
    payload.setdefault("integration_id", "unknown")
    payload.setdefault("surface", "unknown")

    try:
        payload["kind"] = EventKind(payload.get("kind"))
        payload = redact_pii(payload)
        event = AgentEvent.model_validate(payload)
    except (TypeError, ValueError) as exc:
        return jsonify({"error": "Invalid AgentEvent", "detail": str(exc)[:300]}), 400

    event_data = event.model_dump(mode="json")
    session_id = event.session_id or event.event_id
    event_data["session_id"] = session_id
    p = sql_placeholder()
    conn = get_db() if is_postgres() else _sqlite_connect()
    try:
        cur = conn.cursor()
        if is_postgres():
            cur.execute(
                """CREATE TABLE IF NOT EXISTS agent_event_envelopes (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    event_kind TEXT NOT NULL,
                    occurred_at DOUBLE PRECISION NOT NULL,
                    payload JSONB NOT NULL,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )"""
            )
        else:
            cur.execute(
                """CREATE TABLE IF NOT EXISTS agent_event_envelopes (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    event_kind TEXT NOT NULL,
                    occurred_at REAL NOT NULL,
                    payload TEXT NOT NULL,
                    received_at TEXT DEFAULT CURRENT_TIMESTAMP
                )"""
            )
        cur.execute(
            f"""INSERT INTO agent_event_envelopes (
                event_id, tenant_id, org_id, agent_id, session_id,
                event_kind, occurred_at, payload
            ) VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
            ON CONFLICT (event_id) DO NOTHING""",
            (
                event.event_id,
                event.tenant_id,
                event.org_id,
                event.agent_id,
                session_id,
                event.kind.value,
                event.timestamp,
                json.dumps(event_data),
            ),
        )
        inserted = cur.rowcount == 1
        conn.commit()
    except Exception:
        conn.rollback()
        current_app.logger.exception("canonical_agent_event_persist_failed")
        return jsonify({"error": "Event persistence unavailable"}), 503
    finally:
        conn.close()

    return jsonify(
        {
            "event_id": event.event_id,
            "accepted": True,
            "duplicate": not inserted,
            "schema_version": event.schema_version,
        }
    ), 202
