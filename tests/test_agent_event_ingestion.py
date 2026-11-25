from flask import g


def test_canonical_event_ingestion_uses_authenticated_identity(app, monkeypatch):
    from collector.api import events

    monkeypatch.setattr(events, "_reject_if_agent_disconnected", lambda: None)
    monkeypatch.setattr(events, "_request_agent_id", lambda: "agent-authenticated")

    payload = {
        "event_id": "event-00000001",
        "kind": "tool.pre",
        "timestamp": 1700000000.0,
        "tenant_id": "tenant-spoofed",
        "org_id": "org-spoofed",
        "agent_id": "agent-spoofed",
        "integration_id": "claude-code",
        "surface": "coding",
        "session_id": "session-1",
        "tool_name": "db.read",
        "arguments": {"query": "select 1"},
    }

    with app.test_request_context("/api/events", method="POST", json=payload):
        g.tenant_id = "tenant-trusted"
        g.org_id = "org-trusted"
        response, status = events.receive_agent_event()

    assert status == 202
    assert response.get_json()["accepted"] is True

    from collector.api.helpers import _db_run

    row, _ = _db_run(
        "SELECT tenant_id, org_id, agent_id FROM agent_event_envelopes WHERE event_id = ?",
        ("event-00000001",),
        fetch="one",
    )
    assert row == ("tenant-trusted", "org-trusted", "agent-authenticated")


def test_canonical_event_ingestion_is_idempotent(app, monkeypatch):
    from collector.api import events

    monkeypatch.setattr(events, "_reject_if_agent_disconnected", lambda: None)
    monkeypatch.setattr(events, "_request_agent_id", lambda: "agent-1")
    payload = {
        "event_id": "event-00000002",
        "kind": "tool.result",
        "timestamp": 1700000001.0,
        "integration_id": "python-sdk",
        "surface": "python",
        "session_id": "session-1",
        "tool_name": "db.read",
        "result": {"sha256": "abc"},
    }

    with app.test_request_context("/api/events", method="POST", json=payload):
        g.tenant_id = "tenant-1"
        g.org_id = "org-1"
        first, first_status = events.receive_agent_event()

    with app.test_request_context("/api/events", method="POST", json=payload):
        g.tenant_id = "tenant-1"
        g.org_id = "org-1"
        second, second_status = events.receive_agent_event()

    assert first_status == 202
    assert second_status == 202
    assert first.get_json()["duplicate"] is False
    assert second.get_json()["duplicate"] is True


def test_canonical_event_ingestion_persists_value_free_provenance(app, monkeypatch):
    from collector.api import events
    from collector.api.helpers import _db_run

    monkeypatch.setattr(events, "_reject_if_agent_disconnected", lambda: None)
    monkeypatch.setattr(events, "_request_agent_id", lambda: "agent-authenticated")
    payload = {
        "event_id": "event-provenance-0001",
        "kind": "tool.result",
        "timestamp": 1700000002.0,
        "integration_id": "python-sdk",
        "surface": "python",
        "session_id": "session-provenance",
        "tool_name": "crm.lookup",
        "result": {"sha256": "abc"},
        "provenance_records": [
            {
                "data_id": "data-customer-001",
                "parent_data_ids": ["data-source-001"],
                "classification": "CONFIDENTIAL",
                "source": "tool:crm.lookup",
                "transformation": "normalized_customer_record",
                "content_sha256": "a" * 64,
            }
        ],
    }

    with app.test_request_context("/api/events", method="POST", json=payload):
        g.tenant_id = "tenant-trusted"
        g.org_id = "org-trusted"
        _response, status = events.receive_agent_event()

    assert status == 202
    row, _ = _db_run(
        """SELECT tenant_id, org_id, agent_id, session_id, parent_data_ids,
                  classification, source, transformation, content_sha256
           FROM agent_data_provenance
           WHERE event_id = ? AND data_id = ?""",
        ("event-provenance-0001", "data-customer-001"),
        fetch="one",
    )
    assert row[:4] == (
        "tenant-trusted",
        "org-trusted",
        "agent-authenticated",
        "session-provenance",
    )
    assert row[5:] == (
        "CONFIDENTIAL",
        "tool:crm.lookup",
        "normalized_customer_record",
        "a" * 64,
    )


def test_canonical_event_rejects_invalid_provenance_classification(app, monkeypatch):
    from collector.api import events

    monkeypatch.setattr(events, "_reject_if_agent_disconnected", lambda: None)
    monkeypatch.setattr(events, "_request_agent_id", lambda: "agent-1")
    payload = {
        "event_id": "event-provenance-invalid",
        "kind": "tool.result",
        "timestamp": 1700000003.0,
        "integration_id": "python-sdk",
        "surface": "python",
        "session_id": "session-1",
        "tool_name": "crm.lookup",
        "provenance_records": [
            {
                "data_id": "data-1",
                "classification": "TRUSTED",
                "source": "tool:crm.lookup",
            }
        ],
    }

    with app.test_request_context("/api/events", method="POST", json=payload):
        g.tenant_id = "tenant-1"
        g.org_id = "org-1"
        response, status = events.receive_agent_event()

    assert status == 400
    assert response.get_json()["error"] == "Invalid AgentEvent"
