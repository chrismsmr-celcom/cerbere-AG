import pytest
from pydantic import ValidationError

from agentguard.event_contract import AgentEvent, EventKind
from agentguard.event_runtime import AgentEventRuntime
from agentguard.policy_sequences import SequenceRule


def _event(kind, tool, timestamp):
    return AgentEvent(
        kind=kind,
        timestamp=timestamp,
        tenant_id="tenant-1",
        org_id="org-1",
        agent_id="agent-1",
        session_id="session-1",
        integration_id="test",
        surface="unit",
        tool_name=tool,
    )


def test_runtime_persists_canonical_event_before_sequence_processing():
    persisted = []
    runtime = AgentEventRuntime(
        sink=persisted.append,
        sequence_rules=[
            SequenceRule(
                "read_then_send",
                (EventKind.TOOL_PRE, EventKind.TOOL_PRE),
                window_seconds=30,
                predicate=lambda event: event.tool_name in {"db.read", "email.send"},
            )
        ],
    )
    first = runtime.emit(_event(EventKind.TOOL_PRE, "db.read", 100.0))
    second = runtime.emit(_event(EventKind.TOOL_PRE, "email.send", 101.0))

    assert first.sequence_matches == ()
    assert second.sequence_matches[0].rule_id == "read_then_send"
    assert len(persisted) == 2
    assert persisted[0]["tenant_id"] == "tenant-1"
    assert persisted[1]["tool_name"] == "email.send"


def test_runtime_sink_failure_is_not_swallowed():
    def unavailable(_event):
        raise OSError("database unavailable")

    runtime = AgentEventRuntime(sink=unavailable, require_sink=True)
    with pytest.raises(OSError, match="database unavailable"):
        runtime.emit(_event(EventKind.TOOL_PRE, "db.read", 100.0))


def test_strict_runtime_requires_a_sink():
    with pytest.raises(ValueError, match="durable event sink"):
        AgentEventRuntime(require_sink=True)


def test_runtime_does_not_accept_unvalidated_model_constructed_event():
    event = AgentEvent.model_construct(
        kind=EventKind.TOOL_PRE,
        tenant_id="",
        org_id="org-1",
        agent_id="agent-1",
        integration_id="test",
        surface="unit",
        arguments={},
        data_labels=[],
        provenance=[],
        metadata={},
    )
    runtime = AgentEventRuntime()
    with pytest.raises(ValidationError):
        runtime.emit(event)


def test_sequence_state_is_isolated_between_orgs():
    runtime = AgentEventRuntime(
        sequence_rules=[
            SequenceRule(
                "read_then_send",
                (EventKind.TOOL_PRE, EventKind.TOOL_PRE),
                window_seconds=30,
                predicate=lambda event: event.tool_name in {"db.read", "email.send"},
            )
        ]
    )
    runtime.emit(_event(EventKind.TOOL_PRE, "db.read", 100.0))
    other_org = AgentEvent(
        kind=EventKind.TOOL_PRE,
        timestamp=101.0,
        tenant_id="tenant-1",
        org_id="org-2",
        agent_id="agent-1",
        session_id="session-1",
        integration_id="test",
        surface="unit",
        tool_name="email.send",
    )
    assert runtime.emit(other_org).sequence_matches == ()
