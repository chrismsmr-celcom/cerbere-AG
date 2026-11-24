from agentguard.integrations.registry import (
    get_integration,
    list_integrations,
    normalize_event,
)


def test_registry_has_truthful_coding_agent_status():
    claude = get_integration("claude-code")
    cursor = get_integration("cursor")
    codex = get_integration("codex")
    assert claude is not None and claude.status == "experimental"
    assert "tool.pre" in claude.enforcement
    assert cursor is not None and cursor.status == "mcp"
    assert codex is not None and codex.status == "planned"


def test_registry_filter_and_serialization():
    items = list_integrations(kind="coding_agent")
    assert {item["id"] for item in items} == {"claude-code", "cursor", "codex"}
    assert all(isinstance(item["events"], tuple) for item in items)


def test_normalized_event_envelope():
    event = normalize_event(
        integration="claude-code",
        event_type="tool.pre",
        agent_id="agent-1",
        session_id="session-1",
        tool_name="Bash",
        arguments={"command": "pwd"},
    )
    assert event["schema_version"] == "1"
    assert event["event_type"] == "tool.pre"
    assert event["arguments"] == {"command": "pwd"}


def test_unknown_integration_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        normalize_event(
            integration="unknown", event_type="tool.pre", agent_id="agent-1"
        )
