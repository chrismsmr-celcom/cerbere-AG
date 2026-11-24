import pytest

from agentguard.integrations.hooks import normalize_hook_event, run_hook


def test_claude_pre_tool_use_normalizes_mcp_tool():
    event = normalize_hook_event(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "session-1",
            "tool_name": "mcp__github__create_issue",
            "tool_input": {"title": "test"},
        },
        "claude-code",
    )
    assert event.tool_name == "mcp:github:create_issue"
    assert event.arguments == {"title": "test"}
    assert event.session_id == "session-1"


def test_claude_normal_tool_is_preserved():
    event = normalize_hook_event(
        {"tool_name": "Bash", "tool_input": {"command": "pwd"}},
        "claude-code",
    )
    assert event.tool_name == "Bash"
    assert event.arguments == {"command": "pwd"}


def test_cursor_shell_event_normalizes_command_and_cwd():
    event = normalize_hook_event(
        {
            "hook_event_name": "beforeShellExecution",
            "command": "rm -rf build",
            "cwd": "/workspace",
            "sandbox": True,
        },
        "cursor",
    )
    assert event.tool_name == "Shell"
    assert event.arguments == {
        "command": "rm -rf build",
        "cwd": "/workspace",
        "sandbox": True,
    }


def test_cursor_mcp_event_namespaces_server_and_tool():
    event = normalize_hook_event(
        {
            "hook_event_name": "beforeMCPExecution",
            "mcp_server_name": "github",
            "tool_name": "create_issue",
            "tool_input": '{"title":"test"}',
        },
        "cursor",
    )
    assert event.tool_name == "mcp:github:create_issue"
    assert event.arguments == {"title": "test"}


def test_unknown_event_is_rejected():
    with pytest.raises(ValueError):
        normalize_hook_event({"hook_event_name": "afterFileEdit"}, "cursor")


def test_authorization_success_returns_host_specific_allow():
    response, allowed = run_hook(
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}},
        "claude-code",
        authorize=lambda event: None,
    )
    assert allowed is True
    assert response == {}


def test_authorization_failure_denies_claude_tool():
    response, allowed = run_hook(
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}},
        "claude-code",
        authorize=lambda event: (_ for _ in ()).throw(RuntimeError("policy denied")),
    )
    assert allowed is False
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "policy denied" in response["hookSpecificOutput"]["permissionDecisionReason"]


def test_authorization_failure_denies_cursor_tool():
    response, allowed = run_hook(
        {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": {}},
        "cursor",
        authorize=lambda event: (_ for _ in ()).throw(
            RuntimeError("collector unavailable")
        ),
    )
    assert allowed is False
    assert response["permission"] == "deny"
    assert "collector unavailable" in response["agent_message"]


def test_non_object_payload_fails_closed():
    with pytest.raises(ValueError):
        normalize_hook_event([], "claude-code")
