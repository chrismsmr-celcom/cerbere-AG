"""Fail-closed adapters for native AI coding-agent hooks.

The adapters normalize host-specific hook payloads and delegate authorization
to AgentGuard. They do not implement a second policy engine.

Supported first pass:
- Claude Code: PreToolUse
- Cursor: preToolUse, beforeShellExecution, beforeMCPExecution

The host sends one JSON object on stdin. Decisions are written to stdout only;
diagnostics go to stderr so protocol output is never corrupted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizedHookEvent:
    tool_name: str
    arguments: dict[str, Any]
    event_name: str
    session_id: str | None = None


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("Hook tool_input is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Hook tool_input JSON must be an object")
        return parsed
    if value is None:
        return {}
    return {"value": value}


def normalize_hook_event(
    payload: dict[str, Any],
    agent: str,
) -> NormalizedHookEvent:
    """Convert Claude Code or Cursor hook input to Cerbere's tool-call shape."""
    if not isinstance(payload, dict):
        raise ValueError("Hook payload must be a JSON object")

    event = str(payload.get("hook_event_name") or "").strip()
    agent = agent.strip().lower()

    if agent == "claude-code":
        if event and event != "PreToolUse":
            raise ValueError(f"Unsupported Claude Code event: {event}")
        name = str(payload.get("tool_name") or "").strip()
        if not name:
            raise ValueError("Claude Code payload is missing tool_name")
        args = _object(payload.get("tool_input"))
        # Preserve the server/tool boundary rather than treating two MCP
        # servers' identically named tools as the same capability.
        if name.startswith("mcp__"):
            parts = name.split("__", 2)
            if len(parts) == 3 and parts[1] and parts[2]:
                name = f"mcp:{parts[1]}:{parts[2]}"
        return NormalizedHookEvent(
            tool_name=name,
            arguments=args,
            event_name=event or "PreToolUse",
            session_id=payload.get("session_id"),
        )

    if agent != "cursor":
        raise ValueError(f"Unsupported agent: {agent}")

    if event == "beforeShellExecution":
        command = payload.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ValueError("Cursor shell hook is missing command")
        args = {"command": command}
        if payload.get("cwd"):
            args["cwd"] = payload["cwd"]
        if "sandbox" in payload:
            args["sandbox"] = payload["sandbox"]
        return NormalizedHookEvent("Shell", args, event, payload.get("conversation_id"))

    if event == "beforeMCPExecution":
        name = str(payload.get("tool_name") or "").strip()
        server = str(payload.get("mcp_server_name") or "").strip()
        if not name or not server:
            raise ValueError("Cursor MCP hook requires tool_name and mcp_server_name")
        return NormalizedHookEvent(
            tool_name=f"mcp:{server}:{name}",
            arguments=_object(payload.get("tool_input")),
            event_name=event,
            session_id=payload.get("conversation_id"),
        )

    if event == "preToolUse":
        name = str(payload.get("tool_name") or "").strip()
        if not name:
            raise ValueError("Cursor preToolUse payload is missing tool_name")
        return NormalizedHookEvent(
            tool_name=name,
            arguments=_object(payload.get("tool_input")),
            event_name=event,
            session_id=payload.get("conversation_id"),
        )

    raise ValueError(f"Unsupported Cursor event: {event or '<missing>'}")


def _host_response(agent: str, allowed: bool, reason: str) -> dict[str, Any]:
    if agent == "claude-code":
        if allowed:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }

    response: dict[str, Any] = {"permission": "allow" if allowed else "deny"}
    if not allowed:
        response["user_message"] = reason
        response["agent_message"] = reason
    return response


def _authorize(event: NormalizedHookEvent) -> None:
    # The no-op is intentional: this hook authorizes the host's imminent call.
    # The real tool remains owned and executed by Claude Code or Cursor.
    from agentguard import AgentGuard

    api_key = os.getenv("AGENTGUARD_API_KEY", "").strip()
    collector_url = os.getenv("AGENTGUARD_COLLECTOR_URL", "").strip()
    if not api_key or not collector_url:
        raise RuntimeError(
            "AGENTGUARD_API_KEY and AGENTGUARD_COLLECTOR_URL are required; "
            "refusing unverified execution"
        )

    guard = AgentGuard(
        collector_url=collector_url,
        api_key=api_key,
        agent_id=os.getenv("AGENTGUARD_AGENT_ID") or "coding-agent",
        fail_open=False,
        wait_for_approval=True,
    )
    guard.guard_tool_call(
        event.tool_name,
        params=event.arguments,
        func=lambda *args, **kwargs: None,
    )


def run_hook(
    payload: dict[str, Any],
    agent: str,
    authorize: Callable[[NormalizedHookEvent], None] | None = None,
) -> tuple[dict[str, Any], bool]:
    """Return (host response, allowed). Any uncertainty is a denial."""
    try:
        event = normalize_hook_event(payload, agent)
        (authorize or _authorize)(event)
        return _host_response(agent, True, ""), True
    except Exception as exc:
        reason = str(exc).strip() or "Cerbere could not authorize this action"
        return _host_response(agent, False, f"Blocked by Cerbere: {reason}"), False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cerbere coding-agent hook adapter")
    parser.add_argument("--agent", choices=("claude-code", "cursor"), required=True)
    args = parser.parse_args(argv)

    try:
        payload = json.load(sys.stdin)
    except Exception as exc:
        response = _host_response(
            args.agent, False, f"Blocked by Cerbere: invalid hook input ({exc})"
        )
        json.dump(response, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0

    response, allowed = run_hook(payload, args.agent)
    json.dump(response, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    if not allowed:
        print("Cerbere denied the coding-agent action", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
