"""Experimental Claude Code PreToolUse hook backed by Cerbere signed decisions.

Only a verified, request-bound ALLOW is passed through. Missing credentials,
network failures, invalid signatures and every non-ALLOW decision deny.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from typing import Any

import requests


def _category(tool_name: str) -> str:
    name = tool_name.lower()
    if name in {"read", "glob", "grep", "ls"}:
        return "read"
    if name in {"write", "edit", "multiedit", "notebookedit"}:
        return "write"
    if name in {"bash", "terminal"}:
        return "execute"
    return "tool"


def _decision_client() -> tuple[str, dict[str, str], Any]:
    collector = os.getenv(
        "AGENTGUARD_COLLECTOR_URL", "http://localhost:8080"
    ).rstrip("/")
    api_key = os.getenv("AGENTGUARD_API_KEY", "").strip()
    agent_id = os.getenv("AGENTGUARD_AGENT_ID", "claude-code").strip()
    if not api_key:
        raise RuntimeError("AGENTGUARD_API_KEY is required")

    from agentguard.signing import DecisionVerifier

    public_key = os.getenv("AGENTGUARD_PUBLIC_KEY")
    if not public_key:
        response = requests.get(f"{collector}/api/public-key", timeout=5)
        response.raise_for_status()
        public_key = response.json()["public_key_pem"]
    verifier = DecisionVerifier(public_key)
    headers = {"X-API-Key": api_key, "X-Agent-Id": agent_id}
    return collector, headers, (agent_id, verifier)


def evaluate_pre_tool_use(
    payload: dict, *, timeout: float = 5.0
) -> tuple[bool, str]:
    """Ask the collector for a signed decision bound to this exact tool call."""
    tool_name = str(payload.get("tool_name") or "").strip()
    arguments = payload.get("tool_input") or {}
    if not tool_name or not isinstance(arguments, dict):
        return False, "Malformed Claude Code hook payload"

    collector, headers, auth = _decision_client()
    bound_agent_id, verifier = auth
    nonce = uuid.uuid4().hex
    category = _category(tool_name)
    body = {
        "tool_name": tool_name,
        "params": arguments,
        "tool_category": category,
        "external_side_effect": category in {"write", "execute"},
        "irreversible": False,
        "nonce": nonce,
        "trajectory_length": 1,
        "policy": "claude_code_hook",
    }
    response = requests.post(
        f"{collector}/api/decide",
        json=body,
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()
    signed = response.json()

    if not verifier.verify_for(
        signed, tool_name=tool_name, params=arguments, nonce=nonce
    ):
        return False, "Cerbere could not verify the signed decision"
    if signed.get("agent_id") != bound_agent_id:
        return False, "Cerbere decision agent identity mismatch"
    if signed.get("action") != "ALLOW":
        reason = signed.get("reason") or signed.get("action") or "Blocked by Cerbere"
        return False, str(reason)
    return True, str(signed.get("reason") or "Allowed by Cerbere")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("Hook input must be a JSON object")
        allowed, reason = evaluate_pre_tool_use(payload)
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow" if allowed else "deny",
                "permissionDecisionReason": reason,
            }
        }
    except Exception as exc:
        # Fail closed: never turn an enforcement error into an implicit allow.
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "Cerbere enforcement unavailable: "
                    f"{type(exc).__name__}"
                ),
            }
        }
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
