"""Canonical, versioned event contract shared by all agent integration surfaces."""
from __future__ import annotations

import time
from collections.abc import Iterable
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentguard.ids import uuid7


class EventKind(str, Enum):
    PROMPT = "prompt"
    TOOL_PRE = "tool.pre"
    TOOL_RESULT = "tool.result"
    AGENT_START = "agent.start"
    AGENT_END = "agent.end"
    DELEGATION = "agent.delegate"
    NETWORK_EGRESS = "network.egress"


class AgentEvent(BaseModel):
    """Surface-neutral event. Adapters map host payloads into this model before policy evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str = "1.0"
    event_id: str = Field(default_factory=uuid7, min_length=8, max_length=64)
    kind: EventKind
    timestamp: float = Field(default_factory=time.time, ge=0)
    tenant_id: str = Field(min_length=1, max_length=128)
    org_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)
    parent_agent_id: str | None = Field(default=None, max_length=128)
    integration_id: str = Field(min_length=1, max_length=128)
    surface: str = Field(min_length=1, max_length=64)
    tool_name: str | None = Field(default=None, max_length=256)
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any = None
    data_labels: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("schema_version")
    @classmethod
    def supported_version(cls, value: str) -> str:
        if value != "1.0":
            raise ValueError(f"Unsupported event schema version: {value}")
        return value

    def policy_context(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "org_id": self.org_id, "agent_id": self.agent_id,
            "session_id": self.session_id, "parent_agent_id": self.parent_agent_id,
            "surface": self.surface, "integration_id": self.integration_id,
            "event_kind": self.kind.value, "data_labels": list(self.data_labels),
            "provenance": list(self.provenance), "metadata": dict(self.metadata),
        }


def normalize_event(payload: dict[str, Any], *, integration_id: str, surface: str,
                    defaults: dict[str, Any] | None = None) -> AgentEvent:
    """Strict adapter boundary: explicit identity defaults, no silent identity guessing."""
    values = {**(defaults or {}), **payload}
    values.setdefault("integration_id", integration_id)
    values.setdefault("surface", surface)
    return AgentEvent.model_validate(values)


def decision_fingerprint(decision: Any) -> tuple[str, str, tuple[str, ...]]:
    """Stable comparable decision tuple for cross-surface conformance tests."""
    action = getattr(getattr(decision, "action", None), "value", None) or getattr(decision, "action", "deny")
    reason = str(getattr(decision, "reason", "") or "")
    rules = tuple(sorted(getattr(decision, "matched_rules", []) or []))
    return str(action).lower(), reason, rules


def assert_decision_conformance(decisions: Iterable[Any]) -> tuple[str, str, tuple[str, ...]]:
    """Raise when adapters backed by the same evaluator produce divergent outcomes."""
    fingerprints = [decision_fingerprint(item) for item in decisions]
    if not fingerprints:
        raise ValueError("At least one decision is required")
    if any(item != fingerprints[0] for item in fingerprints[1:]):
        raise AssertionError(f"Cross-surface decision mismatch: {fingerprints!r}")
    return fingerprints[0]
