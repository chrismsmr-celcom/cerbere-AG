"""Shared runtime event pipeline used by SDK and integration adapters.

The pipeline validates every event against AgentEvent, correlates ordered
multi-step policies, and forwards canonical events to an optional durable sink.
A sink failure is surfaced to the caller so enforcement adapters can fail closed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentguard.event_contract import AgentEvent, EventKind
from agentguard.policy_sequences import SequenceMatch, SequencePolicyEngine, SequenceRule


@dataclass(frozen=True)
class EventResult:
    event: AgentEvent
    sequence_matches: tuple[SequenceMatch, ...]


class AgentEventRuntime:
    """Canonical event boundary with optional persistence and sequence policies.

    The runtime deliberately does not pretend that an in-memory queue is durable.
    Production callers should provide a sink that persists events transactionally.
    """

    def __init__(
        self,
        *,
        sink: Callable[[dict[str, Any]], None] | None = None,
        sequence_rules: list[SequenceRule] | None = None,
        require_sink: bool = False,
    ) -> None:
        if require_sink and sink is None:
            raise ValueError("A durable event sink is required in strict mode")
        self._sink = sink
        self._sequences = SequencePolicyEngine(sequence_rules or [])
        self._require_sink = require_sink

    def emit(self, event: AgentEvent) -> EventResult:
        # Re-validate even if an adapter passes an AgentEvent instance. This
        # protects the boundary against unsafe model_construct()/mutation paths.
        canonical = AgentEvent.model_validate(event.model_dump(mode="python"))
        if self._sink is not None:
            # Persist before sequence evaluation: a storage outage must not
            # silently discard an event and leave sequence state inconsistent.
            self._sink(canonical.model_dump(mode="json"))
        elif self._require_sink:
            raise RuntimeError("Canonical event persistence is unavailable")
        matches = self._sequences.ingest(canonical)
        return EventResult(canonical, tuple(matches))


def default_exfiltration_rules() -> list[SequenceRule]:
    """Conservative read-then-external-call correlation rules."""
    return [
        SequenceRule(
            rule_id="read_then_external_tool",
            kinds=(EventKind.TOOL_PRE, EventKind.TOOL_PRE),
            window_seconds=300,
            max_events=64,
            predicate=lambda event: event.kind == EventKind.TOOL_PRE,
        )
    ]
