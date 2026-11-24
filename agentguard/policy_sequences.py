"""Bounded multi-step policy detection over canonical agent events."""
from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable
from agentguard.event_contract import AgentEvent, EventKind

@dataclass(frozen=True)
class SequenceRule:
    rule_id: str
    kinds: tuple[EventKind, ...]
    window_seconds: float = 300
    max_events: int = 64
    predicate: Callable[[AgentEvent], bool] | None = None

@dataclass(frozen=True)
class SequenceMatch:
    rule_id: str
    agent_id: str
    event_ids: tuple[str, ...]

class SequencePolicyEngine:
    """Correlates events per tenant/agent/session; bounded memory and deterministic matching."""
    def __init__(self, rules: list[SequenceRule]):
        self.rules = tuple(rules)
        self._events: dict[tuple[str, str, str], deque[AgentEvent]] = defaultdict(deque)

    def ingest(self, event: AgentEvent) -> list[SequenceMatch]:
        key = (event.tenant_id, event.agent_id, event.session_id or "")
        queue = self._events[key]
        queue.append(event)
        cutoff = event.timestamp - max((r.window_seconds for r in self.rules), default=0)
        while queue and (queue[0].timestamp < cutoff or len(queue) > max((r.max_events for r in self.rules), default=64)):
            queue.popleft()
        matches = []
        for rule in self.rules:
            candidates = [e for e in queue if e.timestamp >= event.timestamp - rule.window_seconds
                          and (rule.predicate is None or rule.predicate(e))]
            cursor = 0
            selected = []
            for candidate in candidates:
                if cursor < len(rule.kinds) and candidate.kind == rule.kinds[cursor]:
                    selected.append(candidate)
                    cursor += 1
            if cursor == len(rule.kinds):
                matches.append(SequenceMatch(rule.rule_id, event.agent_id, tuple(e.event_id for e in selected)))
                # Consume matched prefix to avoid repeated alerts from the same sequence.
                matched = set(e.event_id for e in selected)
                self._events[key] = deque(e for e in queue if e.event_id not in matched)
                queue = self._events[key]
        return matches
