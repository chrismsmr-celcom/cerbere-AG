"""Unified orchestration facade for Cerbere runtime security primitives.

This is the common application boundary used by SDK and protocol adapters.
Individual controls remain independently testable; adapters must route every
relevant event through this engine for consistent enforcement.
"""

from __future__ import annotations

from typing import Any

from agentguard.attestation import build_attestation
from agentguard.delegation import DelegationRegistry
from agentguard.egress import EgressDecision, evaluate_egress
from agentguard.event_contract import AgentEvent
from agentguard.event_runtime import AgentEventRuntime, EventResult
from agentguard.host_security import HostDecision, HostSecurityPolicy
from agentguard.result_inspection import (
    InspectionFinding,
    ResultInspection,
    inspect_result,
)
from agentguard.tool_contracts import (
    ContractDecision,
    DataOrigin,
    ToolContractRegistry,
)


class SecurityEngine:
    """Per-agent/per-gateway facade for policy, inspection and evidence controls.

    Do not share one instance across tenants unless its registries and event sink
    are tenant-aware. Delegations are in-memory unless a persistent backend is
    supplied by a future adapter.
    """

    def __init__(
        self,
        *,
        contracts: ToolContractRegistry | None = None,
        host_policy: HostSecurityPolicy | None = None,
        events: AgentEventRuntime | None = None,
        delegations: DelegationRegistry | None = None,
    ) -> None:
        self.contracts = contracts or ToolContractRegistry(strict=False)
        self.host_policy = host_policy or HostSecurityPolicy()
        self.events = events or AgentEventRuntime()
        self.delegations = delegations or DelegationRegistry()

    def authorize_tool(
        self,
        tool_name: str,
        origins: list[DataOrigin],
        *,
        tenant_id: str,
        org_id: str,
        destination: str | None = None,
    ) -> ContractDecision:
        return self.contracts.authorize(
            tool_name,
            origins,
            tenant_id=tenant_id,
            org_id=org_id,
            destination=destination,
        )

    @staticmethod
    def inspect_tool_result(
        value: Any, *, block_on_injection: bool = True
    ) -> ResultInspection:
        return inspect_result(value, block_on_injection=block_on_injection)

    def inspect_content(
        self, content: list[Any], *, block_on_injection: bool = True
    ) -> tuple[list[Any], list[InspectionFinding]]:
        findings: list[InspectionFinding] = []
        for item in content:
            value = getattr(item, "text", None)
            if not isinstance(value, str):
                continue
            result = self.inspect_tool_result(
                value, block_on_injection=block_on_injection
            )
            findings.extend(result.findings)
            if not result.safe:
                raise ValueError(
                    "Blocked by Cerbere: prompt injection detected in tool result"
                )
            try:
                item.text = result.redacted_text
            except (AttributeError, TypeError):
                pass
        return content, findings

    @staticmethod
    def authorize_egress(
        destination: str,
        *,
        allowlist: tuple[str, ...] = (),
        denylist: tuple[str, ...] = (),
        default_allow: bool = False,
    ) -> EgressDecision:
        return evaluate_egress(
            destination,
            allowlist,
            denylist,
            default_allow=default_allow,
        )

    def authorize_command(self, command: str) -> HostDecision:
        return self.host_policy.evaluate_command(command)

    def emit(self, event: AgentEvent) -> EventResult:
        return self.events.emit(event)

    @staticmethod
    def attest(
        events: list[dict[str, Any]],
        *,
        subject: str,
        created_at: float,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return build_attestation(
            events,
            subject=subject,
            created_at=created_at,
            metadata=metadata,
        )
