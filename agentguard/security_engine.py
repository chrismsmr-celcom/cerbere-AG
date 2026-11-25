"""Unified orchestration facade for Cerbere runtime security primitives.

This is the common application boundary used by SDK and protocol adapters.
Individual controls remain independently testable; adapters must route every
relevant event through this engine for consistent enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class PolicyDecision:
    """Canonical outcome shared by SDK and protocol adapters."""

    action: str
    would_action: str
    requires_approval: bool
    reason: str
    source: str
    shadow_observation: dict[str, Any] | None = None


class PolicyDecisionEngine:
    """Combines primitive results into one deterministic enforcement outcome."""

    @staticmethod
    def decide(
        *,
        policy_check: Any | None = None,
        runtime_decision: Any | None = None,
        contract_decision: ContractDecision | None = None,
        signed_action: str | None = None,
        shadow_mode: bool = False,
        block_on_high: bool = True,
    ) -> PolicyDecision:
        signed = (signed_action or "").upper()
        runtime_action = str(
            getattr(runtime_decision, "action", "ALLOW") or "ALLOW"
        ).upper()
        reasons: list[str] = []
        source = "default"

        if signed == "DENY":
            return PolicyDecision("DENY", "DENY", False, "Signed server DENY", "signed")
        if signed and signed not in {"ALLOW", "REQUIRE_APPROVAL"}:
            return PolicyDecision(
                "DENY", "DENY", False, "Invalid signed action", "signed"
            )

        if contract_decision is not None and not contract_decision.allowed:
            return PolicyDecision(
                "DENY", "DENY", False, contract_decision.reason, "tool_contract"
            )

        requires_approval = bool(
            (
                policy_check is not None
                and not getattr(policy_check, "passed", True)
                and getattr(policy_check, "metadata", {}).get("requires_approval")
            )
            or runtime_action == "REQUIRE_APPROVAL"
            or signed == "REQUIRE_APPROVAL"
            or (contract_decision is not None and contract_decision.requires_approval)
        )

        denied = False
        if (
            runtime_decision is not None
            and not getattr(runtime_decision, "allowed", True)
            and runtime_action != "REQUIRE_APPROVAL"
        ):
            denied = True
            source = "runtime"
            reasons.extend(getattr(runtime_decision, "reasons", [])[:5])

        if (
            policy_check is not None
            and not getattr(policy_check, "passed", True)
            and getattr(policy_check, "risk_level", None) is not None
            and getattr(policy_check.risk_level, "value", "") in {"high", "critical"}
            and block_on_high
            and not requires_approval
        ):
            denied = True
            source = "policy"
            details = str(getattr(policy_check, "details", "") or "")
            if details:
                reasons.append(details)

        would_action = (
            "DENY" if denied else ("REQUIRE_APPROVAL" if requires_approval else "ALLOW")
        )
        reason = "; ".join(item for item in reasons if item) or (
            "Human approval required" if requires_approval else "Policy allowed"
        )

        if shadow_mode and signed != "REQUIRE_APPROVAL":
            observation = None
            if would_action != "ALLOW":
                observation = {
                    "enabled": True,
                    "would_have_action": would_action,
                    "would_have_blocked": would_action == "DENY",
                    "would_have_required_approval": would_action == "REQUIRE_APPROVAL",
                    "reasons": [item for item in reasons if item][:5],
                }
            effective = "REQUIRE_APPROVAL" if requires_approval else "ALLOW"
            return PolicyDecision(
                effective, would_action, requires_approval, reason, source, observation
            )

        action = (
            "DENY" if denied else ("REQUIRE_APPROVAL" if requires_approval else "ALLOW")
        )
        return PolicyDecision(action, would_action, requires_approval, reason, source)


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
        self.decision_engine = PolicyDecisionEngine()
        self.host_policy = host_policy or HostSecurityPolicy()
        self.events = events or AgentEventRuntime()
        self.delegations = delegations or DelegationRegistry()

    def decide_tool(self, **signals: Any) -> PolicyDecision:
        """Return the canonical ALLOW / DENY / REQUIRE_APPROVAL outcome."""
        return self.decision_engine.decide(**signals)

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
