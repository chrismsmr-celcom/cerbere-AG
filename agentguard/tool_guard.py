"""
Cerbere / AgentGuard — Zero Trust Tool Guard

All tool execution passes through DecisionEngine.

Unknown tool:
    BLOCK

Unauthorized identity:
    BLOCK

Malicious taint:
    BLOCK

High-risk:
    BLOCK

Policy requiring approval:
    REQUIRE_APPROVAL

Safe:
    ALLOW

HITL lifecycle:
    REQUIRE_APPROVAL -> persisted approval request -> human decision
    -> APPROVED retry -> (all controls re-evaluated) -> ALLOW, once

An approval authorizes ONE precise action. It never disables the other
controls: tool registration, identity, argument size and hard BLOCK decisions
are re-evaluated on every retry, and the approval is consumed atomically so it
cannot be replayed.

The guard never executes a tool itself. It only authorizes or rejects
execution before the caller performs the actual side effect.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from agentguard.decision_engine import (
    Decision,
    DecisionEngine,
    DecisionRequest,
    PolicyRule,
)


class ToolBlocked(Exception):
    """Raised when AgentGuard blocks a tool call."""


class ApprovalRequired(Exception):
    """Raised when human approval is required."""

    def __init__(self, reason: str, approval_id: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.approval_id = approval_id


@dataclass
class ToolPolicy:
    name: str

    allowed_identities: set[str] = field(default_factory=set)

    category: str = "read"

    read_only: bool = True

    external_side_effect: bool = False

    irreversible: bool = False

    require_approval: bool = False

    max_argument_bytes: int = 50_000

    blocked: bool = False


@dataclass
class ToolRequest:
    tool_name: str

    identity: str

    arguments: dict[str, Any]

    model_score: float = 0.0

    anomaly_score: float = 0.0

    taint_level: str = "PUBLIC"

    trajectory_length: int = 0

    previous_risky_actions: int = 0

    agent_id: str = ""

    session_id: str = ""

    org_id: str = ""

    tenant_id: str = ""

    trace_id: str = ""

    span_id: str = ""

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolDecision:
    allowed: bool

    decision: str

    reason: str

    risk_score: float

    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def requires_approval(self) -> bool:
        return self.decision == "require_approval"


def _arguments_hash(arguments: Any) -> str:
    """
    Create a deterministic hash of tool arguments.

    The hash binds an approval to the exact arguments that were reviewed.
    """

    payload = json.dumps(
        arguments if arguments is not None else {},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def _approval_matches_request(
    approval: dict[str, Any],
    request: ToolRequest,
) -> bool:
    """
    Ensure an approval cannot be replayed for another action or context.

    Every binding is mandatory: organization, tenant, tool, agent, session
    and the exact arguments hash. An approval without an arguments hash
    never matches.
    """

    if approval.get("status") != "approved":
        return False

    if (approval.get("org_id") or "") != (request.org_id or ""):
        return False

    if (approval.get("tenant_id") or "") != (request.tenant_id or ""):
        return False

    if approval.get("tool_name") != request.tool_name:
        return False

    expected_agent = request.agent_id or request.identity

    if (approval.get("agent_id") or "") != (expected_agent or ""):
        return False

    if (approval.get("session_id") or "") != (request.session_id or ""):
        return False

    approved_hash = approval.get("arguments_hash")

    return bool(approved_hash) and approved_hash == _arguments_hash(request.arguments)


class ToolGuard:
    def __init__(
        self,
        policies=None,
    ):

        self.policies: dict[str, ToolPolicy] = {
            policy.name: policy for policy in (policies or [])
        }

        self.decision_engine = DecisionEngine()

        self._sync_engine_policies()

    # -------------------------------------------------------------
    # Policy registration
    # -------------------------------------------------------------

    def _sync_engine_policies(self):

        allowed_tools = set(self.policies.keys())

        blocked_tools = {
            name for name, policy in self.policies.items() if policy.blocked
        }

        approval_tools = {
            name for name, policy in self.policies.items() if policy.require_approval
        }

        self.decision_engine.register_policy(
            PolicyRule(
                name="tool_guard",
                allowed_tools=allowed_tools,
                blocked_tools=blocked_tools,
                require_approval_for=approval_tools,
                allow_unknown_tools=False,
            )
        )

    def register(
        self,
        policy: ToolPolicy,
    ) -> None:

        self.policies[policy.name] = policy

        self._sync_engine_policies()

    # -------------------------------------------------------------
    # Static checks (always run, with or without an approval)
    # -------------------------------------------------------------

    def _static_checks(
        self,
        request: ToolRequest,
    ) -> tuple[ToolPolicy | None, ToolDecision | None]:
        """
        Tool registration, identity and argument-size checks.

        Returns (policy, None) when the request passes, or
        (None, decision) with the blocking decision otherwise.
        """

        policy = self.policies.get(request.tool_name)

        # Unknown tool
        if policy is None:
            return None, ToolDecision(
                allowed=False,
                decision="block",
                reason=("Tool is not registered in AgentGuard policy"),
                risk_score=100,
                metadata={
                    "reason_code": "tool",
                    "tool": request.tool_name,
                },
            )

        # Identity
        if (
            policy.allowed_identities
            and request.identity not in policy.allowed_identities
        ):
            return None, ToolDecision(
                allowed=False,
                decision="block",
                reason=("Agent identity is not authorized for this tool"),
                risk_score=100,
                metadata={
                    "reason_code": "identity",
                    "tool": request.tool_name,
                    "identity": request.identity,
                },
            )

        # Serialize arguments safely
        try:
            serialized = json.dumps(
                request.arguments,
                default=str,
                ensure_ascii=False,
            )

            argument_size = len(serialized.encode("utf-8"))

        except Exception:
            return None, ToolDecision(
                allowed=False,
                decision="block",
                reason=("Tool arguments could not be serialized safely"),
                risk_score=100,
                metadata={"reason_code": "validation"},
            )

        # Argument size
        if argument_size > policy.max_argument_bytes:
            return None, ToolDecision(
                allowed=False,
                decision="block",
                reason=("Tool argument size exceeds policy limit"),
                risk_score=90,
                metadata={
                    "reason_code": "argument_size",
                    "argument_bytes": argument_size,
                    "limit": policy.max_argument_bytes,
                },
            )

        return policy, None

    # -------------------------------------------------------------
    # Unified decision engine
    # -------------------------------------------------------------

    def _evaluate_engine(
        self,
        request: ToolRequest,
        policy: ToolPolicy,
    ):
        metadata = dict(request.metadata)

        metadata.update(
            {
                "policy": "tool_guard",
                "tool_category": policy.category,
                "session_id": request.session_id,
            }
        )

        return self.decision_engine.evaluate(
            DecisionRequest(
                agent_id=(request.agent_id or request.identity),
                tool_name=request.tool_name,
                tool_category=policy.category,
                identity_trusted=True,
                model_score=request.model_score,
                anomaly_score=request.anomaly_score,
                taint_level=request.taint_level,
                trajectory_length=(request.trajectory_length),
                previous_risky_actions=(request.previous_risky_actions),
                external_side_effect=(policy.external_side_effect),
                irreversible=(policy.irreversible),
                tool_registered=True,
                metadata=metadata,
            )
        )

    # -------------------------------------------------------------
    # Approved retry
    # -------------------------------------------------------------

    def _approved_retry(
        self,
        request: ToolRequest,
        engine_result,
    ) -> ToolDecision:
        """
        Validate a previously approved request.

        Called AFTER the static checks and a fresh engine evaluation, so the
        approval can never override a hard BLOCK, a revoked identity or an
        unregistered tool.

        The approval is bound to organization, tenant, tool, agent, session
        and exact arguments, and is consumed atomically (single use).
        """

        approval_id = str(request.metadata.get("approval_id"))

        # A hard BLOCK still blocks, approval or not.
        if engine_result.decision == Decision.BLOCK:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason=(
                    "Approved action is now blocked by policy: "
                    + "; ".join(engine_result.reasons)
                ),
                risk_score=engine_result.risk_score,
                metadata={
                    **engine_result.to_dict(),
                    "reason_code": "approval_revalidation_blocked",
                    "approval_id": approval_id,
                },
            )

        # An authenticated organization is mandatory.
        if not request.org_id:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Approval requires an authenticated organization",
                risk_score=100,
                metadata={
                    "reason_code": "approval_org_required",
                    "approval_id": approval_id,
                },
            )

        from collector.approvals import consume_approval, get_approval

        try:
            approval = get_approval(
                approval_id,
                org_id=request.org_id,
            )
        except Exception as exc:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Approval could not be verified; action blocked",
                risk_score=100,
                metadata={
                    "reason_code": "approval_lookup_failure",
                    "approval_id": approval_id,
                    "error": str(exc)[:200],
                },
            )

        if approval is None:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Approval request was not found",
                risk_score=100,
                metadata={
                    "reason_code": "approval_not_found",
                    "approval_id": approval_id,
                },
            )

        if not _approval_matches_request(
            approval,
            request,
        ):
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Approval does not match this tool request",
                risk_score=100,
                metadata={
                    "reason_code": "approval_mismatch",
                    "approval_id": approval_id,
                },
            )

        # Spend the approval LAST, once everything else has passed, so a
        # request blocked above does not burn a valid approval.
        try:
            consumed = consume_approval(
                approval_id,
                org_id=request.org_id,
            )
        except Exception as exc:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Approval could not be consumed; action blocked",
                risk_score=100,
                metadata={
                    "reason_code": "approval_consume_failure",
                    "approval_id": approval_id,
                    "error": str(exc)[:200],
                },
            )

        if not consumed:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="Approval was already used or has expired",
                risk_score=100,
                metadata={
                    "reason_code": "approval_already_used",
                    "approval_id": approval_id,
                },
            )

        return ToolDecision(
            allowed=True,
            decision="allow",
            reason="Human approval granted",
            risk_score=engine_result.risk_score,
            metadata={
                "reason_code": "human_approval",
                "approval_id": approval_id,
                "approved_by": approval.get("decided_by"),
                "arguments_hash": approval.get("arguments_hash"),
            },
        )

    # -------------------------------------------------------------
    # Approval persistence
    # -------------------------------------------------------------

    def _create_or_reuse_approval(
        self,
        request: ToolRequest,
        decision: ToolDecision,
    ) -> ToolDecision:
        """
        Persist a pending approval.

        If the same request is already pending, reuse its approval ID
        instead of creating duplicate approval requests.
        """

        from collector.approvals import (
            create_approval,
            list_approvals,
        )

        argument_hash = _arguments_hash(request.arguments)

        agent_id = request.agent_id or request.identity

        # Avoid approval spam when an agent retries while
        # the human is still deciding.
        try:
            pending = list_approvals(
                org_id=request.org_id or None,
                status="pending",
                limit=200,
            )

            for approval in pending:
                if (
                    approval.get("tool_name") == request.tool_name
                    and approval.get("agent_id") == agent_id
                    and approval.get("session_id") == request.session_id
                    and approval.get("arguments_hash") == argument_hash
                ):
                    approval_id = approval.get("approval_id")

                    return ToolDecision(
                        allowed=False,
                        decision="require_approval",
                        reason=decision.reason,
                        risk_score=decision.risk_score,
                        metadata={
                            **decision.metadata,
                            "approval_id": approval_id,
                            "approval_status": "pending",
                            "arguments_hash": argument_hash,
                        },
                    )

        except Exception:
            # Persistence errors are handled below.
            pass

        approval = create_approval(
            tool_name=request.tool_name,
            arguments=request.arguments,
            org_id=request.org_id or None,
            tenant_id=request.tenant_id or None,
            agent_id=agent_id,
            session_id=request.session_id or None,
            trace_id=request.trace_id or None,
            span_id=request.span_id or None,
            risk_score=decision.risk_score,
            reason=decision.reason,
            policy_name=request.tool_name,
        )

        approval_id = approval["approval_id"]

        return ToolDecision(
            allowed=False,
            decision="require_approval",
            reason=decision.reason,
            risk_score=decision.risk_score,
            metadata={
                **decision.metadata,
                "approval_id": approval_id,
                "approval_status": "pending",
                "arguments_hash": argument_hash,
            },
        )

    # -------------------------------------------------------------
    # Authorization
    # -------------------------------------------------------------

    def authorize(
        self,
        request: ToolRequest,
    ) -> ToolDecision:

        # Static checks ALWAYS run first, including for approved retries:
        # an approval must never bypass tool registration, identity or
        # argument-size controls.
        policy, early_decision = self._static_checks(request)

        if early_decision is not None:
            return early_decision

        # Fresh engine evaluation, also for approved retries.
        result = self._evaluate_engine(request, policy)

        # A previously approved action can be retried: the approval
        # authorizes this exact action once, nothing else.
        if request.metadata.get("approval_id"):
            return self._approved_retry(request, result)

        # ---------------------------------------------------------
        # BLOCK
        # ---------------------------------------------------------

        if result.decision == Decision.BLOCK:
            return ToolDecision(
                allowed=False,
                decision="block",
                reason="; ".join(result.reasons),
                risk_score=result.risk_score,
                metadata=result.to_dict(),
            )

        # ---------------------------------------------------------
        # REQUIRE APPROVAL
        # ---------------------------------------------------------

        if result.decision == Decision.REQUIRE_APPROVAL:
            base_decision = ToolDecision(
                allowed=False,
                decision="require_approval",
                reason="; ".join(result.reasons),
                risk_score=result.risk_score,
                metadata=result.to_dict(),
            )

            try:
                return self._create_or_reuse_approval(
                    request,
                    base_decision,
                )

            except Exception as exc:
                # Fail closed:
                # if the approval cannot be persisted,
                # the side effect must not happen.
                return ToolDecision(
                    allowed=False,
                    decision="block",
                    reason=("Approval could not be persisted; action blocked"),
                    risk_score=100,
                    metadata={
                        "reason_code": ("approval_persistence_failure"),
                        "error": str(exc)[:200],
                    },
                )

        # ---------------------------------------------------------
        # ALLOW
        # ---------------------------------------------------------

        return ToolDecision(
            allowed=True,
            decision="allow",
            reason="Tool call authorized",
            risk_score=result.risk_score,
            metadata=result.to_dict(),
        )

    # -------------------------------------------------------------
    # Enforcement helper
    # -------------------------------------------------------------

    def enforce(
        self,
        request: ToolRequest,
    ) -> ToolDecision:

        decision = self.authorize(request)

        if decision.decision == "block":
            raise ToolBlocked(decision.reason)

        if decision.decision == "require_approval":
            raise ApprovalRequired(
                decision.reason,
                approval_id=decision.metadata.get("approval_id"),
            )

        return decision
