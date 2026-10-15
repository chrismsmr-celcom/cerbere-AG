"""
AgentGuard Policy Engine — Zero-Trust authorization for AI agents.

Usage:
    from policy import PolicyEngine

    engine = PolicyEngine(policies_dir="./policies")
    decision = engine.evaluate_tool_call(
        agent_id="finance-agent",
        tool_name="send_email",
        params={"to": "client@acme.com", "body": "Hello"},
    )

    if decision.is_allowed():
        # execute tool
        pass
    elif decision.is_denied():
        raise SecurityException(decision.reason)
"""

from .engine import PolicyEngine
from .loader import PolicyLoader
from .models import (
    BudgetLimits,
    Capabilities,
    Decision,
    FailureMode,
    FilesystemCapabilities,
    NetworkCapabilities,
    Policy,
    PolicyDecision,
    Rule,
    ToolCapabilities,
)

__all__ = [
    "BudgetLimits",
    "Capabilities",
    "Decision",
    "FailureMode",
    "FilesystemCapabilities",
    "NetworkCapabilities",
    "Policy",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyLoader",
    "Rule",
    "ToolCapabilities",
]
