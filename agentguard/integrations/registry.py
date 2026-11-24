"""Machine-readable integration registry and normalized event contract.

Adapters describe what they can observe; they must never claim coverage for
surfaces they cannot intercept. The registry is intentionally independent of
any one agent framework.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Integration:
    id: str
    name: str
    kind: str
    status: str
    surfaces: tuple[str, ...]
    events: tuple[str, ...]
    enforcement: tuple[str, ...]
    notes: str


_INTEGRATIONS = (
    Integration(
        id="claude-code",
        name="Claude Code",
        kind="coding_agent",
        status="experimental",
        surfaces=("mcp", "native_hooks"),
        events=("prompt.submit", "tool.pre", "tool.post", "session.stop"),
        enforcement=("tool.pre",),
        notes="Native PreToolUse enforcement is experimental; direct OS activity outside configured hooks is not covered.",
    ),
    Integration(
        id="cursor",
        name="Cursor",
        kind="coding_agent",
        status="mcp",
        surfaces=("mcp",),
        events=("mcp.tool.call",),
        enforcement=("mcp.tool.call",),
        notes="MCP-routed tool calls only; native terminal and filesystem actions are not implied.",
    ),
    Integration(
        id="codex",
        name="Codex",
        kind="coding_agent",
        status="planned",
        surfaces=(),
        events=(),
        enforcement=(),
        notes="Native adapter not shipped yet.",
    ),
    Integration(
        id="mcp-client",
        name="MCP-compatible agent",
        kind="agent_protocol",
        status="available",
        surfaces=("mcp_server", "mcp_gateway"),
        events=("mcp.tool.call", "mcp.tool.result"),
        enforcement=("mcp.tool.call", "mcp.tool.result"),
        notes="Coverage depends on the client routing its tool traffic through Cerbere.",
    ),
)


def list_integrations(*, kind: str | None = None) -> list[dict]:
    """Return stable, JSON-serializable integration metadata."""
    items = (item for item in _INTEGRATIONS if kind is None or item.kind == kind)
    return [asdict(item) for item in items]


def get_integration(integration_id: str) -> Integration | None:
    """Look up an integration by its stable identifier."""
    return next((item for item in _INTEGRATIONS if item.id == integration_id), None)


def normalize_event(
    *,
    integration: str,
    event_type: str,
    agent_id: str,
    session_id: str = "",
    tool_name: str = "",
    arguments: dict | None = None,
    result: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Create the shared event envelope consumed by adapters and telemetry."""
    if get_integration(integration) is None:
        raise ValueError(f"Unknown integration: {integration}")
    if not event_type or not agent_id:
        raise ValueError("event_type and agent_id are required")
    return {
        "schema_version": "1",
        "integration": integration,
        "event_type": event_type,
        "agent_id": agent_id,
        "session_id": session_id,
        "tool_name": tool_name,
        "arguments": arguments or {},
        "result": result,
        "metadata": metadata or {},
    }
