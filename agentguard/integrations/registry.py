"""Central registry for agent and framework integration coverage.

Statuses describe verified connection surfaces, not marketing claims.
Each adapter owns event normalization; the registry exposes its declared
coverage so docs, tests and future tooling can query it consistently.
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
        surfaces=("native_hooks", "mcp"),
        events=("tool.pre",),
        enforcement=("tool.pre",),
        notes="PreToolUse only; post-tool results and other lifecycle events are not covered.",
    ),
    Integration(
        id="cursor",
        name="Cursor",
        kind="coding_agent",
        status="experimental",
        surfaces=("native_hooks", "mcp"),
        events=("tool.pre", "shell.pre", "mcp.tool.pre"),
        enforcement=("tool.pre", "shell.pre", "mcp.tool.pre"),
        notes="Initial pre-execution hooks; result-side inspection is not included.",
    ),
    Integration(
        id="codex",
        name="Codex",
        kind="coding_agent",
        status="planned",
        surfaces=(),
        events=(),
        enforcement=(),
        notes="Native adapter not shipped.",
    ),
    Integration(
        id="mcp-gateway",
        name="MCP Gateway",
        kind="agent_protocol",
        status="available",
        surfaces=("mcp_gateway",),
        events=("mcp.tool.pre", "mcp.tool.result"),
        enforcement=("mcp.tool.pre", "mcp.tool.result"),
        notes="Only traffic routed through the gateway is covered.",
    ),
    Integration(id="langchain", name="LangChain", kind="framework", status="planned", surfaces=("python_sdk",), events=("llm.call", "tool.pre", "tool.result"), enforcement=(), notes="Registry entry only; verified adapter not shipped yet."),
    Integration(id="crewai", name="CrewAI", kind="framework", status="planned", surfaces=("python_sdk",), events=("agent.start", "tool.pre", "tool.result", "agent.delegate"), enforcement=(), notes="Registry entry only; verified adapter not shipped yet."),
    Integration(id="openai-agents", name="OpenAI Agents SDK", kind="framework", status="planned", surfaces=("python_sdk",), events=("agent.start", "tool.pre", "tool.result", "agent.delegate"), enforcement=(), notes="Registry entry only; verified adapter not shipped yet."),
    Integration(id="google-adk", name="Google ADK", kind="framework", status="planned", surfaces=("python_sdk",), events=("agent.start", "tool.pre", "tool.result", "agent.delegate"), enforcement=(), notes="Registry entry only; verified adapter not shipped yet."),
    Integration(id="pydantic-ai", name="Pydantic AI", kind="framework", status="planned", surfaces=("python_sdk",), events=("agent.start", "tool.pre", "tool.result"), enforcement=(), notes="Registry entry only; verified adapter not shipped yet."),
    Integration(id="business-agent", name="Business Agent (generic)", kind="business_agent", status="planned", surfaces=("python_sdk", "mcp"), events=("agent.start", "tool.pre", "tool.result", "network.egress"), enforcement=(), notes="Generic category for CRM, finance, support and operations agents; not a vendor adapter."),
    Integration(id="workflow-agent", name="Workflow Agent (generic)", kind="workflow_agent", status="planned", surfaces=("python_sdk", "mcp"), events=("agent.start", "tool.pre", "tool.result", "agent.delegate"), enforcement=(), notes="Generic category for workflow automation agents; not a vendor adapter."),
    Integration(
        id="python-sdk",
        name="Python SDK",
        kind="framework",
        status="available",
        surfaces=("sdk",),
        events=("llm.call", "tool.call"),
        enforcement=("llm.call", "tool.call"),
        notes="Decorators and AgentGuard SDK instrumentation.",
    ),
)


def list_integrations(*, kind: str | None = None) -> list[dict]:
    """Return stable, JSON-serializable integration metadata."""
    items = (item for item in _INTEGRATIONS if kind is None or item.kind == kind)
    return [asdict(item) for item in items]


def get_integration(integration_id: str) -> Integration | None:
    """Look up an integration by its stable identifier."""
    return next((item for item in _INTEGRATIONS if item.id == integration_id), None)
