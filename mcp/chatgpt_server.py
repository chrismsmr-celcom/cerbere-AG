"""Public, read-only MCP endpoint for ChatGPT and other hosted MCP clients.

Only deterministic local utilities are exposed here. Tenant data, audit logs,
API-key administration, and tool execution are intentionally not exposed.
"""

import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp_server import calculate_token_cost, check_prompt_security, redact_pii
from starlette.responses import JSONResponse
from starlette.routing import Route

allowed_hosts = [
    item.strip()
    for item in os.environ.get("CERBERE_MCP_ALLOWED_HOSTS", "").split(",")
    if item.strip()
]
if not allowed_hosts:
    raise RuntimeError(
        "CERBERE_MCP_ALLOWED_HOSTS is required; configure exact public hostnames."
    )

server = FastMCP(
    name="Cerbere AG Security",
    instructions=(
        "Cerbere AG provides local security utilities for AI agent workflows. "
        "Use check_prompt_security before processing untrusted text, redact_pii "
        "before sharing text externally, and calculate_token_cost for estimates. "
        "This public endpoint does not expose tenant data, audit logs, or "
        "privileged execution tools."
    ),
    host="0.0.0.0",
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
    transport_security=TransportSecuritySettings(
        allowed_hosts=allowed_hosts,
        allowed_origins=[],
    ),
)

# Keep this public surface intentionally narrow. Do not register get_audit_trail
# or authorize_tool_call here: those require tenant-scoped identity and policy.
server.tool()(check_prompt_security)
server.tool()(redact_pii)
server.tool()(calculate_token_cost)

# In MCP Python SDK 1.x, transport options are configured on FastMCP's
# constructor; streamable_http_app() itself takes no keyword arguments.
app = server.streamable_http_app()


async def health(_request):
    return JSONResponse({"status": "ok", "transport": "streamable-http"})


app.routes.insert(0, Route("/health", health, methods=["GET"]))
