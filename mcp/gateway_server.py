"""Cœur de la gateway Cerbere : multi-upstream, enforcement, deux transports.

Topologie :

    Agent (local)  --stdio--> \
                              \
    Agent (distant) --HTTP/SSE---> Cerbere MCP Gateway ---> Collector
                              /        | enforcement (AgentGuard)
                              |        v
                              /     Serveur amont 1 (fs)
    (aucun code à changer :   \\     Serveur amont N (github, db, ...)

Noms d'outils exposés : "<label>__<tool>" (ex: "fs__read_file"),
ce qui évite les collisions entre serveurs et rend la traçabilité lisible
dans les spans ("mcp:<label>:<tool>" côté AgentGuard).
"""

from __future__ import annotations

import argparse
import asyncio
import contextvars
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from agentguard import SecurityException

try:
    from agentguard import ApprovalRequiredException
except ImportError:  # SDK plus ancien : l'approbation remonte comme SecurityException
    ApprovalRequiredException = SecurityException

from gateway_config import ConfigError, GatewayConfig, ServerSpec, load_config
from gateway_inspection import ResponseInspector

from agentguard.sdk import AgentGuard

# Identité de l'appelant courant (définie par l'auth HTTP, ou défaut en stdio).
current_identity: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "cerbere_identity", default=None
)

# Auth HTTP : clé courant (pour les logs/erreurs), None en stdio.
current_api_key: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "cerbere_api_key", default=None
)


class GuardPool:
    """Un AgentGuard par identité (clé API) : politique et budget dédiés."""

    def __init__(self, config: GatewayConfig) -> None:
        self._config = config
        self._guards: dict[str, AgentGuard] = {}

    def _build(self, agent_id: str, budget: float) -> AgentGuard:
        policies = [
            {
                "type": "tool_whitelist",
                "allowed_tools": [
                    f"mcp:{s.label}:{t}"
                    for s in self._config.servers
                    if not s.allow_all
                    for t in s.allowed_tools
                ]
                + [f"mcp:{s.label}:*" for s in self._config.servers if s.allow_all],
            }
        ]
        return AgentGuard(
            collector_url=self._config.collector_url,
            api_key=current_api_key.get() or None,
            agent_id=agent_id,
            policies=policies,
            max_budget=budget,
            block_on_high=True,
        )

    def get(self, identity: dict[str, Any]) -> AgentGuard:
        agent_id = identity.get("agent_id", self._config.agent_id)
        guard = self._guards.get(agent_id)
        if guard is None:
            guard = self._build(
                agent_id, float(identity.get("budget", self._config.budget))
            )
            self._guards[agent_id] = guard
        return guard


class Upstream:
    """Connexion vers un serveur MCP amont (subprocess stdio)."""

    def __init__(self, spec: ServerSpec) -> None:
        self.spec = spec
        self.session = None  # ClientSession, affecté dans connect()

    async def connect(self):
        from mcp.client.stdio import stdio_client

        from mcp import ClientSession, StdioServerParameters

        params = StdioServerParameters(
            command=self.spec.command[0], args=self.spec.command[1:]
        )
        self._client_ctx = stdio_client(params)
        read, write = await self._client_ctx.__aenter__()
        self.session = ClientSession(read, write)
        await self.session.__aenter__()
        await self.session.initialize()
        return self

    async def close(self) -> None:
        for exit_ in reversed((self.session, getattr(self, "_client_ctx", None))):
            if exit_ is not None:
                try:
                    await exit_.__aexit__(None, None, None)
                except Exception:  # pragma: no cover
                    pass


class CerbereGateway:
    """Assemble upstreams, enforcement et inspection derrière un Server MCP."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.guards = GuardPool(config)
        self.inspector = ResponseInspector(config.redact_pii, config.redact_secrets)
        self.upstreams: dict[str, Upstream] = {}
        self.executor = ThreadPoolExecutor(max_workers=config.workers)
        self._tools_cache: list | None = None

    # ------------------------------------------------------------------ setup
    async def start(self) -> None:
        for spec in self.config.servers:
            try:
                up = Upstream(spec)
                await up.connect()
            except Exception as exc:
                raise ConfigError(
                    f"Failed to start upstream '{spec.label}': {exc}"
                ) from exc
            self.upstreams[spec.label] = up
            allow = "*" if spec.allow_all else ",".join(spec.allowed_tools)
            mode = " (external: taint-enforced)" if spec.external else ""
            sys.stderr.write(
                f"[cerbere-ag-gateway] upstream '{spec.label}' up — "
                f"allowed_tools={allow}{mode}\n"
            )
        if not self.upstreams:
            raise ConfigError("No upstream connected")

    async def stop(self) -> None:
        for up in self.upstreams.values():
            await up.close()
        self.executor.shutdown(wait=False)

    # ------------------------------------------------------------- MCP server
    def build_server(self):
        from mcp.server import Server
        from mcp.types import Tool

        server = Server("cerbere-ag-mcp-gateway")
        inspector = self.inspector
        config = self.config
        guards = self.guards
        executor = self.executor

        def _identity() -> dict[str, Any]:
            identity = current_identity.get()
            if not identity:
                identity = config.key_identity(None)
                current_identity.set(identity)
            return identity

        def _authorize(label: str, tool: str, arguments: dict) -> None:
            """Enforcement AgentGuard, synchrone (exécuté dans un thread)."""
            identity = _identity()
            allowed_servers = identity.get("allowed_servers")
            if allowed_servers is not None and label not in allowed_servers:
                raise SecurityException(
                    f"Server '{label}' is not allowed for this agent identity"
                )
            guard = guards.get(identity)
            guard.guard_tool_call(
                f"mcp:{label}:{tool}",
                params=arguments,
                func=lambda *a, **k: (
                    None
                ),  # no-op : le vrai appel suit, seulement si ALLOW
            )

        @server.list_tools()
        async def list_tools() -> list[Tool]:
            if self._tools_cache is None:
                merged: list[Tool] = []
                for label, up in self.upstreams.items():
                    spec = config.server(label)
                    result = await up.session.list_tools()
                    for tool in result.tools:
                        if not spec.allows(tool.name):
                            continue
                        merged.append(
                            Tool(
                                name=f"{label}__{tool.name}",
                                description=(
                                    f"[{label}] {tool.description or ''}".strip()
                                    + (" (external)" if spec.external else "")
                                ).strip(),
                                inputSchema=tool.inputSchema,
                            )
                        )
                self._tools_cache = merged
            return self._tools_cache

        @server.call_tool()
        async def call_tool(name: str, arguments: dict | None):
            args = arguments or {}
            loop = asyncio.get_running_loop()

            # 1. Résolution <label>__<tool>
            if "__" not in name:
                raise RuntimeError(
                    "Blocked by CerbereAG: tool name must be '<label>__<tool>'"
                )
            label, tool = name.split("__", 1)
            spec = None
            try:
                spec = config.server(label)
            except ConfigError:
                pass
            up = self.upstreams.get(label)
            if up is None or spec is None:
                raise RuntimeError(f"Blocked by CerbereAG: unknown server '{label}'")

            # 2. Allowlist par serveur (fail-closed)
            if not spec.allows(tool):
                sys.stderr.write(
                    f"[cerbere-ag-gateway] DENIED {name}: tool not in allowlist\n"
                )
                raise RuntimeError(
                    f"Blocked by CerbereAG: tool '{tool}' is not allowed on '{label}'"
                )

            # 3. Taint : un secret vu en interne ne sort jamais vers un serveur externe
            if spec.external:
                leak = inspector.taints.find_in_arguments(args)
                if leak:
                    sys.stderr.write(
                        f"[cerbere-ag-gateway] BLOCKED {name}: sensitive taint reaches external sink\n"
                    )
                    raise RuntimeError(
                        "Blocked by CerbereAG: sensitive taint reaches external sink"
                    )

            # 4. Enforcement AgentGuard avant tout forward — fail-closed
            try:
                await loop.run_in_executor(executor, _authorize, label, tool, args)
            except (ApprovalRequiredException, SecurityException) as exc:
                approval_id = getattr(exc, "approval_id", None)
                suffix = f" (approval_id={approval_id})" if approval_id else ""
                sys.stderr.write(f"[cerbere-ag-gateway] BLOCKED {name}: {exc}\n")
                raise RuntimeError(f"Blocked by CerbereAG: {exc}{suffix}") from exc
            except Exception as exc:
                sys.stderr.write(
                    f"[cerbere-ag-gateway] DENIED {name}: authorization unavailable (fail-closed)\n"
                )
                raise RuntimeError(
                    "Blocked by CerbereAG: authorization unavailable (fail-closed)"
                ) from exc

            # 5. Forward vers l'amont, puis inspection de la réponse
            result = await up.session.call_tool(tool, args)
            content = inspector.inspect_content(list(result.content))

            if result.isError:
                text = " ".join(getattr(c, "text", "") for c in content).strip()
                raise RuntimeError(text or "Upstream tool error")
            return content

        return server

    # ------------------------------------------------------------- transports
    async def run_stdio(self) -> None:
        from mcp.server.stdio import stdio_server

        server = self.build_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    async def run_http(self) -> None:
        """Streamable HTTP (nécessite mcp>=1.9). Auth par clé API."""
        try:
            import uvicorn
            from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
            from starlette.applications import Starlette
            from starlette.middleware import Middleware
            from starlette.requests import Request
            from starlette.responses import JSONResponse
            from starlette.routing import Mount
        except ImportError as exc:  # pragma: no cover
            raise ConfigError(
                "HTTP transport needs: pip install 'mcp>=1.9' uvicorn starlette"
            ) from exc

        config = self.config
        server = self.build_server()
        session_manager = StreamableHTTPSessionManager(
            app=server, json_response=True, stateless=True
        )

        async def _authenticate(request: Request, call_next):
            api_key = request.headers.get("x-api-key") or None
            auth = request.headers.get("authorization") or ""
            if not api_key and auth.lower().startswith("bearer "):
                api_key = auth[7:].strip()
            try:
                identity = config.key_identity(api_key)
            except ConfigError:
                return JSONResponse(
                    {"error": "invalid or missing API key"}, status_code=401
                )
            current_api_key.set(api_key)
            current_identity.set(identity)
            return await call_next(request)

        app = Starlette(
            routes=[Mount(config.path, app=session_manager.handle_request)],
            middleware=[Middleware(_authenticate)],
            lifespan=session_manager.run(),
        )
        sys.stderr.write(
            f"[cerbere-ag-gateway] HTTP on http://{config.host}:{config.port}{config.path} "
            f"({len(config.api_keys)} API key(s))\n"
        )
        config_uvicorn = uvicorn.Config(
            app, host=config.host, port=config.port, log_level="info"
        )
        await uvicorn.Server(config_uvicorn).serve()


async def _run(config_path: str | None) -> None:
    config = load_config(config_path)
    gateway = CerbereGateway(config)
    await gateway.start()
    try:
        if config.transport == "http":
            await gateway.run_http()
        else:
            await gateway.run_stdio()
    finally:
        await gateway.stop()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cerbere-ag-gateway",
        description="Cerbere AG universal MCP gateway (stdio or Streamable HTTP)",
    )
    parser.add_argument(
        "--config", default=None, help="Path to gateway config (JSON/YAML)"
    )
    args = parser.parse_args()

    try:
        asyncio.run(_run(args.config))
    except ConfigError as exc:
        sys.stderr.write(f"\n❌ {exc}\n\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
