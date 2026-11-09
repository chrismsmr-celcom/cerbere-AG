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
import json
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
current_identity: contextvars.ContextVar[dict[str, Any] | None] = (
    contextvars.ContextVar("cerbere_identity", default=None)
)

# Auth HTTP : clé courant (pour les logs/erreurs), None en stdio.
current_api_key: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "cerbere_api_key", default=None
)

# Tarif blended par défaut (USD / million de tokens) pour le budget par serveur.
DEFAULT_PRICE_PER_MTOK = 3.0

class APIKeyAuthMiddleware:
    """ASGI middleware that authenticates each HTTP request and scopes its identity."""

    def __init__(self, app, config: GatewayConfig) -> None:
        self.app = app
        self.config = config

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        api_key = headers.get("x-api-key", "").strip()
        authorization = headers.get("authorization", "").strip()
        if not api_key and authorization.lower().startswith("bearer "):
            api_key = authorization[7:].strip()

        # HTTP must never fall back to the stdio/default identity.
        if not api_key:
            from starlette.responses import JSONResponse
            response = JSONResponse(
                {"error": "invalid or missing API key"}, status_code=401
            )
            await response(scope, receive, send)
            return
        try:
            identity = self.config.key_identity(api_key)
        except ConfigError:
            from starlette.responses import JSONResponse
            response = JSONResponse(
                {"error": "invalid or missing API key"}, status_code=401
            )
            await response(scope, receive, send)
            return

        key_token = current_api_key.set(api_key)
        identity_token = current_identity.set(identity)
        try:
            await self.app(scope, receive, send)
        finally:
            current_identity.reset(identity_token)
            current_api_key.reset(key_token)




class ServerBudgetLedger:
    """Budget USD par (identité, serveur amont).

    Estimation heuristique : ~4 caractères par token, tarif blended
    configurable (défaut 3 $/Mtok). Volontairement conservateur : le but
    est de borner le coût d'un serveur bruyant, pas de facturer au token.
    Fail-closed : budget épuisé ⇒ SecurityException avant tout forward.
    """

    def __init__(self, price_per_mtok: float = DEFAULT_PRICE_PER_MTOK) -> None:
        self._spent: dict[tuple[str, str], float] = {}
        self._price_per_token = price_per_mtok / 1_000_000.0

    @staticmethod
    def _texts(*parts: Any) -> str:
        out: list[str] = []
        for p in parts:
            if isinstance(p, str) and p:
                out.append(p)
        return " ".join(out)

    def estimate_usd(self, *texts: Any) -> float:
        total_chars = len(self._texts(*texts))
        return (total_chars / 4.0) * self._price_per_token

    def check(self, agent_id: str, label: str, budget: float) -> None:
        spent = self._spent.get((agent_id, label), 0.0)
        if spent >= budget:
            sys.stderr.write(
                f"[cerbere-ag-gateway] BUDGET {label} exhausted for '{agent_id}': "
                f"${spent:.4f} >= ${budget:.2f}\n"
            )
            raise SecurityException(
                f"Per-server budget exhausted for '{label}' "
                f"(${spent:.4f} spent >= ${budget:.2f} allowed)"
            )

    def charge(self, agent_id: str, label: str, amount: float) -> float:
        key = (agent_id, label)
        self._spent[key] = self._spent.get(key, 0.0) + amount
        return self._spent[key]


class GuardPool:
    """Un AgentGuard par identité (clé API) : politique et budget dédiés."""

    def __init__(self, config: GatewayConfig) -> None:
        self._config = config
        self._guards: dict[tuple[str, str | None], AgentGuard] = {}

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
        # A guard captures the collector API key at construction time. Keep
        # separate instances when two HTTP credentials share an agent_id.
        cache_key = (agent_id, current_api_key.get())
        guard = self._guards.get(cache_key)
        if guard is None:
            guard = self._build(
                agent_id, float(identity.get("budget", self._config.budget))
            )
            self._guards[cache_key] = guard
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
        self.server_budgets = ServerBudgetLedger()
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
            budget = f", budget=${spec.budget:.2f}" if spec.budget is not None else ""
            sys.stderr.write(
                f"[cerbere-ag-gateway] upstream '{spec.label}' up — "
                f"allowed_tools={allow}{mode}{budget}\n"
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
        ledger = self.server_budgets

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

            # Budget par serveur (fail-closed) : vérifié avant l'enforcement.
            spec = config.server(label)
            if spec.budget is not None:
                ledger.check(identity["agent_id"], label, spec.budget)

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
                # ContextVars are not propagated automatically to a thread pool.
                # Preserve the authenticated identity and API key for enforcement.
                context = contextvars.copy_context()
                await loop.run_in_executor(
                    executor, context.run, _authorize, label, tool, args
                )
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

            # 6. Budget par serveur : charge heuristique (arguments + réponse)
            if spec.budget is not None:
                agent_id = _identity()["agent_id"]
                response_texts = [getattr(c, "text", "") or "" for c in content]
                cost = ledger.estimate_usd(
                    json.dumps(args, ensure_ascii=False, default=str),
                    *response_texts,
                )
                spent = ledger.charge(agent_id, label, cost)
                sys.stderr.write(
                    f"[cerbere-ag-gateway] budget '{label}' for '{agent_id}': "
                    f"+${cost:.6f} → ${spent:.4f} / ${spec.budget:.2f}\n"
                )

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

        app = Starlette(
            routes=[Mount(config.path, app=session_manager.handle_request)],
            middleware=[Middleware(APIKeyAuthMiddleware, config=config)],
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
