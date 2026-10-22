"""
AgentGuard MCP Gateway — proxy MCP autonome (roadmap "MCP Gateway/Adapter").

Différence avec mcp_example.py :
  - mcp_example.py modifie le CODE de l'agent (wrap de sa ClientSession).
  - mcp_gateway.py NE MODIFIE RIEN côté agent. Il s'agit d'un vrai serveur
    MCP qui se fait passer pour le serveur cible : l'agent s'y connecte
    normalement (stdio), la gateway forward tools/list tel quel, et
    intercepte CHAQUE tools/call via AgentGuard avant de le transmettre au
    serveur MCP réel en amont (lui-même lancé en subprocess stdio).

Cas d'usage : plusieurs agents/équipes partagent les mêmes serveurs MCP
(filesystem, github, base de données...) et il faut UN point de contrôle
centralisé — cohérent avec le modèle /api/decide déjà en place côté
collector (décisions signées Ed25519, seul un DENY signé fait autorité).

Topologie :

    Agent (Claude Desktop, Claude Code, LangGraph, etc.)
        │  stdio MCP standard — aucune config spéciale côté agent,
        │  juste pointer vers "python mcp_gateway.py" au lieu du
        │  serveur MCP réel dans mcp_config.json / claude_desktop_config.json
        ▼
    AgentGuard MCP Gateway (ce fichier)
        │  tools/list  -> forward tel quel
        │  tools/call  -> guard.guard_tool_call() AVANT forward
        ▼
    Serveur MCP réel (subprocess stdio, ex: @modelcontextprotocol/server-filesystem)

Installer : pip install mcp
Lancer    : python mcp_gateway.py -- npx -y @modelcontextprotocol/server-filesystem /tmp
            (tout ce qui suit "--" est la commande du serveur MCP réel à protéger)

GARANTIE D'ENFORCEMENT :
    Un tools/call n'atteint le serveur amont QUE si guard.guard_tool_call()
    est revenu sans exception. Toute exception (blocage, approbation requise,
    collector injoignable, erreur interne) refuse l'appel : fail-closed.
    stdout est réservé au protocole MCP : la gateway n'écrit que sur stderr.

WHITELIST DES OUTILS :
    AGENTGUARD_MCP_ALLOWED_TOOLS : liste d'outils séparés par virgules.
        Ex : AGENTGUARD_MCP_ALLOWED_TOOLS="read_file,write_file,list_directory"
    La valeur "*" autorise tous les outils du serveur amont (équivalent du
    comportement historique), mais elle doit être un CHOIX EXPLICITE : un
    avertissement est loggé au démarrage.
    Si la variable est absente ou vide, la gateway REFUSE DE DÉMARRER
    (fail-closed : mieux vaut un échec de config clair qu'une gateway qui
    bloque tout ou, pire, qui laisserait tout passer par accident de config).
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from concurrent.futures import ThreadPoolExecutor

from agentguard import SecurityException
from agentguard.sdk import AgentGuard

try:
    from agentguard import ApprovalRequiredException
except ImportError:  # SDK plus ancien : l'approbation remonte comme SecurityException
    ApprovalRequiredException = SecurityException

_executor = ThreadPoolExecutor(
    max_workers=int(os.environ.get("AGENTGUARD_MCP_WORKERS", "4"))
)
SERVER_LABEL = os.environ.get("AGENTGUARD_MCP_SERVER_LABEL", "upstream")


def _build_allowed_tools() -> list[str]:
    """Construit la whitelist d'outils depuis l'environnement.

    Fail-closed : sans AGENTGUARD_MCP_ALLOWED_TOOLS défini, la gateway
    refuse de démarrer avec un message explicite plutôt que de tourner
    avec une whitelist symbolique qui ne protège rien.
    """
    raw = os.environ.get("AGENTGUARD_MCP_ALLOWED_TOOLS", "").strip()

    if not raw:
        sys.stderr.write(
            "\n❌ AGENTGUARD_MCP_ALLOWED_TOOLS n'est pas défini.\n"
            "   La gateway refuse de démarrer sans une whitelist explicite.\n\n"
            "   Définis les outils du serveur MCP autorisés, séparés par virgules :\n"
            '     export AGENTGUARD_MCP_ALLOWED_TOOLS="read_file,write_file,list_directory"\n\n'
            "   Pour autoriser explicitement TOUS les outils du serveur (choix conscient) :\n"
            '     export AGENTGUARD_MCP_ALLOWED_TOOLS="*"\n'
            "   (dans ce cas, la protection repose sur les autres couches AgentGuard :\n"
            "    budget, taint tracking, runtime risk — pas sur la whitelist d'outils)\n\n"
        )
        sys.exit(2)

    tools = [t.strip() for t in raw.split(",") if t.strip()]

    if not tools:
        sys.stderr.write("\n❌ AGENTGUARD_MCP_ALLOWED_TOOLS est vide ou mal formé.\n\n")
        sys.exit(2)

    if "*" in tools:
        sys.stderr.write(
            "\n⚠️  AGENTGUARD_MCP_ALLOWED_TOOLS='*' : TOUS les outils du serveur amont "
            "sont autorisés.\n"
            "   La protection repose uniquement sur les autres couches AgentGuard "
            "(budget, taint, runtime risk).\n"
            "   Assure-toi que c'est un choix délibéré.\n\n"
        )
        return [f"mcp:{SERVER_LABEL}:*"]

    # Préfixage : la gateway nomme les outils "mcp:<label>:<tool>"
    return [f"mcp:{SERVER_LABEL}:{t}" for t in tools]


ALLOWED_TOOLS = _build_allowed_tools()

guard = AgentGuard(
    collector_url=os.environ.get("AGENTGUARD_COLLECTOR_URL", "http://localhost:8080"),
    api_key=os.environ.get("AGENTGUARD_API_KEY"),
    policies=[
        {"type": "tool_whitelist", "allowed_tools": ALLOWED_TOOLS},
    ],
    max_budget=float(os.environ.get("AGENTGUARD_MAX_BUDGET", "5.0")),
    block_on_high=True,
)

sys.stderr.write(
    f"[agentguard-mcp-gateway] server='{SERVER_LABEL}' "
    f"allowed_tools={ALLOWED_TOOLS} "
    f"budget={os.environ.get('AGENTGUARD_MAX_BUDGET', '5.0')}\n"
)


def _authorize(tool_name: str, arguments: dict) -> None:
    """Fait autoriser l'appel par AgentGuard. Lève une exception s'il est refusé.

    Synchrone (le SDK l'est) : la gateway l'exécute dans un thread.
    La fonction passée à guard_tool_call est volontairement un no-op : le
    VRAI appel amont est fait par la gateway, uniquement si cette fonction
    revient sans exception.
    """
    guard.guard_tool_call(
        f"mcp:{SERVER_LABEL}:{tool_name}",
        params=arguments,
        func=lambda *args, **kwargs: None,
    )


async def run_gateway(upstream_command: list[str]) -> None:
    from mcp.client.stdio import stdio_client
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool

    from mcp import ClientSession, StdioServerParameters

    upstream_params = StdioServerParameters(
        command=upstream_command[0],
        args=upstream_command[1:],
    )

    gateway = Server(f"agentguard-mcp-gateway::{SERVER_LABEL}")

    async with (
        stdio_client(upstream_params) as (up_read, up_write),
        ClientSession(up_read, up_write) as upstream,
    ):
        await upstream.initialize()

        @gateway.list_tools()
        async def list_tools() -> list[Tool]:
            result = await upstream.list_tools()
            return result.tools

        @gateway.call_tool()
        async def call_tool(name: str, arguments: dict | None) -> list:
            args = arguments or {}
            loop = asyncio.get_running_loop()

            # 1. Autorisation AVANT tout forward. Fail-closed sur toute exception.
            try:
                await loop.run_in_executor(_executor, _authorize, name, args)
            except (ApprovalRequiredException, SecurityException) as exc:
                approval_id = getattr(exc, "approval_id", None)
                suffix = f" (approval_id={approval_id})" if approval_id else ""
                sys.stderr.write(f"[agentguard-mcp-gateway] BLOCKED {name}: {exc}\n")
                raise RuntimeError(f"Blocked by CerbereAG: {exc}{suffix}") from exc
            except Exception as exc:
                sys.stderr.write(
                    f"[agentguard-mcp-gateway] DENIED {name}: authorization error: {exc}\n"
                )
                raise RuntimeError(
                    "Blocked by CerbereAG: authorization unavailable (fail-closed)"
                ) from exc

            # 2. Seulement ici : transmission au serveur MCP réel.
            result = await upstream.call_tool(name, args)

            if result.isError:
                text = " ".join(getattr(c, "text", "") for c in result.content).strip()
                raise RuntimeError(text or "Upstream tool error")

            return list(result.content)

        # 3. Le transport vers l'agent démarre une fois les handlers en place.
        async with stdio_server() as (read, write):
            await gateway.run(read, write, gateway.create_initialization_options())


def main() -> None:
    argv = sys.argv[1:]

    if "--" not in argv or not argv[argv.index("--") + 1 :]:
        sys.stderr.write(
            "Usage: python mcp_gateway.py -- <commande du serveur MCP amont>\n"
            "Ex   : python mcp_gateway.py -- npx -y "
            "@modelcontextprotocol/server-filesystem /tmp\n"
        )
        sys.exit(2)

    upstream_command = argv[argv.index("--") + 1 :]
    asyncio.run(run_gateway(upstream_command))


if __name__ == "__main__":
    main()
