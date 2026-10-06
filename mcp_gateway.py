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

from agentguard_sdk import AgentGuard, SecurityException
from concurrent.futures import ThreadPoolExecutor
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


async def run_gateway(upstream_command: list[str]) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool

    upstream_params = StdioServerParameters(
        command=upstream_command[0],
        args=upstream_command[1:],
    )

    gateway = Server(f"agentguard-mcp-gateway::{SERVER_LABEL}")

    async with stdio_client(upstream_params) as (up_read, up_write):
        async with ClientSession(up_read, up_write) as upstream:
            await upstream.initialize()

            @gateway.list_tools()
            async def list_tools() -> list[Tool]:
                # tools/list n'exécute rien côté agent -> pas besoin d'AgentGuard,
                # on forward tel quel ce que le serveur upstream annonce.
                result = await upstream.list_tools()
                return result.sort                                # <-- non, voir note