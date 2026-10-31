"""Smoke test end-to-end de la gateway Cerbere (gateway + vrai serveur amont).

Vérifie les comportements clés SANS modification du code de l'agent :
  1. tools/list expose les outils amonts préfixés (<label>__<tool>),
     filtrés par l'allowlist
  2. un appel autorisé passe et revient
  3. un outil hors allowlist est BLOQUÉ (fail-closed)
  4. un label inconnu est BLOQUÉ

Prérequis : node/npx (pour le serveur filesystem amont) et mcp installé.
Lancement, depuis la racine du repo :

    pip install -e "mcp[dev]"
    pytest tests/test_gateway_smoke.py -q

Pour tester aussi le taint tracking inter-serveurs et le fail-closed
(collector injoignable), voir le README section "Security layers".
"""

import json
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp"))

pytestmark = pytest.mark.skipif(
    shutil.which("npx") is None, reason="npx (node) requis pour le serveur amont"
)

CONFIG = {
    "transport": "stdio",
    # Collector volontairement injoignable : la policy engine locale reste
    # utilisable, les spans échouent silencieusement. Pour tester le vrai
    # fail-closed (refus si le collector est requis), voir le README.
    "collector_url": "http://localhost:9999",
    "budget": 5.0,
    "servers": [
        {
            "label": "fs",
            "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            "allowed_tools": ["read_file", "list_directory"],
        }
    ],
}


def test_gateway_smoke(tmp_path):
    """Le SDK lance la gateway comme n'importe quel serveur MCP — exactement
    ce que fait l'agent en production (aucune coopération requise)."""
    import asyncio

    from mcp.client.stdio import stdio_client

    from mcp import ClientSession, StdioServerParameters

    mcp_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp"))

    # Échec lisible si le module n'est pas là, plutôt qu'un crash MCP cryptique.
    assert os.path.exists(os.path.join(mcp_dir, "gateway_server.py")), (
        f"gateway_server.py introuvable dans {mcp_dir}"
    )

    config_path = tmp_path / "gateway.json"
    config_path.write_text(json.dumps(CONFIG))

    # Le client MCP stdio n'hérite que d'une liste blanche de variables
    # d'environnement (PATH, HOME, ...) : PYTHONPATH positionné dans os.environ
    # serait ignoré par le sous-processus. On passe donc l'env explicitement.
    child_env = {
        **os.environ,
        "PYTHONPATH": mcp_dir + os.pathsep + os.environ.get("PYTHONPATH", ""),
    }
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gateway_server", "--config", str(config_path)],
        env=child_env,
    )

    async def scenario() -> dict:
        results: dict = {}
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()

            # 1. tools/list : outils amonts préfixés et filtrés
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            results["listed"] = names
            assert "fs__read_file" in names, f"fs__read_file absent de {names}"
            assert "fs__write_file" not in names, (
                "write_file est hors allowlist : il ne doit PAS apparaître"
            )

            # 2. appel autorisé -> doit aboutir
            listing = await session.call_tool("fs__list_directory", {"path": "/tmp"})
            results["allowed_call_ok"] = not listing.isError

            # 3. outil hors allowlist -> BLOQUÉ
            denied = await session.call_tool(
                "fs__write_file", {"path": "/tmp/x", "contents": "x"}
            )
            results["denied_call_blocked"] = denied.isError

            # 4. label inconnu -> BLOQUÉ
            unknown = await session.call_tool("ghost__read_file", {"path": "/tmp"})
            results["unknown_label_blocked"] = unknown.isError
        return results

    results = asyncio.run(scenario())

    assert "fs__read_file" in results["listed"]
    assert results["allowed_call_ok"], "un appel autorisé doit aboutir"
    assert results["denied_call_blocked"], "un outil hors allowlist doit être bloqué"
    assert results["unknown_label_blocked"], "un label inconnu doit être bloqué"
