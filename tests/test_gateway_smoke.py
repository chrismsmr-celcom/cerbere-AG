"""Smoke test end-to-end de la gateway Cerbere.

Vérifie :
1. tools/list expose les outils amonts préfixés et filtrés.
2. Un appel autorisé passe.
3. Un outil hors allowlist est bloqué.
4. Un label inconnu est bloqué.

Prérequis : Node.js/npx et le package MCP installé.
"""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

MCP_DIR = Path(__file__).resolve().parent.parent / "mcp"

pytestmark = pytest.mark.skipif(
    shutil.which("npx") is None,
    reason="npx (Node.js) requis pour le serveur filesystem amont",
)


def test_gateway_smoke(tmp_path):
    import asyncio

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    gateway_file = MCP_DIR / "gateway_server.py"

    assert gateway_file.is_file(), f"gateway_server.py introuvable dans {MCP_DIR}"

    # Utilise un répertoire temporaire compatible Windows et Linux.
    filesystem_root = tmp_path.resolve()

    config = {
        "transport": "stdio",
        "collector_url": "http://localhost:9999",
        "budget": 5.0,
        "servers": [
            {
                "label": "fs",
                "command": [
                    "npx",
                    "-y",
                    "@modelcontextprotocol/server-filesystem",
                    str(filesystem_root),
                ],
                "allowed_tools": ["read_file", "list_directory"],
            }
        ],
    }

    config_path = tmp_path / "gateway.json"
    config_path.write_text(
        json.dumps(config),
        encoding="utf-8",
    )

    child_env = os.environ.copy()
    existing_pythonpath = child_env.get("PYTHONPATH", "")

    child_env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(MCP_DIR), existing_pythonpath) if part
    )

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "gateway_server",
            "--config",
            str(config_path),
        ],
        env=child_env,
    )

    async def scenario():
        results = {}

        async with (
            stdio_client(params) as (read_stream, write_stream),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()

            # 1. Vérifier les outils exposés.
            tools = await session.list_tools()
            names = [tool.name for tool in tools.tools]

            results["listed"] = names

            assert "fs__read_file" in names, (
                f"fs__read_file absent de la liste : {names}"
            )
            assert "fs__list_directory" in names, (
                f"fs__list_directory absent de la liste : {names}"
            )
            assert "fs__write_file" not in names, (
                "write_file est hors allowlist et ne doit pas être exposé"
            )

            # 2. Appel autorisé.
            listing = await session.call_tool(
                "fs__list_directory",
                {"path": str(filesystem_root)},
            )

            results["allowed_call_ok"] = not listing.isError

            # 3. Appel hors allowlist.
            denied = await session.call_tool(
                "fs__write_file",
                {
                    "path": str(filesystem_root / "unauthorized.txt"),
                    "contents": "unauthorized",
                },
            )

            results["denied_call_blocked"] = denied.isError

            # 4. Label inconnu.
            unknown = await session.call_tool(
                "ghost__read_file",
                {"path": str(filesystem_root / "missing.txt")},
            )

            results["unknown_label_blocked"] = unknown.isError

        return results

    results = asyncio.run(scenario())

    assert results["allowed_call_ok"], "Un appel autorisé doit aboutir"
    assert results["denied_call_blocked"], "Un outil hors allowlist doit être bloqué"
    assert results["unknown_label_blocked"], "Un label inconnu doit être bloqué"
