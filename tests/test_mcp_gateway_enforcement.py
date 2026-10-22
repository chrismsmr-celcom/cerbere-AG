"""
La gateway MCP doit refuser un outil hors whitelist AVANT tout forward amont.

On teste la fonction d'autorisation synchrone (_authorize), qui est la seule
porte vers le serveur amont : le handler call_tool ne forward que si elle
revient sans exception. Aucun package `mcp` n'est nécessaire.
"""

import importlib
import os
import sys

import pytest

from agentguard import SecurityException


def _load_gateway(monkeypatch, allowed_tools="read_file", label="fs"):
    monkeypatch.setenv("AGENTGUARD_MCP_ALLOWED_TOOLS", allowed_tools)
    monkeypatch.setenv("AGENTGUARD_MCP_SERVER_LABEL", label)
    monkeypatch.setenv("AGENTGUARD_API_KEY", "ag-test")
    monkeypatch.setenv("AGENTGUARD_STATUS_CHECK", "false")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)

    from collector import mcp_gateway

    return importlib.reload(mcp_gateway)


def test_unlisted_tool_is_refused_before_any_forward(monkeypatch):
    mod = _load_gateway(monkeypatch, allowed_tools="read_file")

    with pytest.raises(SecurityException):
        mod._authorize("rm_rf", {"path": "/"})


def test_tool_from_another_server_label_is_refused(monkeypatch):
    mod = _load_gateway(monkeypatch, allowed_tools="read_file", label="fs")

    # "read_file" est autorisé pour "fs" ; un nom déjà préfixé d'un autre
    # serveur ne doit pas passer par la porte de ce serveur.
    with pytest.raises(SecurityException):
        mod._authorize("mcp:github:create_issue", {})
