"""
Tests de la correction "Whitelist MCP symbolique" :

1. Le PolicyEngine supporte désormais le matching par préfixe
   (entrées "xxx:*") — c'est ce qui rendait la gateway inopérante.
2. La gateway construit sa whitelist depuis AGENTGUARD_MCP_ALLOWED_TOOLS
   et refuse de démarrer (exit 2) si elle est vide.

Aucun test ne nécessite le package `mcp` : on teste les fonctions
pures (_tool_matches_whitelist, _build_allowed_tools) et le
PolicyEngine, pas le transport stdio.
"""
import importlib
import os
import sys

import pytest

from agentguard.policy import PolicyEngine, _tool_matches_whitelist


# ==============================================================
# 1. MATCHING WILDCARD DU POLICY ENGINE
# ==============================================================

class TestToolMatchesWhitelist:

    def test_exact_match(self):
        assert _tool_matches_whitelist("read_file", {"read_file"})

    def test_exact_mismatch(self):
        assert not _tool_matches_whitelist("write_file", {"read_file"})

    def test_prefix_wildcard_matches(self):
        assert _tool_matches_whitelist("mcp:fs:read_file", {"mcp:fs:*"})

    def test_prefix_wildcard_blocks_other_server(self):
        # "mcp:fs:*" ne doit PAS autoriser un autre serveur
        assert not _tool_matches_whitelist("mcp:github:create_issue", {"mcp:fs:*"})

    def test_bare_star_matches_nothing(self):
        # "*" seul ne matche RIEN au niveau du policy engine :
        # autoriser tout doit rester un choix explicite de la gateway.
        assert not _tool_matches_whitelist("any_tool", {"*"})

    def test_prefix_wildcard_requires_separator_consistency(self):
        # "mcp:fs:*" -> préfixe "mcp:fs:" ; "mcp:fsx:read" ne matche pas
        assert not _tool_matches_whitelist("mcp:fsx:read", {"mcp:fs:*"})


class TestPolicyEngineWildcard:

    def _engine(self, tools):
        return PolicyEngine(
            policies=[{"type": "tool_whitelist", "allowed_tools": tools}]
        )

    def test_wildcard_allows_prefixed_tool(self):
        engine = self._engine(["mcp:fs:*"])
        check = engine.check_tool_policy("mcp:fs:read_file", {"path": "/tmp/a"}, 10.0)
        assert check.passed, check.details

    def test_wildcard_blocks_unlisted_tool(self):
        engine = self._engine(["mcp:fs:read_file"])
        check = engine.check_tool_policy("mcp:fs:rm_rf", {"path": "/"}, 10.0)
        assert not check.passed
        assert check.risk_level.name == "CRITICAL"

    def test_exact_match_still_works(self):
        engine = self._engine(["web_search"])
        assert engine.check_tool_policy("web_search", {}, 10.0).passed
        assert not engine.check_tool_policy("web_search_v2", {}, 10.0).passed

    def test_scoped_agent_wildcard(self):
        engine = PolicyEngine(
            policies=[{
                "type": "tool_whitelist",
                "allowed_tools": ["mcp:db:*"],
                "agents": ["agent-42"],
            }]
        )
        # L'agent scoped : le wildcard préfixe s'applique
        assert engine.check_tool_policy(
            "mcp:db:query", {"sql": "SELECT 1"}, 10.0, agent_id="agent-42"
        ).passed
        # L'agent scoped ne voit QUE sa whitelist :
        assert not engine.check_tool_policy(
            "mcp:db2:query", {"sql": "SELECT 1"}, 10.0, agent_id="agent-42"
        ).passed
        # COMPORTEMENT DOCUMENTÉ (fail-open, historique) : un agent NON
        # listé dans une policy scoped et sans whitelist globale n'est
        # soumis à AUCUNE whitelist -> ALLOW. Voir audit point "whitelist
        # scoped fail-open" pour la décision éventuelle de durcir.
        assert engine.check_tool_policy(
            "mcp:db:query", {"sql": "SELECT 1"}, 10.0, agent_id="other-agent"
        ).passed


# ==============================================================
# 2. CONSTRUCTION DE LA WHITELIST GATEWAY (SANS PACKAGE mcp)
# ==============================================================

def _load_gateway_module(monkeypatch, allowed_tools, label="fs"):
    """Charge mcp_gateway.py avec un environnement contrôlé.

    Reload systématique : les tests précédents peuvent avoir modifié
    les variables d'environnement.
    """
    monkeypatch.setenv("AGENTGUARD_MCP_ALLOWED_TOOLS", allowed_tools)
    monkeypatch.setenv("AGENTGUARD_MCP_SERVER_LABEL", label)
    monkeypatch.setenv("AGENTGUARD_API_KEY", "ag-test")
    monkeypatch.setenv("AGENTGUARD_STATUS_CHECK", "false")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)

    import mcp_gateway
    return importlib.reload(mcp_gateway)


class TestBuildAllowedTools:

    def test_comma_separated_list(self, monkeypatch):
        mod = _load_gateway_module(monkeypatch, "read_file,write_file")
        assert sorted(mod.ALLOWED_TOOLS) == [
            "mcp:fs:read_file",
            "mcp:fs:write_file",
        ]

    def test_star_expands_to_server_wildcard(self, monkeypatch):
        mod = _load_gateway_module(monkeypatch, "*", label="star")
        assert mod.ALLOWED_TOOLS == ["mcp:star:*"]

    def test_empty_refuses_to_start(self, monkeypatch):
        with pytest.raises(SystemExit) as excinfo:
            _load_gateway_module(monkeypatch, "")
        assert excinfo.value.code == 2

    def test_missing_env_refuses_to_start(self, monkeypatch):
        monkeypatch.delenv("AGENTGUARD_MCP_ALLOWED_TOOLS", raising=False)
        with pytest.raises(SystemExit) as excinfo:
            _load_gateway_module(monkeypatch, "")
        assert excinfo.value.code == 2

    def test_guard_uses_effective_whitelist(self, monkeypatch):
        mod = _load_gateway_module(
            monkeypatch, "read_file,write_file,delete_file"
        )
        assert sorted(mod.ALLOWED_TOOLS) == [
            "mcp:fs:delete_file",
            "mcp:fs:read_file",
            "mcp:fs:write_file",
        ]
        # La policy envoyée à AgentGuard est bien la whitelist explicite
        policies = mod.guard.policy_engine.policies
        assert policies[0]["allowed_tools"] == mod.ALLOWED_TOOLS
        # ==============================================================
# 3. FAIL MODE DE LA WHITELIST SCOPED (open par défaut, closed opt-in)
# ==============================================================

class TestWhitelistFailMode:

    def _engine(self, policies):
        return PolicyEngine(policies=policies)

    def test_default_open_keeps_historical_behavior(self, monkeypatch):
        monkeypatch.delenv("AGENTGUARD_WHITELIST_FAIL_MODE", raising=False)
        engine = self._engine([{
            "type": "tool_whitelist",
            "allowed_tools": ["mcp:db:*"],
            "agents": ["agent-42"],
        }])
        # Comportement historique : agent non couvert -> ALLOW
        assert engine.check_tool_policy(
            "anything", {}, 10.0, agent_id="other-agent"
        ).passed

    def test_closed_blocks_uncovered_agent(self, monkeypatch):
        monkeypatch.setenv("AGENTGUARD_WHITELIST_FAIL_MODE", "closed")
        engine = self._engine([{
            "type": "tool_whitelist",
            "allowed_tools": ["mcp:db:*"],
            "agents": ["agent-42"],
        }])
        check = engine.check_tool_policy(
            "mcp:db:query", {"sql": "SELECT 1"}, 10.0, agent_id="other-agent"
        )
        assert not check.passed
        assert check.risk_level.name == "CRITICAL"
        assert check.metadata["fail_mode"] == "closed"

    def test_closed_still_allows_scoped_agent(self, monkeypatch):
        monkeypatch.setenv("AGENTGUARD_WHITELIST_FAIL_MODE", "closed")
        engine = self._engine([{
            "type": "tool_whitelist",
            "allowed_tools": ["mcp:db:*"],
            "agents": ["agent-42"],
        }])
        assert engine.check_tool_policy(
            "mcp:db:query", {"sql": "SELECT 1"}, 10.0, agent_id="agent-42"
        ).passed

    def test_closed_with_global_whitelist_blocks_unknown_agent(self, monkeypatch):
        monkeypatch.setenv("AGENTGUARD_WHITELIST_FAIL_MODE", "closed")
        engine = self._engine([{
            "type": "tool_whitelist",
            "allowed_tools": ["web_search"],
        }])
        # agent couvert par la whitelist globale : OK
        assert engine.check_tool_policy(
            "web_search", {}, 10.0, agent_id="any-agent"
        ).passed
        # outil hors whitelist : BLOCK (comportement normal, inchangé)
        assert not engine.check_tool_policy(
            "rm_rf", {}, 10.0, agent_id="any-agent"
        ).passed

    def test_closed_without_any_whitelist_policy_still_allows(self, monkeypatch):
        monkeypatch.setenv("AGENTGUARD_WHITELIST_FAIL_MODE", "closed")
        # Aucune policy whitelist configurée : le fail mode ne doit pas
        # créer une restriction ex nihilo.
        engine = self._engine([])
        assert engine.check_tool_policy("any_tool", {}, 10.0).passed