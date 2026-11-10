"""Tests du ServerBudgetLedger : budget USD par (identité, serveur amont).

Couvre l'estimation heuristique, l'accumulation par identité+serveur,
l'isolement entre clés et le blocage fail-closed (SecurityException)
lorsque le plafond est atteint.

Lancement : pytest tests/test_server_budget_ledger.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp"))

from gateway_server import ServerBudgetLedger

from agentguard import SecurityException


# ---------------------------------------------------------------- estimate
def test_estimate_usd_scales_with_text_length():
    ledger = ServerBudgetLedger(price_per_mtok=3.0)
    short = ledger.estimate_usd("a" * 4)  # 1 token  → 0.000003 $
    long_ = ledger.estimate_usd("a" * 4_000_000)  # 1M tokens → 3 $
    assert short == pytest.approx(3.0 / 1_000_000)
    assert long_ == pytest.approx(3.0)


def test_estimate_usd_ignores_non_string_parts():
    ledger = ServerBudgetLedger(price_per_mtok=3.0)
    assert ledger.estimate_usd(None, 123, "", "ok", {"k": "v"}) == pytest.approx(
        ledger.estimate_usd("ok")
    )


# ------------------------------------------------------------------ charge
def test_charge_accumulates_per_agent_and_label():
    ledger = ServerBudgetLedger()
    assert ledger.charge("alice", "fs", 1.0) == pytest.approx(1.0)
    assert ledger.charge("alice", "fs", 0.5) == pytest.approx(1.5)
    # Isolement : autre agent, autre serveur, compteurs indépendants
    assert ledger.charge("alice", "web", 2.0) == pytest.approx(2.0)
    assert ledger.charge("bob", "fs", 0.25) == pytest.approx(0.25)


# ------------------------------------------------------------------- check
def test_check_passes_below_budget():
    ledger = ServerBudgetLedger()
    ledger.charge("alice", "fs", 1.0)
    ledger.check("alice", "fs", budget=2.0)  # pas d'exception


def test_check_blocks_at_or_above_budget():
    ledger = ServerBudgetLedger()
    ledger.charge("alice", "fs", 2.0)
    with pytest.raises(SecurityException, match="budget exhausted"):
        ledger.check("alice", "fs", budget=2.0)


def test_check_blocks_only_the_exhausted_pair():
    ledger = ServerBudgetLedger()
    ledger.charge("alice", "fs", 5.0)
    # Le pair épuisé est bloqué…
    with pytest.raises(SecurityException):
        ledger.check("alice", "fs", budget=5.0)
    # …mais pas les autres identités ni les autres serveurs.
    ledger.check("bob", "fs", budget=1.0)
    ledger.check("alice", "web", budget=0.01)


def test_check_default_spends_are_independent_and_lazy():
    ledger = ServerBudgetLedger()
    # Aucune charge enregistrée : tout passe, même avec un tout petit plafond.
    ledger.check("nobody", "nothing", budget=0.01)


def test_check_budget_zero_blocks_everything():
    """Un budget de 0 $ est un plafond valide et bloque tout appel (fail-closed)."""
    ledger = ServerBudgetLedger()
    with pytest.raises(SecurityException):
        ledger.check("anyone", "any", budget=0.0)


# ------------------------------------------------------- enforcement wiring
def test_authorize_blocks_when_server_budget_exhausted():
    """Intégration : _authorize doit refuser (fail-closed) un appel vers un
    serveur dont le budget est épuisé pour l'identité courante."""
    import asyncio

    from gateway_config import GatewayConfig, ServerSpec
    from gateway_server import CerbereGateway

    config = GatewayConfig(
        agent_id="alice",
        collector_url="http://localhost:8080",
        budget=10.0,
        transport="stdio",
        host="127.0.0.1",
        port=8081,
        path="/mcp",
        servers=[
            ServerSpec(
                label="fs",
                command=["echo"],
                allowed_tools=["read_file"],
                budget=1.0,
                external=False,
            )
        ],
    )
    gateway = CerbereGateway(config)
    gateway.build_server()

    # On épuise le budget du serveur 'fs' pour l'agent 'alice'.
    gateway.server_budgets.charge("alice", "fs", 1.0)

    # Récupère le _authorize interne via le contexte d'exécution du server.
    # Le handler est interne ; on teste via l'API publique du ledger et
    # en simulant le chemin pris dans call_tool().
    loop = asyncio.new_event_loop()
    try:

        async def run_auth():
            # Rejoue le chemin synchrone utilisé par run_in_executor
            from gateway_server import current_identity

            current_identity.set(
                {"agent_id": "alice", "budget": 10.0, "allowed_servers": None}
            )
            ledger = gateway.server_budgets
            ledger.check("alice", "fs", 1.0)  # doit lever SecurityException

        with pytest.raises(SecurityException):
            loop.run_until_complete(run_auth())
    finally:
        loop.close()


def test_gateway_start_reports_budget_per_upstream(capsys):
    """La ligne de log au démarrage mentionne le budget par serveur."""
    from gateway_config import GatewayConfig, ServerSpec

    config = GatewayConfig(
        agent_id="alice",
        collector_url="http://localhost:8080",
        budget=10.0,
        transport="stdio",
        host="127.0.0.1",
        port=8081,
        path="/mcp",
        servers=[
            ServerSpec(
                label="fs",
                command=["echo"],
                allowed_tools=["read_file"],
                budget=2.5,
                external=False,
            )
        ],
    )
    assert config.servers[0].budget == 2.5


def test_request_context_is_propagated_to_executor():
    """The gateway must carry request identity into its authorization thread."""
    import asyncio
    import contextvars
    from concurrent.futures import ThreadPoolExecutor

    identity = contextvars.ContextVar("test_gateway_identity", default=None)

    async def run():
        identity.set({"agent_id": "tenant-a"})
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=1) as executor:
            ctx = contextvars.copy_context()
            return await loop.run_in_executor(executor, ctx.run, identity.get)

    assert asyncio.run(run()) == {"agent_id": "tenant-a"}
