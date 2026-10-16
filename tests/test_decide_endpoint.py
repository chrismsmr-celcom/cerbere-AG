"""Régression : /api/decide doit réellement évaluer via le DecisionEngine.

Bug corrigé : `decision_engine` n'était pas importé dans collector/api/decisions.py.
La NameError était avalée par l'except et chaque appel finissait en
DENY 503 « Decision engine failure » (fail-closed permanent).
"""

import pytest

KEYS = {"key-a": "org-a"}


def _fresh_signing_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return (
        Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


def hdr(agent="finance-bot"):
    return {"X-API-Key": "key-a", "X-Agent-Id": agent}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.setenv("AGENTGUARD_SIGNING_KEY", _fresh_signing_pem())
    monkeypatch.delenv("DATABASE_URL", raising=False)

    from collector import api, auth

    monkeypatch.setattr(auth, "resolve_org_id", lambda key: KEYS.get(key))
    api._AGENT_SEEN.clear()
    api._AGENT_STATUS.clear()

    from collector.app import create_app
    from collector.db import init_db

    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_decision_engine_is_importable_in_module():
    from collector.api import decisions

    assert hasattr(decisions, "decision_engine")


def test_decide_unregistered_tool_is_blocked_by_policy_not_by_engine_failure(client):
    """Outil inconnu : refus par la politique (deny-by-default), pas par une panne."""
    r = client.post(
        "/api/decide",
        json={"tool_name": "read_file", "parameters": {"path": "/tmp/readme.txt"}},
        headers=hdr(),
    )
    body = r.get_json() or {}
    assert r.status_code == 200, body
    assert body.get("action") == "BLOCK", body
    assert "not registered" in body.get("reason", ""), body
    assert "Decision engine failure" not in str(body)
    assert "signature" in body, body


def test_decide_registered_tool_is_allowed(client, monkeypatch):
    """Outil enregistré dans la politique : le moteur le laisse passer, décision signée."""
    from collector.api.helpers import decision_engine

    monkeypatch.setattr(
        decision_engine.policies["default"], "allowed_tools", {"read_file"}
    )
    r = client.post(
        "/api/decide",
        json={"tool_name": "read_file", "parameters": {"path": "/tmp/readme.txt"}},
        headers=hdr(),
    )
    body = r.get_json() or {}
    assert r.status_code == 200, body
    assert body.get("action") == "ALLOW", body
    assert "risk_score" in body and "signature" in body, body
