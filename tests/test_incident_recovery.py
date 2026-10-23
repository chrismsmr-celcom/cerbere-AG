"""Secure Evidence Recovery : masquage, coffre scellé, routes du collector.

Couvre : couverture réelle du masquage (régression : il ne masquait aucun
champ d'un vrai span), tokens HMAC, SDK incapable de déchiffrer, TTL côté
serveur, isolation entre organisations et entre agents, refus des clés API
sur les routes humaines, motif obligatoire, aucune valeur brute dans le chiffré.
"""

import hashlib
import os
import time

import pytest

from agentguard.masking import SpanMasker
from agentguard.models import SpanPayload
from agentguard.vault import IncidentVault, seal_to_public_key

EMAIL = "alice.martin@example.com"
SECRET = "sk-abcdefghijklmnopqrstuvwx1234567890"
MASTER_KEY = "ab" * 32


def _span(**over):
    base = {
        "trace_id": "t1",
        "span_id": "s1",
        "span_type": "tool_call",
        "timestamp": 1.0,
        "latency_ms": 1.0,
        "cost_usd": 0.0,
        "input_data": {"text": f"mail {EMAIL} with {SECRET}", "nested": [{"k": EMAIL}]},
        "output_data": {"result": f"ok {SECRET}"},
        "block_reason": f"leak {EMAIL}",
        "security_checks": [
            {
                "check_name": "pii",
                "passed": False,
                "risk_level": "high",
                "details": f"found {EMAIL}",
                "metadata": {"m": SECRET},
            }
        ],
    }
    base.update(over)
    return SpanPayload(**base).model_dump()


# ── masquage ────────────────────────────────────────────────────────────────


def test_masking_covers_every_field_of_a_real_span():
    masked = SpanMasker(mode="redact", key="k" * 20).mask_span(_span())
    blob = repr(masked)
    assert EMAIL not in blob
    assert SECRET not in blob
    assert "CERB:" in blob
    assert masked["trace_id"] == "t1" and masked["span_type"] == "tool_call"


def test_tokens_are_keyed_not_a_bare_hash():
    old_style = hashlib.sha256(EMAIL.encode()).hexdigest()[:16]
    a = SpanMasker(mode="redact", key="a" * 20).mask_text(EMAIL)
    b = SpanMasker(mode="redact", key="b" * 20).mask_text(EMAIL)
    assert a != b
    assert old_style not in a and old_style not in b
    assert a == SpanMasker(mode="redact", key="a" * 20).mask_text(EMAIL)


def test_random_key_per_process_when_none_given(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_MASKING_KEY", raising=False)
    assert SpanMasker(mode="redact").mask_text(EMAIL) != SpanMasker(
        mode="redact"
    ).mask_text(EMAIL)


def test_off_mode_needs_explicit_opt_in(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_ALLOW_UNMASKED", raising=False)
    with pytest.warns(UserWarning):
        m = SpanMasker(mode="off")
    assert m.mode == "redact"
    assert EMAIL not in m.mask_text(EMAIL)


def test_existing_token_is_not_masked_twice():
    m = SpanMasker(mode="redact", key="k" * 20)
    once = m.mask_text(f"x {EMAIL} y")
    assert m.mask_text(once) == once


# ── coffre : le SDK ne peut que chiffrer ───────────────────────────────────


def _keypair(incident_id="inc_test"):
    from collector.incident_crypto import generate_incident_keypair

    os.environ["AGENTGUARD_INCIDENT_MASTER_KEY"] = MASTER_KEY
    return generate_incident_keypair(incident_id)


def test_roundtrip_and_sdk_holds_no_decryption_material():
    from collector.incident_crypto import open_sealed

    pub, wrapped = _keypair()
    token = SpanMasker(mode="redact", key="k" * 20).mask_text(EMAIL)
    vault = IncidentVault("http://x", "inc_test", bytes.fromhex(pub), time.time() + 60)
    vault.seal(token, EMAIL)
    blob = vault._sealed[token]
    assert EMAIL.encode() not in blob
    assert not hasattr(vault, "decrypt") and not hasattr(vault, "open")
    assert open_sealed(wrapped, "inc_test", token, blob) == EMAIL


def test_blob_is_bound_to_token_and_incident():
    from collector.incident_crypto import IncidentCryptoError, open_sealed

    pub, wrapped = _keypair()
    blob = seal_to_public_key(
        bytes.fromhex(pub), "inc_test", "⟦CERB:0000000000000001⟧", EMAIL
    )
    with pytest.raises(IncidentCryptoError):
        open_sealed(wrapped, "inc_test", "⟦CERB:0000000000000002⟧", blob)
    with pytest.raises(IncidentCryptoError):
        open_sealed(wrapped, "inc_other", "⟦CERB:0000000000000001⟧", blob)


def test_vault_never_keeps_data_after_ttl_and_buffer_is_bounded():
    pub, _ = _keypair()
    expired = IncidentVault("http://x", "inc_test", bytes.fromhex(pub), time.time() - 1)
    expired.seal("⟦CERB:00000000000000aa⟧", EMAIL)
    assert expired.pending() == 0

    v = IncidentVault("http://x", "inc_test", bytes.fromhex(pub), time.time() + 60)
    v.MAX_PENDING = 3
    for i in range(10):
        v.seal(f"⟦CERB:{i:016x}⟧", EMAIL)
    assert v.pending() == 3 and v.dropped == 7


def test_flush_failures_are_bounded_logged_and_never_raise():
    pub, _ = _keypair()
    v = IncidentVault(
        "http://127.0.0.1:1",
        "inc_test",
        bytes.fromhex(pub),
        time.time() + 60,
        timeout=0.2,
    )
    v.seal("⟦CERB:00000000000000bb⟧", EMAIL)
    for _ in range(v.MAX_CONSECUTIVE_FAILURES):
        assert v.flush(force=True) == 0
    assert v.pending() == 0 and v.dropped >= 1


# ── collector ──────────────────────────────────────────────────────────────


@pytest.fixture
def incident_env(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_INCIDENT_ENABLED", "true")
    monkeypatch.setenv("AGENTGUARD_INCIDENT_MASTER_KEY", MASTER_KEY)


@pytest.fixture
def human(monkeypatch, incident_env, client, auth_headers):
    """Session humaine admin simulée (org configurable via state['org']).

    Le middleware fail-closed doit laisser passer la requête avant la route :
    la clé de test sert uniquement à franchir ce premier contrôle ; la décision
    humaine/admin, elle, est celle de require_human_auth (simulée ici) et de
    _is_admin. Le refus réel des clés API est testé sans cette fixture.
    """
    client.environ_base["HTTP_X_API_KEY"] = auth_headers["X-API-Key"]
    from flask import g

    import collector.api as api_pkg
    import collector.api.incidents as inc

    state = {"org": None, "admin": True, "email": "admin@corp.test"}

    def fake_human():
        if state["org"] is None:
            return False
        g.org_id = state["org"]
        g.human_email = state["email"]
        return True

    monkeypatch.setattr(api_pkg, "require_human_auth", fake_human)
    monkeypatch.setattr(inc, "_is_admin", lambda: state["admin"])
    inc._reveal_log.clear()
    return state


def test_disabled_by_default(client, auth_headers, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_INCIDENT_ENABLED", raising=False)
    assert client.get("/v1/incident/active", headers=auth_headers).status_code == 404
    # sans session ni clé : le middleware fail-closed répond avant la route
    assert client.post("/api/incidents", json={}).status_code == 401


def test_fails_closed_without_master_key(client, auth_headers, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_INCIDENT_ENABLED", "true")
    monkeypatch.delenv("AGENTGUARD_INCIDENT_MASTER_KEY", raising=False)
    assert client.get("/v1/incident/active", headers=auth_headers).status_code == 503


def test_api_key_can_never_open_close_or_reveal(client, auth_headers, incident_env):
    body = {"agent_id": "a1", "reason": "investigation of leak", "ttl_seconds": 600}
    assert (
        client.post("/api/incidents", json=body, headers=auth_headers).status_code
        == 401
    )
    assert (
        client.post(
            "/api/incidents/inc_x/close", json={}, headers=auth_headers
        ).status_code
        == 401
    )
    r = client.post(
        "/api/incidents/inc_x/reveal",
        json={"token": "⟦CERB:0000000000000000⟧", "reason": "investigation of leak"},
        headers=auth_headers,
    )
    assert r.status_code == 401


def test_non_admin_human_is_refused(client, human):
    human["org"] = "default"
    human["admin"] = False
    r = client.post(
        "/api/incidents", json={"agent_id": "a1", "reason": "investigation of leak"}
    )
    assert r.status_code == 403


def test_open_requires_reason_and_bounded_ttl(client, human):
    human["org"] = "default"
    assert (
        client.post(
            "/api/incidents", json={"agent_id": "a1", "reason": "short"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/incidents",
            json={
                "agent_id": "a1",
                "reason": "investigation of leak",
                "ttl_seconds": 10**9,
            },
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/incidents",
            json={"reason": "investigation of leak", "ttl_seconds": 600},
        ).status_code
        == 400
    )


def _open(client, agent="agent-1", ttl=600):
    r = client.post(
        "/api/incidents",
        json={
            "agent_id": agent,
            "reason": "investigation of data leak",
            "ttl_seconds": ttl,
        },
    )
    assert r.status_code == 201, r.get_json()
    return r.get_json()["incident_id"]


def _agent_vault(client, auth_headers, agent="agent-1"):
    h = {**auth_headers, "X-Agent-Id": agent}
    r = client.get("/v1/incident/active", headers=h)
    assert r.status_code == 200, r.get_json()
    d = r.get_json()
    return d, IncidentVault(
        "http://collector.test",
        d["incident_id"],
        bytes.fromhex(d["public_key"]),
        d["expires_at"],
        headers=h,
    )


def _flush(client, vault):
    r = client.post(
        "/v1/incident/sealed",
        json={
            "incident_id": vault.incident_id,
            "sealed": {t: c.hex() for t, c in vault._sealed.items()},
        },
        headers=vault._headers,
    )
    return r


def _org_of_api_key(client, auth_headers, human):
    from flask import g

    seen = {}
    import collector.api.incidents as inc

    orig = inc._setup

    def spy():
        out = orig()
        seen["org"] = getattr(g, "org_id", None)
        return out

    inc._setup = spy
    try:
        client.get(
            "/v1/incident/active", headers={**auth_headers, "X-Agent-Id": "probe"}
        )
    finally:
        inc._setup = orig
    return seen.get("org")


def test_full_flow_reveal_returns_original_and_leaves_no_clear_text(
    client, auth_headers, human
):
    org = _org_of_api_key(client, auth_headers, human) or "default"
    human["org"] = org
    incident_id = _open(client)

    d, vault = _agent_vault(client, auth_headers)
    assert d["incident_id"] == incident_id
    assert "private" not in repr(d).lower()

    masker = SpanMasker(mode="incident", vault=vault, key="k" * 20)
    masked = masker.mask_span(_span())
    assert EMAIL not in repr(masked)
    assert vault.pending() >= 2
    assert _flush(client, vault).status_code == 200

    # rien en clair dans la base
    from collector.api.helpers import _db_run

    rows, _ = _db_run("SELECT ciphertext FROM incident_sealed", fetch="all")
    assert rows and all(EMAIL not in r[0] and SECRET not in r[0] for r in rows)

    token = masker.mask_text(EMAIL)
    r = client.post(
        f"/api/incidents/{incident_id}/reveal",
        json={"token": token, "reason": "legal request ref 4521"},
    )
    assert r.status_code == 200
    assert r.get_json()["value"] == EMAIL
    assert r.headers["Cache-Control"] == "no-store"

    # motif obligatoire
    assert (
        client.post(
            f"/api/incidents/{incident_id}/reveal", json={"token": token, "reason": "x"}
        ).status_code
        == 400
    )
    # token inconnu
    assert (
        client.post(
            f"/api/incidents/{incident_id}/reveal",
            json={
                "token": "⟦CERB:ffffffffffffffff⟧",
                "reason": "legal request ref 4521",
            },
        ).status_code
        == 404
    )


def test_other_org_and_other_agent_are_isolated(client, auth_headers, human):
    org = _org_of_api_key(client, auth_headers, human) or "default"
    human["org"] = org
    incident_id = _open(client, agent="agent-1")
    _d, vault = _agent_vault(client, auth_headers, "agent-1")
    SpanMasker(mode="incident", vault=vault, key="k" * 20).mask_text(EMAIL)

    # un autre agent ne voit pas l'incident et ne peut pas y déposer
    assert (
        client.get(
            "/v1/incident/active", headers={**auth_headers, "X-Agent-Id": "agent-2"}
        ).status_code
        == 404
    )
    forged = client.post(
        "/v1/incident/sealed",
        json={
            "incident_id": incident_id,
            "sealed": {t: c.hex() for t, c in vault._sealed.items()},
        },
        headers={**auth_headers, "X-Agent-Id": "agent-2"},
    )
    assert forged.status_code == 404

    assert _flush(client, vault).status_code == 200
    token = next(iter(vault._sealed))

    # un admin d'une autre organisation ne voit rien
    human["org"] = "another-org"
    r = client.post(
        f"/api/incidents/{incident_id}/reveal",
        json={"token": token, "reason": "legal request ref 4521"},
    )
    assert r.status_code == 404
    assert client.get("/api/incidents").get_json()["incidents"] == []


def test_ttl_is_enforced_server_side_and_evidence_is_destroyed(
    client, auth_headers, human
):
    from collector.api.helpers import _db_run

    org = _org_of_api_key(client, auth_headers, human) or "default"
    human["org"] = org
    incident_id = _open(client)
    _d, vault = _agent_vault(client, auth_headers)
    masker = SpanMasker(mode="incident", vault=vault, key="k" * 20)
    masker.mask_text(EMAIL)
    assert _flush(client, vault).status_code == 200
    token = masker.mask_text(EMAIL)

    _db_run(
        "UPDATE incidents SET expires_at = ? WHERE id = ?",
        (time.time() - 1, incident_id),
        commit=True,
    )

    # dépôt refusé après expiration, même avec une clé API valide
    assert _flush(client, vault).status_code == 404
    r = client.post(
        f"/api/incidents/{incident_id}/reveal",
        json={"token": token, "reason": "legal request ref 4521"},
    )
    assert r.status_code == 410
    left, _ = _db_run("SELECT COUNT(*) FROM incident_sealed", fetch="one")
    keys, _ = _db_run(
        "SELECT wrapped_private_key FROM incidents WHERE id = ?",
        (incident_id,),
        fetch="one",
    )
    assert left[0] == 0 and keys[0] == ""


def test_malformed_and_oversized_uploads_are_rejected(client, auth_headers, human):
    org = _org_of_api_key(client, auth_headers, human) or "default"
    human["org"] = org
    incident_id = _open(client)
    h = {**auth_headers, "X-Agent-Id": "agent-1"}
    bad_token = client.post(
        "/v1/incident/sealed",
        json={"incident_id": incident_id, "sealed": {"nope": "00" * 80}},
        headers=h,
    )
    assert bad_token.status_code == 400
    bad_blob = client.post(
        "/v1/incident/sealed",
        json={"incident_id": incident_id, "sealed": {"⟦CERB:0000000000000001⟧": "zz"}},
        headers=h,
    )
    assert bad_blob.status_code == 400
    too_many = {f"⟦CERB:{i:016x}⟧": "00" * 80 for i in range(501)}
    assert (
        client.post(
            "/v1/incident/sealed",
            json={"incident_id": incident_id, "sealed": too_many},
            headers=h,
        ).status_code
        == 413
    )


def test_reveal_rate_limit(client, auth_headers, human, monkeypatch):
    import collector.api.incidents as inc

    monkeypatch.setattr(inc, "REVEALS_PER_HOUR", 2)
    org = _org_of_api_key(client, auth_headers, human) or "default"
    human["org"] = org
    incident_id = _open(client)
    codes = [
        client.post(
            f"/api/incidents/{incident_id}/reveal",
            json={
                "token": "⟦CERB:0000000000000009⟧",
                "reason": "legal request ref 4521",
            },
        ).status_code
        for _ in range(3)
    ]
    assert codes == [404, 404, 429]
