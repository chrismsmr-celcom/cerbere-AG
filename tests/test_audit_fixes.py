"""
Non-régression des correctifs issus de l'audit (04/11/2026).

1. X-Agent-Id ne peut pas l'emporter sur l'agent lié à la clé API (usurpation,
   contournement du kill switch).
2. Approuver / rejeter / déconnecter exige un rôle admin ou developer.
3. Taint tracker saturé : fail-closed (jamais "PUBLIC" pour une valeur non suivie).
4. SDK : le vérificateur Ed25519 est réellement initialisé et appliqué, et la
   décision signée est liée à l'outil, aux arguments et à la requête.
"""

import time

import pytest

KEYS = {"key-a": "org-a"}
SPAN = {
    "trace_id": "t1",
    "span_id": "s1",
    "span_type": "tool_call",
    "timestamp": time.time(),
    "latency_ms": 12,
    "cost_usd": 0.01,
    "input_data": {"tool": "send_email"},
    "output_data": {},
    "security_checks": [],
}


def hdr(agent="bot"):
    return {"X-API-Key": "key-a", "X-Agent-Id": agent}


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.setenv("AGENTGUARD_CORS_ALLOW_ALL", "true")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    from collector import api, auth

    monkeypatch.setattr(auth, "resolve_org_id", lambda key: KEYS.get(key))
    api._AGENT_SEEN.clear()
    api._AGENT_STATUS.clear()
    api.helpers._MISMATCH_LOGGED.clear()

    from collector.app import create_app
    from collector.db import init_db

    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield app, c, api, monkeypatch


def _as_human(api, monkeypatch, role, org="org-a"):
    def fake():
        from flask import g

        from agentguard.identity import IdentityType, ResolvedIdentity, Role

        g.org_id, g.human_email = org, f"{role}@acme.io"
        g.identity = ResolvedIdentity(
            identity_type=IdentityType.USER,
            tenant_id="t",
            org_id=org,
            subject_id=f"u-{role}",
            role=Role(role),
        )
        return True

    monkeypatch.setattr(api, "require_human_auth", fake)


# ── 1. Usurpation d'agent via X-Agent-Id ────────────────────────────────────


def test_header_cannot_override_agent_bound_to_key(app_client):
    app, _c, api, _ = app_client
    from flask import g

    with app.test_request_context("/", headers={"X-Agent-Id": "victim-agent"}):
        g.agent_identity = {"agent_id": "my-real-agent", "org_id": "org-a"}
        assert api._request_agent_id() == "my-real-agent"


def test_org_level_key_still_uses_declared_agent(app_client):
    """Clé d'organisation (aucun agent lié) : l'identité déclarée reste utilisée."""
    app, _c, api, _ = app_client
    with app.test_request_context("/", headers={"X-Agent-Id": "finance-bot"}):
        assert api._request_agent_id() == "finance-bot"


def test_spoofed_header_does_not_bypass_kill_switch(app_client):
    """Un agent déconnecté ne peut pas se faire passer pour un autre via l'en-tête."""
    app, c, api, mp = app_client
    from flask import g

    assert c.post("/span", json=SPAN, headers=hdr("bot")).status_code in (200, 201)
    _as_human(api, mp, "admin")
    r = c.post("/api/agents/bot/disconnect", headers={"X-API-Key": "key-a"})
    assert r.status_code == 200

    api._AGENT_STATUS.clear()
    with app.test_request_context("/", headers={"X-Agent-Id": "some-other-agent"}):
        g.org_id = "org-a"
        g.agent_identity = {"agent_id": "bot", "org_id": "org-a"}
        refused = api._reject_if_agent_disconnected()
        assert refused is not None and refused[1] == 403


# ── 2. Rôle requis pour décider ─────────────────────────────────────────────


@pytest.mark.parametrize("role,expected", [("viewer", 403), ("auditor", 403)])
def test_read_only_roles_cannot_approve_reject_or_disconnect(
    app_client, role, expected
):
    _app, c, api, mp = app_client
    assert (
        c.post(
            "/api/approvals",
            headers=hdr(),
            json={"approval_id": "r1", "tool_name": "send_email"},
        ).status_code
        == 201
    )
    _as_human(api, mp, role)
    k = {"X-API-Key": "key-a"}
    assert c.post("/api/approvals/r1/approve", headers=k).status_code == expected
    assert c.post("/api/approvals/r1/reject", headers=k).status_code == expected
    assert c.post("/api/agents/bot/disconnect", headers=k).status_code == expected

    # La demande reste en attente : aucune décision n'a été prise.
    pending = c.get("/api/approvals?status=pending", headers=k).get_json()
    assert [a["id"] for a in pending["approvals"]] == ["r1"]


@pytest.mark.parametrize("role", ["admin", "developer"])
def test_admin_and_developer_can_approve(app_client, role):
    _app, c, api, mp = app_client
    c.post(
        "/api/approvals",
        headers=hdr(),
        json={"approval_id": "r2", "tool_name": "send_email"},
    )
    _as_human(api, mp, role)
    r = c.post("/api/approvals/r2/approve", headers={"X-API-Key": "key-a"})
    assert r.status_code == 200 and r.get_json()["status"] == "approved"


def test_approval_agent_comes_from_key_not_body(app_client):
    app, c, api, _ = app_client
    # Org key + corps qui tente d'imposer un autre agent : l'en-tête déclaré gagne
    # sur le corps (le corps n'est qu'un dernier recours).
    c.post(
        "/api/approvals",
        headers=hdr("real-bot"),
        json={"approval_id": "r3", "tool_name": "x", "agent_id": "victim"},
    )
    pending = c.get(
        "/api/approvals?status=pending", headers={"X-API-Key": "key-a"}
    ).get_json()
    row = next(a for a in pending["approvals"] if a["id"] == "r3")
    assert row["agent_id"] == "real-bot"


# ── 3. Taint tracker : saturation fail-closed ───────────────────────────────


def _secrets(n):
    import secrets

    return [secrets.token_hex(12) for _ in range(n)]


def test_taint_saturation_is_explicit_and_fail_closed():
    from agentguard.taint import FlowTracker, TaintLevel

    vals = _secrets(520)
    ft = FlowTracker()
    for v in vals:
        ft.track(v, level=TaintLevel.SECRET)

    assert ft.saturated is True and ft.dropped_needles > 0
    assert ft.report()["saturated"] is True

    # La valeur lue APRÈS saturation n'est plus suivie, mais n'est pas "PUBLIC".
    label = ft.level_in({"body": vals[-1]})
    assert label.level >= TaintLevel.SECRET
    assert label.source == "tracker_saturated"

    # Même en base64 : jamais assimilée à une donnée sûre.
    import base64

    enc = base64.b64encode(vals[-1].encode()).decode()
    assert ft.level_in({"body": enc}).level >= TaintLevel.SECRET


def test_taint_clear_recovers_from_saturation():
    from agentguard.taint import FlowTracker, TaintLevel

    ft = FlowTracker()
    for v in _secrets(520):
        ft.track(v, level=TaintLevel.SECRET)
    assert ft.saturated
    ft.clear()
    assert ft.saturated is False
    assert ft.level_in({"body": "hello world"}).level == TaintLevel.PUBLIC


def test_taint_full_tracker_evicts_low_level_for_high_level():
    from agentguard.taint import FlowTracker, TaintLevel

    ft = FlowTracker()
    for v in _secrets(520):
        ft.track(v, level=TaintLevel.CONFIDENTIAL)
    assert ft.saturated
    ft.clear()

    for v in _secrets(60):
        ft.track(v, level=TaintLevel.CONFIDENTIAL)  # remplit le stock
    big = _secrets(40)
    for v in big:
        ft.track(v, level=TaintLevel.SECRET)  # doit évincer du CONFIDENTIAL
    # Le dernier secret (le plus grave) est réellement suivi, pas seulement "plancher".
    assert ft.level_in({"x": big[-1]}).source == "tracked_value"


def test_taint_warn_mode_keeps_legacy_behaviour_but_flags_it():
    from agentguard.taint import FlowTracker, TaintLevel

    vals = _secrets(520)
    ft = FlowTracker(on_saturation="warn")
    for v in vals:
        ft.track(v, level=TaintLevel.SECRET)
    assert ft.saturated is True
    assert ft.level_in({"body": vals[-1]}).level == TaintLevel.PUBLIC


def test_unknown_saturation_mode_defaults_to_block():
    from agentguard.taint import FlowTracker

    assert FlowTracker(on_saturation="nonsense").on_saturation == "block"


# ── 4. Décisions signées : vérificateur actif + liaison à l'action ──────────


@pytest.fixture
def signer(monkeypatch):
    from agentguard.signing import DecisionSigner

    monkeypatch.setenv("AGENTGUARD_ALLOW_EPHEMERAL_SIGNING_KEY", "true")
    return DecisionSigner()


def _guard(public_pem=None, monkeypatch=None):
    from agentguard.sdk import AgentGuard

    return AgentGuard(
        collector_url="http://collector.invalid",
        api_key="k",
        agent_id="a",
        public_key_pem=public_pem,
    )


def test_verifier_is_initialised_when_public_key_given(signer, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_PUBLIC_KEY", raising=False)
    assert _guard()._verifier is None
    assert _guard(signer.public_key_pem())._verifier is not None


def test_verifier_from_environment_with_escaped_newlines(signer, monkeypatch):
    monkeypatch.setenv(
        "AGENTGUARD_PUBLIC_KEY", signer.public_key_pem().replace("\n", "\\n")
    )
    assert _guard()._verifier is not None


def test_invalid_public_key_fails_closed_at_construction(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_PUBLIC_KEY", raising=False)
    with pytest.raises(ValueError):
        _guard("not a pem")


class _Resp:
    def __init__(self, body, status=200):
        self._b, self.status_code = body, status

    def json(self):
        return self._b


def _serve(monkeypatch, make_body):
    """Fait répondre au SDK un collector simulé qui signe make_body(request_json)."""
    import agentguard.sdk as sdk_mod

    def fake_post(url, json=None, **kw):  # noqa: A002
        return _Resp(make_body(json))

    monkeypatch.setattr(sdk_mod.requests, "post", fake_post)


def _honest(signer, action="ALLOW", **override):
    from agentguard.signing import params_digest

    def make(req):
        d = {
            "request_id": "r",
            "action": action,
            "policy_name": "p",
            "policy_version": 1,
            "reason": "ok",
            "tool_name": req["tool_name"],
            "agent_id": "a",
            "org_id": "org",
            "args_sha256": params_digest(req["params"]),
            "nonce": req["nonce"],
        }
        d.update(override)
        return signer.sign_decision(d)

    return make


def test_valid_bound_decision_is_accepted(signer, monkeypatch):
    g = _guard(signer.public_key_pem())
    _serve(monkeypatch, _honest(signer))
    out = g._request_signed_decision("send_email", {"to": "a@b.c", "n": 2})
    assert out and out["action"] == "ALLOW"


def test_forged_decision_from_attacker_key_is_rejected(signer, monkeypatch):
    from agentguard.signing import DecisionSigner

    monkeypatch.setenv("AGENTGUARD_ALLOW_EPHEMERAL_SIGNING_KEY", "true")
    attacker = DecisionSigner()
    g = _guard(signer.public_key_pem())
    _serve(monkeypatch, _honest(attacker))
    assert g._request_signed_decision("send_email", {"to": "x"}) is None


def test_decision_for_another_tool_is_rejected(signer, monkeypatch):
    g = _guard(signer.public_key_pem())
    _serve(monkeypatch, _honest(signer, tool_name="read_file"))
    assert g._request_signed_decision("send_email", {"to": "x"}) is None


def test_decision_for_other_arguments_is_rejected(signer, monkeypatch):
    g = _guard(signer.public_key_pem())
    _serve(monkeypatch, _honest(signer, args_sha256="0" * 64))
    assert g._request_signed_decision("send_email", {"to": "x"}) is None


def test_replayed_decision_with_old_nonce_is_rejected(signer, monkeypatch):
    g = _guard(signer.public_key_pem())
    _serve(monkeypatch, _honest(signer, nonce="a-previous-request"))
    assert g._request_signed_decision("send_email", {"to": "x"}) is None


def test_unbound_legacy_decision_is_rejected(signer, monkeypatch):
    g = _guard(signer.public_key_pem())
    _serve(
        monkeypatch,
        lambda req: signer.sign_decision(
            {"request_id": "r", "action": "ALLOW", "policy_name": "p"}
        ),
    )
    assert g._request_signed_decision("send_email", {"to": "x"}) is None


def test_guarded_tool_is_denied_when_signed_decision_is_forged(signer, monkeypatch):
    """Bout en bout côté SDK : une fausse décision ALLOW ne permet jamais l'exécution."""
    from agentguard.exceptions import SecurityException
    from agentguard.signing import DecisionSigner

    monkeypatch.setenv("AGENTGUARD_ALLOW_EPHEMERAL_SIGNING_KEY", "true")
    g = _guard(signer.public_key_pem())
    _serve(monkeypatch, _honest(DecisionSigner()))
    ran = []

    @g.guard_tool_call("lookup")
    def lookup(q):
        ran.append(q)
        return "ok"

    with pytest.raises(SecurityException):
        lookup("hello")
    assert ran == []


# ── 5. Audit : checkpoints durables, persistance visible, ancrage ───────────


def _audit_log(tmp_path, signer, monkeypatch, **kw):
    from agentguard.audit import ImmutableAuditLog

    monkeypatch.delenv("AGENTGUARD_SIGNING_PUBLIC_KEY", raising=False)
    return ImmutableAuditLog(
        backup_file=str(tmp_path / "audit.jsonl"),
        signing_key_pem=signer.export_private_pem(),
        sign_every=1,
        **kw,
    )


def _log(log, n):
    from agentguard.audit import AuditEventType

    for i in range(n):
        log.log_event(
            list(AuditEventType)[0], "org", "actor", f"res{i}", "act", {"i": i}
        )


def test_audit_checkpoint_signature_does_not_expire(tmp_path, signer, monkeypatch):
    """Une signature de checkpoint reste valide bien après 5 minutes."""
    import agentguard.signing as signing_mod

    log = _audit_log(tmp_path, signer, monkeypatch)
    _log(log, 3)
    ok, report = log.verify_chain()
    assert ok and report["signatures_verified"] >= 1

    real_time = time.time
    monkeypatch.setattr(signing_mod.time, "time", lambda: real_time() + 3600 * 24 * 365)
    ok, report = log.verify_chain()
    assert ok, report
    assert report["signatures_failed"] == 0


def test_audit_checkpoint_signature_is_not_a_valid_runtime_decision(
    tmp_path, signer, monkeypatch
):
    """Une signature d'audit sans expiration ne peut pas servir de décision runtime."""
    import json

    from agentguard.signing import DecisionVerifier

    log = _audit_log(tmp_path, signer, monkeypatch)
    _log(log, 1)
    line = json.loads(open(tmp_path / "audit.jsonl").readline())
    payload = json.loads(line["signature"])
    assert "expires_at" not in payload
    v = DecisionVerifier(signer.public_key_pem())
    assert v.verify(payload) is False
    assert v.verify(payload, check_expiry=False) is True


def test_runtime_decision_signature_still_expires(signer):
    from agentguard.signing import DecisionVerifier

    v = DecisionVerifier(signer.public_key_pem())
    d = signer.sign_decision({"request_id": "r", "action": "ALLOW"}, ttl=-1)
    assert v.verify(d) is False
    assert v.verify(d, check_expiry=False) is True


def test_audit_persistence_failure_is_visible(tmp_path, signer, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_AUDIT_ON_FAILURE", raising=False)
    log = _audit_log(tmp_path, signer, monkeypatch)
    assert log.status()["state"] == "OK"

    # Plus aucun stockage accessible.
    log.backup_file = str(tmp_path / "missing-dir" / "audit.jsonl")
    _log(log, 1)  # mode par défaut "degrade" : pas d'exception
    assert log.degraded is True
    assert log.status()["state"] == "AUDIT_DEGRADED"
    assert log.persist_failures == 1

    # Récupération.
    log.backup_file = str(tmp_path / "audit2.jsonl")
    _log(log, 1)
    assert log.degraded is False


def test_audit_persistence_failure_can_block(tmp_path, signer, monkeypatch):
    from agentguard.audit import AuditPersistenceError

    monkeypatch.setenv("AGENTGUARD_AUDIT_ON_FAILURE", "block")
    log = _audit_log(tmp_path, signer, monkeypatch)
    log.backup_file = str(tmp_path / "missing-dir" / "audit.jsonl")
    with pytest.raises(AuditPersistenceError):
        _log(log, 1)


def test_audit_anchor_reports_whether_it_is_independent(
    tmp_path, signer, monkeypatch
):
    log = _audit_log(tmp_path, signer, monkeypatch)
    _log(log, 2)

    monkeypatch.delenv("AGENTGUARD_AUDIT_ANCHOR_FILE", raising=False)
    monkeypatch.delenv("AGENTGUARD_AUDIT_ANCHOR_URL", raising=False)
    a = log.publish_anchor()
    assert a["independent"] is False and a["published_to"] == ["log"]

    anchor_file = tmp_path / "anchors.jsonl"
    monkeypatch.setenv("AGENTGUARD_AUDIT_ANCHOR_FILE", str(anchor_file))
    b = log.publish_anchor()
    assert b["independent"] is True and "file" in b["published_to"]
    assert str(b["head_hash"]) in anchor_file.read_text()
