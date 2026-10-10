"""Budgets, règles de politique, destinations d'alertes, routes d'audit."""
import time

import pytest

KEYS = {"key-a": "org-a", "key-b": "org-b"}


def hdr(key="key-a", agent="finance-bot"):
    return {"X-API-Key": key, "X-Agent-Id": agent}


def span(i, blocked=False, cost=0.5, checks=None):
    return {"trace_id": f"t{i}", "span_id": f"s{i}", "span_type": "tool_call",
            "timestamp": time.time(), "latency_ms": 10 + i, "cost_usd": cost,
            "input_data": {"tool": "send_email", "prompt": "hello"}, "output_data": {},
            "blocked": blocked, "block_reason": "bad" if blocked else None,
            "security_checks": checks or []}


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    import collector.auth as auth
    import collector.api as api
    monkeypatch.setattr(auth, "resolve_org_id", lambda key: KEYS.get(key))
    api._AGENT_SEEN.clear()
    api._AGENT_STATUS.clear()

    from collector.db import init_db
    from collector.app import create_app
    init_db()
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c, api, monkeypatch



def _as_human(api, monkeypatch, org="org-a"):
    from flask import g
    import collector.auth.middleware as middleware

    def fake_human_auth():
        g.org_id = org
        g.human_email = "ciso@acme.io"
        return True

    def fake_global_auth():
        # Simule l'authentification globale uniquement dans les tests.
        g.org_id = org
        g.human_email = "ciso@acme.io"
        return True

    monkeypatch.setattr(api, "require_human_auth", fake_human_auth)
    monkeypatch.setattr(middleware, "require_auth", fake_global_auth)



# ── budgets ────────────────────────────────────────────────────────────────

def test_budget_needs_human_and_computes_real_spend(ctx):
    c, api, mp = ctx
    c.post("/span", json=span(1, cost=2.0), headers=hdr())
    c.post("/span", json=span(2, cost=1.5), headers=hdr())

    body = {"max_budget_usd": 10, "period": "daily", "action_on_exceed": "block"}
    assert c.put("/api/budgets/finance-bot", json=body, headers=hdr()).status_code == 401

    _as_human(api, mp)
    r = c.put("/api/budgets/finance-bot", json=body, headers=hdr())
    assert r.status_code == 200
    data = r.get_json()
    assert data["spent_usd"] == pytest.approx(3.5)
    assert data["pct"] == 35.0 and data["exceeded"] is False

    got = c.get("/api/budgets/finance-bot", headers={"X-API-Key": "key-a"}).get_json()
    assert got["configured"] is True and got["max_budget_usd"] == 10


def test_budget_validation_and_isolation(ctx):
    c, api, mp = ctx
    _as_human(api, mp)
    for bad in ({"max_budget_usd": -1}, {"max_budget_usd": "abc"},
                {"max_budget_usd": float("nan")}, {"max_budget_usd": 5, "period": "hourly"},
                {"max_budget_usd": 5, "action_on_exceed": "explode"}):
        assert c.put("/api/budgets/finance-bot", json=bad).status_code == 400
    c.put("/api/budgets/finance-bot", json={"max_budget_usd": 5})
    other = c.get("/api/budgets", headers={"X-API-Key": "key-b"}).get_json()
    assert other["total"] == 0
    unset = c.get("/api/budgets/ghost", headers={"X-API-Key": "key-a"}).get_json()
    assert unset["configured"] is False


# ── règles de politique ────────────────────────────────────────────────────

def test_policy_rule_crud(ctx):
    c, api, mp = ctx
    rule = {"agent_scope": "all", "event_type": "tool_call", "tool_name": "send_email",
            "detection_type": "pii_detection", "operator": ">", "threshold": "0.8",
            "action": "block"}
    assert c.post("/api/policy-rules", json=rule, headers=hdr()).status_code == 401
    _as_human(api, mp)
    created = c.post("/api/policy-rules", json=rule)
    assert created.status_code == 201
    rid = created.get_json()["id"]
    assert c.post("/api/policy-rules", json={**rule, "action": "nuke"}).status_code == 400
    assert c.post("/api/policy-rules", json={**rule, "threshold": "x"}).status_code == 400

    lst = c.get("/api/policy-rules", headers={"X-API-Key": "key-a"}).get_json()
    assert lst["total"] == 1 and lst["rules"][0]["enabled"] is True
    assert c.patch(f"/api/policy-rules/{rid}", json={"enabled": False}).status_code == 200
    assert c.get("/api/policy-rules", headers={"X-API-Key": "key-a"}).get_json()["rules"][0]["enabled"] is False
    assert c.delete(f"/api/policy-rules/{rid}").status_code == 200
    assert c.delete(f"/api/policy-rules/{rid}").status_code == 404


# ── destinations d'alertes ─────────────────────────────────────────────────

def test_destination_masks_secret_and_blocks_ssrf(ctx):
    c, api, mp = ctx
    _as_human(api, mp)
    url = "https://hooks.slack.com/services/T000/B000/SECRETSECRET1234"
    r = c.post("/api/alert-destinations", json={"type": "slack", "url": url, "levels": ["high", "critical"]})
    assert r.status_code == 201
    d = r.get_json()
    assert "SECRETSECRET" not in d["url"] and d["url"].endswith("1234")
    assert d["levels"] == ["critical", "high"]

    lst = c.get("/api/alert-destinations", headers={"X-API-Key": "key-a"}).get_json()
    assert lst["total"] == 1 and "SECRETSECRET" not in str(lst)

    for bad in ("http://hooks.slack.com/x", "https://localhost/x", "https://127.0.0.1/x",
                "https://169.254.169.254/latest", "https://user:pw@example.com/x"):
        r = c.post("/api/alert-destinations", json={"type": "webhook", "url": bad, "levels": ["high"]})
        assert r.status_code == 400, bad
    assert c.post("/api/alert-destinations", json={"type": "email", "url": "nope", "levels": ["high"]}).status_code == 400
    assert c.post("/api/alert-destinations", json={"type": "email", "url": "a@b.io", "levels": []}).status_code == 400
    assert c.delete(f"/api/alert-destinations/{d['id']}").status_code == 200


def test_destination_test_sends_real_request(ctx):
    c, api, mp = ctx
    _as_human(api, mp)
    import collector.api.settings as st

    sent = {}

    class R:
        status_code = 200

    def fake_post(url, json=None, timeout=None, allow_redirects=None):
        sent.update(url=url, json=json, redirects=allow_redirects)
        return R()

    mp.setattr(st.requests, "post", fake_post)
    mp.setattr(st, "_check_webhook_url", lambda url, resolve: None)
    r = c.post("/api/alert-destinations/test", json={"type": "slack", "url": "https://hooks.slack.com/services/a/b/c"})
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert "text" in sent["json"] and sent["redirects"] is False
    assert c.post("/api/alert-destinations/test", json={"type": "email", "url": "a@b.io"}).status_code == 400


# ── audit : forme attendue par dashboard.js ────────────────────────────────

def test_audit_trail_summary_event_use_real_spans(ctx):
    c, api, _ = ctx
    bad = [{"check_name": "prompt_injection", "passed": False, "risk_level": "critical",
            "details": "ignore previous"}]
    c.post("/span", json=span(1), headers=hdr())
    c.post("/span", json=span(2, blocked=True, checks=bad), headers=hdr())
    c.post("/span", json=span(3, checks=[{"check_name": "pii_detection", "passed": False,
                                          "risk_level": "medium"}]), headers=hdr())

    trail = c.get("/api/audit/trail", headers={"X-API-Key": "key-a"}).get_json()
    assert len(trail) == 3
    by_id = {e["event_id"]: e for e in trail}
    assert by_id["s2"]["decision"] == "blocked" and by_id["s2"]["risk"] == "critical"
    assert by_id["s2"]["agent"] == "finance-bot" and by_id["s2"]["tool"] == "send_email"
    assert by_id["s3"]["decision"] == "flagged" and by_id["s1"]["decision"] == "allowed"

    s = c.get("/api/audit/summary", headers={"X-API-Key": "key-a"}).get_json()
    assert (s["total"], s["blocked"], s["flagged"], s["allowed"]) == (3, 1, 1, 1)
    assert s["critical"] == 1 and s["affected_agents"] == 1

    ev = c.get("/api/audit/event/s2", headers={"X-API-Key": "key-a"}).get_json()
    assert ev["detection_type"] == "prompt_injection" and ev["enforcement_action"] == "block"
    assert c.get("/api/audit/event/nope", headers={"X-API-Key": "key-a"}).status_code == 404

    other = c.get("/api/audit/trail", headers={"X-API-Key": "key-b"}).get_json()
    assert other == []
    assert c.get("/api/audit/trail").status_code == 401


def test_dashboard_widgets_do_not_500(ctx):
    c, _, _ = ctx
    c.post("/span", json=span(1), headers=hdr())
    for path in ("/api/checks/breakdown", "/api/latency/distribution", "/api/events/recent"):
        assert c.get(path, headers={"X-API-Key": "key-a"}).status_code == 200, path
