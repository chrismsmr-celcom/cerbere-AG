"""Rapport de conformité : audit en flux, données, PDF, API et CLI.

SQLite/fichier par défaut ; PostgreSQL si AGENTGUARD_TEST_DATABASE_URL est défini :
    AGENTGUARD_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/testdb pytest tests/test_compliance_report.py
"""

import io
import json
import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from collector import cli
from collector import compliance_report as cr
from tests.compliance_helpers import (
    ACME_TOTAL,
    SECURITY_CRITICAL,
    SECURITY_TOTAL,
    log,
    make_audit,
    seed_october,
    seed_spans,
    ts,
)
from tests.licensing_helpers import install

pypdf = pytest.importorskip("pypdf")

NOW = datetime(2026, 11, 9, 10, 30, tzinfo=timezone.utc)
PASSWORD = "correct-horse-battery"
PG_URL = os.environ.get("AGENTGUARD_TEST_DATABASE_URL", "").strip() or None


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_LICENSE_KEY", raising=False)
    monkeypatch.delenv("AGENTGUARD_LICENSE_FILE", raising=False)


@pytest.fixture
def env(tmp_path, monkeypatch):
    from tests.dbmode import configure_db

    configure_db(monkeypatch, tmp_path, "compliance")
    monkeypatch.setenv("AGENTGUARD_FLASK_SECRET", "test-flask-secret-for-ci-only")
    monkeypatch.setenv("AGENTGUARD_COOKIE_SECURE", "false")
    monkeypatch.delenv("AGENTGUARD_ENVIRONMENT", raising=False)

    from collector.auth.local_password import provision_workspace
    from collector.db import init_db
    from collector.migrations import run_migrations

    init_db()
    run_migrations()
    _, acme, acme_tenant = provision_workspace(
        "alice@acme.example", PASSWORD, org_name="Acme Corp"
    )
    _, other, _ = provision_workspace("o@other.example", PASSWORD, org_name="Other Inc")

    audit, clock = make_audit(monkeypatch, tmp_path, database_url=PG_URL, sign_every=25)
    seed_october(audit, clock, acme=acme, other=other)
    seed_spans(acme, other)

    from collector import audit_routes

    monkeypatch.setattr(audit_routes, "_audit_log_instance", audit)
    return SimpleNamespace(
        acme=acme,
        other=other,
        tenant=acme_tenant,
        audit=audit,
        clock=clock,
        tmp=tmp_path,
    )


def period(label="2026-10"):
    return cr.parse_period(label, now=NOW)


def build(env, **kw):
    return cr.build_report_data(env.acme, period(), audit=env.audit, now=NOW, **kw)


def pdf_text(data_bytes):
    reader = pypdf.PdfReader(io.BytesIO(data_bytes))
    return "\n".join(page.extract_text() for page in reader.pages), len(reader.pages)


def tamper(audit, event_id, **changes):
    if audit.database_url:
        import psycopg

        sets = ", ".join(f"{k} = %s" for k in changes)
        with psycopg.connect(audit.database_url, autocommit=True) as conn:
            conn.execute(
                f"UPDATE audit_log SET {sets} WHERE event_id = %s",
                (*changes.values(), event_id),
            )
        return
    with open(audit.backup_file) as handle:
        lines = handle.read().splitlines()
    out = []
    for line in lines:
        entry = json.loads(line)
        if entry["event_id"] == event_id:
            entry.update(changes)
        out.append(json.dumps(entry))
    with open(audit.backup_file, "w") as handle:
        handle.write("\n".join(out) + "\n")


def delete_entry(audit, event_id):
    if audit.database_url:
        import psycopg

        with psycopg.connect(audit.database_url, autocommit=True) as conn:
            conn.execute("DELETE FROM audit_log WHERE event_id = %s", (event_id,))
        return
    with open(audit.backup_file) as handle:
        lines = handle.read().splitlines()
    kept = [ln for ln in lines if json.loads(ln)["event_id"] != event_id]
    with open(audit.backup_file, "w") as handle:
        handle.write("\n".join(kept) + "\n")


def event_ids(audit):
    return [e["event_id"] for e in audit._load_entries()]


# ── Période ───────────────────────────────────────────────────────────────


def test_period_calendar_month():
    p = cr.parse_period("2026-10", now=NOW)
    assert (p["start"], p["end"], p["label"], p["partial"]) == (
        "2026-10-01",
        "2026-10-31",
        "2026-10",
        False,
    )
    assert p["until"] - p["since"] == 31 * 86400


def test_period_range_is_inclusive_of_the_last_day():
    p = cr.parse_period(date_from="2026-10-01", date_to="2026-10-15", now=NOW)
    assert p["end"] == "2026-10-15" and p["until"] - p["since"] == 15 * 86400


def test_period_defaults_to_previous_calendar_month():
    p = cr.parse_period(now=datetime(2026, 1, 20, tzinfo=timezone.utc))
    assert (p["start"], p["end"]) == ("2025-12-01", "2025-12-31")


def test_period_in_progress_is_flagged_partial():
    assert cr.parse_period("2026-11", now=NOW)["partial"] is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {"period": "2026-13"},
        {"period": "october"},
        {"period": "2026-10", "date_from": "2026-10-01", "date_to": "2026-10-02"},
        {"date_from": "2026-10-01"},
        {"date_from": "2026-10-10", "date_to": "2026-10-01"},
        {"date_from": "2025-01-01", "date_to": "2026-12-31"},
        {"date_from": "2026-02-30", "date_to": "2026-03-01"},
    ],
)
def test_invalid_periods_are_rejected(kwargs):
    with pytest.raises(cr.PeriodError):
        cr.parse_period(now=NOW, **kwargs)


# ── Journal d'audit : agrégats et vérification complète en flux ───────────


def test_aggregate_counts_only_the_org_and_the_period(env):
    p = period()
    agg = env.audit.aggregate_org(
        env.acme, p["since"], p["until"], actor_event_types=cr.SECURITY_EVENTS
    )
    assert agg["total"] == ACME_TOTAL == 39
    assert sum(agg["by_type"].get(t, 0) for t in cr.SECURITY_EVENTS) == SECURITY_TOTAL
    assert (
        sum(
            agg["by_type_risk"].get(t, {}).get("critical", 0)
            for t in cr.SECURITY_EVENTS
        )
        == SECURITY_CRITICAL
    )
    assert agg["by_risk"]["critical"] == SECURITY_CRITICAL + 1  # + l'incident ouvert
    assert agg["by_type"]["prompt_blocked"] == 5
    assert agg["by_day"]["2026-10-03"]["prompt_blocked"] == 2
    assert agg["by_actor"] == {
        "agent-billing": 5,
        "agent-support": 7,
        "agent-research": 6,
    }
    # début inclus (minuit le 1er), fin exclue (minuit le 1er novembre), avant-veille exclue
    assert agg["by_type"]["login_success"] == 6


def test_aggregate_never_mixes_organizations(env):
    p = period()
    other = env.audit.aggregate_org(env.other, p["since"], p["until"])
    assert other["total"] == 7 and other["by_type"] == {"prompt_blocked": 7}


def test_full_verification_is_valid_and_matches_the_classic_one(env):
    ok_full, full = env.audit.verify_chain_full()
    ok_classic, classic = env.audit.verify_chain()
    assert ok_full and ok_classic
    for key in (
        "entries_checked",
        "first_entry",
        "last_entry",
        "signatures_verified",
        "signatures_failed",
    ):
        assert full[key] == classic[key]
    assert full["entries_checked"] > 40 and full["signatures_verified"] >= 1
    assert full["violations"] == []


@pytest.mark.parametrize("where", ["first", "middle", "last"])
def test_full_verification_detects_tampering_anywhere(env, where):
    ids = event_ids(env.audit)
    target = {"first": ids[0], "middle": ids[len(ids) // 2], "last": ids[-1]}[where]
    tamper(env.audit, target, action="allowed")
    ok, rep = env.audit.verify_chain_full()
    assert not ok and rep["status"] == "tampered"
    assert any(
        v["type"] == "hash_mismatch" and v["event_id"] == target
        for v in rep["violations"]
    )


def test_full_verification_detects_a_deleted_entry(env):
    ids = event_ids(env.audit)
    delete_entry(env.audit, ids[len(ids) // 2])
    ok, rep = env.audit.verify_chain_full()
    assert not ok and any(v["type"] == "chain_break" for v in rep["violations"])


@pytest.mark.skipif(
    PG_URL is not None, reason="lecture du fichier de secours uniquement"
)
def test_unreadable_line_in_the_file_backend_is_reported(env):
    with open(env.audit.backup_file) as handle:
        lines = handle.read().splitlines()
    lines.insert(len(lines) // 2, "{this is not json")
    with open(env.audit.backup_file, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    ok, rep = env.audit.verify_chain_full()
    assert not ok and any(v["type"] == "unreadable_entry" for v in rep["violations"])


def test_streaming_in_small_batches_returns_every_entry_in_order(env):
    assert [e["event_id"] for e in env.audit._stream_entries(batch=3)] == event_ids(
        env.audit
    )


def test_empty_chain_is_reported_as_empty(env, tmp_path, monkeypatch):
    fresh, _ = make_audit(monkeypatch, tmp_path / "empty", database_url=None)
    ok, rep = fresh.verify_chain_full()
    assert ok and rep == {"status": "empty", "entries_checked": 0}


def test_chain_summary_exposes_head_and_last_signed_checkpoint(env):
    summary = env.audit.chain_summary()
    assert summary["head_hash"] == env.audit._load_entries()[-1]["entry_hash"]
    assert summary["last_checkpoint"] and summary["last_checkpoint"]["timestamp"] > 0


# ── Données du rapport ────────────────────────────────────────────────────


def test_report_data_content(env):
    d = build(env)
    assert d["org"] == {"id": env.acme, "name": "Acme Corp"}
    assert d["period"] == {
        "label": "2026-10",
        "start": "2026-10-01",
        "end": "2026-10-31",
        "partial": False,
    }
    assert d["audit"]["total"] == 39
    assert d["activity"] == {
        "actions": 200,
        "blocked": 12,
        "block_rate": 0.06,
        "blocked_by_layer": {"regex": 7, "ml": 3, "llm": 2},
    }
    assert d["integrity"]["status"] == "verified"
    assert (
        d["integrity"]["signatures_failed"] == 0
        and d["integrity"]["signing_configured"]
    )
    refs = {f["reference"]: f["events"] for f in d["frameworks"]}
    assert (
        refs["LLM01"] == 9
        and refs["LLM02"] == 4
        and refs["LLM06"] == 10
        and refs["LLM10"] == 1
    )
    assert (
        refs["Art. 12"] == 39
        and refs["Art. 14"] == 6
        and refs["A.8.15"] == 10
        and refs["A.8.16"] == 18
    )
    assert d["report_id"].startswith("CR-") and len(d["fingerprint"]) == 64


def test_report_excludes_other_organizations_and_out_of_period_events(env):
    text = json.dumps(build(env))
    for leaked in (
        "agent-other",
        "before@acme.example",
        "after@acme.example",
        "Other Inc",
    ):
        assert leaked not in text


def test_report_never_contains_event_contents(env):
    d = build(env)
    pdf = cr.render_pdf(d)
    secrets = ("PRIVATE-EVENT-CONTENT-4242", "MATCHED-VALUE-DO-NOT-PRINT")
    for leaked in secrets:
        assert leaked not in json.dumps(d)
        assert leaked not in pdf_text(pdf)[0]


def test_fingerprint_is_stable_and_sensitive_to_content(env):
    first = build(env)
    later = cr.build_report_data(
        env.acme,
        period(),
        audit=env.audit,
        now=datetime(2026, 12, 1, tzinfo=timezone.utc),
    )
    assert (
        first["fingerprint"] == later["fingerprint"]
        and first["report_id"] == later["report_id"]
    )
    assert first["generated_at"] != later["generated_at"]

    log(
        env.audit,
        env.clock,
        ts("2026-10-20"),
        env.acme,
        "prompt_blocked",
        "warning",
        actor="agent-support",
    )
    assert build(env)["fingerprint"] != first["fingerprint"]


def test_tampered_chain_is_reported_as_failed_everywhere(env):
    tamper(env.audit, event_ids(env.audit)[5], actor="someone-else")
    d = build(env)
    assert d["integrity"]["status"] == "failed" and d["integrity"]["violations"] >= 1
    assert any(line.startswith("ATTENTION") for line in cr.summary_lines(d))
    text, _ = pdf_text(cr.render_pdf(d))
    assert "FAILED" in text and "VERIFIED" not in text


def test_unavailable_audit_is_never_presented_as_verified(env):
    d = cr.build_report_data(env.acme, period(), audit=None, now=NOW)
    assert d["integrity"]["status"] == "unavailable" and d["audit"]["total"] == 0
    assert any("could NOT be verified" in line for line in cr.summary_lines(d))
    text, _ = pdf_text(cr.render_pdf(d))
    assert "UNAVAILABLE" in text and "VERIFIED" not in text


def test_verification_can_be_skipped_but_is_then_marked_unavailable(env):
    assert build(env, verify=False)["integrity"]["status"] == "unavailable"


def test_missing_signing_key_is_reported_honestly(env, tmp_path, monkeypatch):
    unsigned, clock = make_audit(
        monkeypatch, tmp_path / "unsigned", database_url=None, signing=False
    )
    log(unsigned, clock, ts("2026-10-05"), env.acme, "prompt_blocked", "warning")
    d = cr.build_report_data(env.acme, period(), audit=unsigned, now=NOW)
    assert (
        d["integrity"]["status"] == "verified"
        and d["integrity"]["signing_configured"] is False
    )
    assert d["integrity"]["last_checkpoint"] is None
    assert "NOT CONFIGURED" in pdf_text(cr.render_pdf(d))[0]


def test_global_entry_count_is_hidden_on_multi_tenant_instances(env, monkeypatch):
    shared = build(env)  # deux organisations dans la base
    assert (
        shared["instance"]["single_tenant"] is False
        and shared["integrity"]["entries_checked"] is None
    )
    assert "Entries verified" not in pdf_text(cr.render_pdf(shared))[0]
    monkeypatch.setattr(cr, "_is_single_tenant", lambda: True)
    single = build(env)
    assert isinstance(single["integrity"]["entries_checked"], int)
    assert "Entries verified" in pdf_text(cr.render_pdf(single))[0]


def test_organization_without_activity_still_gets_a_report(env):
    from collector.auth.local_password import provision_workspace

    _, empty_org, _ = provision_workspace(
        "e@empty.example", PASSWORD, org_name="Empty Ltd"
    )
    d = cr.build_report_data(empty_org, period(), audit=env.audit, now=NOW)
    assert d["audit"]["total"] == 0 and d["activity"]["actions"] == 0
    lines = cr.summary_lines(d)
    assert any("No monitored agent actions" in line for line in lines)
    assert any("No security events" in line for line in lines)
    text, pages = pdf_text(cr.render_pdf(d))
    assert pages >= 1 and "Empty Ltd" in text


# ── PDF ───────────────────────────────────────────────────────────────────


def test_pdf_is_a_valid_multi_page_document_with_the_key_facts(env):
    pdf = cr.render_pdf(build(env))
    assert pdf.startswith(b"%PDF")
    text, pages = pdf_text(pdf)
    assert pages >= 3
    for expected in (
        "Acme Corp",
        "2026-10-01 to 2026-10-31",
        "VERIFIED",
        "PASS",
        "LLM01",
        "EU AI Act",
        "Prompt blocked",
    ):
        assert expected in text
    assert f"Page 1 of {pages}" in text and f"Page {pages} of {pages}" in text
    assert "intentionally not reproduced" in text
    meta = pypdf.PdfReader(io.BytesIO(pdf)).metadata
    assert "Acme Corp" in meta.title and meta.author == "Cerbere AG"


def test_pdf_fingerprint_matches_the_data(env):
    d = build(env)
    assert d["fingerprint"] in pdf_text(cr.render_pdf(d))[0].replace("\n", "")


def test_pdf_flags_a_period_still_in_progress(env):
    d = cr.build_report_data(
        env.acme, cr.parse_period("2026-11", now=NOW), audit=env.audit, now=NOW
    )
    assert "period not yet complete" in pdf_text(cr.render_pdf(d))[0]


def test_pdf_escapes_markup_in_names_and_truncates_long_values(env):
    from collector.auth.users import _db_execute
    from collector.db import sql_placeholder

    p = sql_placeholder()
    _db_execute(
        f"UPDATE orgs SET name = {p} WHERE org_id = {p}",
        ('<b>ACME</b> & "Co" <script>x</script>', env.acme),
    )
    log(
        env.audit,
        env.clock,
        ts("2026-10-12"),
        env.acme,
        "prompt_blocked",
        "critical",
        actor="a" * 200,
        resource="r" * 200,
    )
    text, _ = pdf_text(cr.render_pdf(build(env)))
    assert "ACME" in text and "<script>" in text  # affiché tel quel, jamais interprété
    assert "a" * 100 not in text  # tronqué


def test_pdf_with_a_year_long_range_groups_the_chart_by_week(env):
    p = cr.parse_period(date_from="2026-01-01", date_to="2026-12-31", now=NOW)
    d = cr.build_report_data(env.acme, p, audit=env.audit, now=NOW)
    assert "Security events per week" in pdf_text(cr.render_pdf(d))[0]


def test_pdf_generation_is_fast_with_many_actors(env):
    d = build(env)
    d["audit"]["by_actor"] = {f"agent-{i}": i + 1 for i in range(2000)}
    import time

    started = time.time()
    pdf = cr.render_pdf(d)
    assert time.time() - started < 10 and pdf.startswith(b"%PDF")
    assert (
        "agent-1999" in pdf_text(pdf)[0] and "agent-1000" not in pdf_text(pdf)[0]
    )  # top 10 seulement


# ── API ───────────────────────────────────────────────────────────────────


@pytest.fixture
def app(env):
    from collector.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False
    return app


def add_user(env, email, role):
    from collector.auth.local_password import hash_password
    from collector.auth.users import _db_execute
    from collector.db import is_postgres, sql_placeholder

    p = sql_placeholder()
    _db_execute(
        "INSERT INTO users (user_id, org_id, tenant_id, email, display_name, role, active, password_hash, created_at) "
        f"VALUES ({p},{p},{p},{p},{p},{p},{p},{p},CURRENT_TIMESTAMP)",
        (
            f"u-{email}",
            env.acme,
            env.tenant,
            email,
            email,
            role,
            True if is_postgres() else 1,
            hash_password(PASSWORD),
        ),
    )


def login(client, email):
    r = client.post("/auth/password", data={"email": email, "password": PASSWORD})
    assert r.status_code == 302, email


def test_api_requires_authentication(app):
    with app.test_client() as c:
        assert c.get("/api/compliance/report").status_code == 401


def test_api_refuses_viewers_and_follows_the_role_hierarchy(app, env, monkeypatch):
    """Rôles hiérarchiques (admin > developer > auditor > viewer) : auditeur et au-dessus."""
    install(monkeypatch, "team")
    add_user(env, "viewer@acme.example", "viewer")
    add_user(env, "dev@acme.example", "developer")
    with app.test_client() as c:
        login(c, "viewer@acme.example")
        assert c.get("/api/compliance/report?period=2026-10").status_code == 403
    with app.test_client() as c:
        login(c, "dev@acme.example")
        assert c.get("/api/compliance/report?period=2026-10").status_code == 200


def test_api_requires_a_team_or_enterprise_license(app, env, monkeypatch):
    with app.test_client() as c:
        login(c, "alice@acme.example")
        r = c.get("/api/compliance/report?period=2026-10")
        assert r.status_code == 403
        assert (
            r.get_json()["feature"] == "compliance_reports"
            and r.get_json()["required_plan"] == "team"
        )
    install(monkeypatch, "pro")
    with app.test_client() as c:
        login(c, "alice@acme.example")
        assert c.get("/api/compliance/report?period=2026-10").status_code == 403


@pytest.mark.parametrize("plan", ["team", "enterprise"])
def test_api_returns_the_pdf_for_licensed_plans(app, env, monkeypatch, plan):
    install(monkeypatch, plan)
    with app.test_client() as c:
        login(c, "alice@acme.example")
        r = c.get("/api/compliance/report?period=2026-10")
        assert r.status_code == 200 and r.mimetype == "application/pdf"
        assert (
            r.headers["Content-Disposition"]
            == 'attachment; filename="cerbere-compliance-Acme-Corp-2026-10.pdf"'
        )
        assert r.headers["Cache-Control"] == "no-store"
        text, _ = pdf_text(r.data)
        assert "Acme Corp" in text and "VERIFIED" in text


def test_api_allows_auditors(app, env, monkeypatch):
    install(monkeypatch, "team")
    add_user(env, "auditor@acme.example", "auditor")
    with app.test_client() as c:
        login(c, "auditor@acme.example")
        assert c.get("/api/compliance/report?period=2026-10").status_code == 200


def test_api_json_format_and_organization_isolation(app, env, monkeypatch):
    install(monkeypatch, "team")
    with app.test_client() as c:
        login(c, "alice@acme.example")
        mine = c.get("/api/compliance/report?period=2026-10&format=json").get_json()
        assert mine["org"]["id"] == env.acme and mine["audit"]["total"] == 39
    with app.test_client() as c:
        login(c, "o@other.example")
        theirs = c.get("/api/compliance/report?period=2026-10&format=json").get_json()
        assert theirs["org"]["id"] == env.other and theirs["audit"]["by_type"] == {
            "prompt_blocked": 7
        }
        assert "agent-billing" not in json.dumps(theirs)


@pytest.mark.parametrize(
    "query",
    [
        "period=2026-13",
        "period=2026-10&from=2026-10-01&to=2026-10-05",
        "from=2026-10-01",
        "period=2026-10&format=docx",
    ],
)
def test_api_rejects_bad_parameters(app, env, monkeypatch, query):
    install(monkeypatch, "team")
    with app.test_client() as c:
        login(c, "alice@acme.example")
        r = c.get(f"/api/compliance/report?{query}")
        assert r.status_code == 400 and "error" in r.get_json()


def test_api_defaults_to_the_previous_month(app, env, monkeypatch):
    install(monkeypatch, "team")
    with app.test_client() as c:
        login(c, "alice@acme.example")
        data = c.get("/api/compliance/report?format=json").get_json()
        assert data["period"]["label"] == cr.parse_period()["label"]


def test_generating_a_report_is_itself_audited(app, env, monkeypatch):
    install(monkeypatch, "team")
    with app.test_client() as c:
        login(c, "alice@acme.example")
        data = c.get("/api/compliance/report?period=2026-10&format=json").get_json()
    entries = env.audit.query(
        org_id=env.acme, event_type="compliance_report_generated", limit=10
    )
    assert len(entries) == 1
    entry = entries[0]
    assert (
        entry["actor"] == "alice@acme.example"
        and entry["resource"] == f"report:{data['report_id']}"
    )
    details = (
        entry["details"]
        if isinstance(entry["details"], dict)
        else json.loads(entry["details"])
    )
    assert (
        details["fingerprint"] == data["fingerprint"]
        and details["integrity"] == "verified"
    )
    assert env.audit.verify_chain_full()[0]  # et la chaîne reste valide


def test_api_still_answers_when_the_audit_log_is_unavailable(app, env, monkeypatch):
    install(monkeypatch, "team")
    monkeypatch.setattr("collector.api.compliance.get_audit_log", lambda: None)
    with app.test_client() as c:
        login(c, "alice@acme.example")
        data = c.get("/api/compliance/report?period=2026-10&format=json").get_json()
        assert data["integrity"]["status"] == "unavailable"


# ── CLI ───────────────────────────────────────────────────────────────────


def test_cli_requires_a_license(env, capsys):
    assert cli.main(["report", "--org", env.acme, "--period", "2026-10"]) == 1
    assert "Team and Enterprise" in capsys.readouterr().err


def test_cli_writes_the_pdf_and_prints_the_status(env, monkeypatch, capsys, tmp_path):
    install(monkeypatch, "team")
    out = tmp_path / "report.pdf"
    assert (
        cli.main(
            ["report", "--org", env.acme, "--period", "2026-10", "--out", str(out)]
        )
        == 0
    )
    assert "audit chain: verified" in capsys.readouterr().out
    assert out.read_bytes().startswith(b"%PDF")
    assert "Acme Corp" in pdf_text(out.read_bytes())[0]


def test_cli_exit_code_signals_a_failed_integrity_check(
    env, monkeypatch, capsys, tmp_path
):
    install(monkeypatch, "team")
    tamper(env.audit, event_ids(env.audit)[3], action="allowed")
    out = tmp_path / "report.pdf"
    assert (
        cli.main(
            ["report", "--org", env.acme, "--period", "2026-10", "--out", str(out)]
        )
        == 2
    )
    assert (
        out.exists() and "FAILED" in pdf_text(out.read_bytes())[0]
    )  # rapport écrit, mais alerte


def test_cli_json_output(env, monkeypatch, tmp_path):
    install(monkeypatch, "team")
    out = tmp_path / "report.json"
    assert (
        cli.main(
            [
                "report",
                "--org",
                env.acme,
                "--period",
                "2026-10",
                "--format",
                "json",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert json.loads(out.read_text())["audit"]["total"] == 39


def test_cli_needs_an_org_when_there_are_several(env, monkeypatch, capsys):
    install(monkeypatch, "team")
    assert cli.main(["report", "--period", "2026-10"]) == 1
    assert "--org" in capsys.readouterr().err


def test_cli_rejects_an_invalid_period(env, monkeypatch, capsys):
    install(monkeypatch, "team")
    assert cli.main(["report", "--org", env.acme, "--period", "nope"]) == 1
    assert "Invalid date" in capsys.readouterr().err


def test_cli_is_audited_too(env, monkeypatch, tmp_path):
    install(monkeypatch, "team")
    cli.main(
        [
            "report",
            "--org",
            env.acme,
            "--period",
            "2026-10",
            "--out",
            str(tmp_path / "r.pdf"),
        ]
    )
    entries = env.audit.query(
        org_id=env.acme, event_type="compliance_report_generated", limit=5
    )
    assert [e["actor"] for e in entries] == ["cli"]
