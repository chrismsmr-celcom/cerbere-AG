"""Données de test pour le rapport de conformité : journal d'audit à dates contrôlées."""

import time as _time
import types
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class Clock:
    now = 0.0


def signing_pem() -> str:
    return (
        Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


def ts(day: str, hh: int = 12, mm: int = 0, ss: int = 0) -> float:
    moment = datetime.strptime(day, "%Y-%m-%d").replace(
        hour=hh, minute=mm, second=ss, tzinfo=timezone.utc
    )
    return moment.timestamp()


def make_audit(monkeypatch, tmp_path, database_url=None, signing=True, sign_every=10):
    """Journal d'audit dont l'horloge est pilotée par le test (`clock.now`)."""
    from agentguard import audit as audit_module

    clock = Clock()
    fake_time = types.SimpleNamespace(
        **{k: getattr(_time, k) for k in dir(_time) if not k.startswith("_")}
    )
    fake_time.time = lambda: clock.now
    monkeypatch.setattr(audit_module, "time", fake_time)
    log = audit_module.ImmutableAuditLog(
        database_url=database_url,
        backup_file=str(tmp_path / "audit.jsonl"),
        signing_key_pem=signing_pem() if signing else None,
        sign_every=sign_every,
    )
    return log, clock


def log(
    audit,
    clock,
    when,
    org,
    event,
    risk="info",
    actor="system",
    resource="x",
    action="recorded",
    details=None,
):
    clock.now = when
    return audit.log_event(
        event,
        org_id=org,
        actor=actor,
        resource=resource,
        action=action,
        details=details or {},
        risk_level=risk,
    )


# (jour, événement, risque, acteur) pour l'organisation « acme », octobre 2026.
SECURITY = [
    ("2026-10-03", "prompt_blocked", "critical", "agent-billing"),
    ("2026-10-03", "prompt_blocked", "warning", "agent-support"),
    ("2026-10-10", "prompt_blocked", "warning", "agent-support"),
    ("2026-10-15", "prompt_blocked", "warning", "agent-support"),
    ("2026-10-20", "prompt_blocked", "critical", "agent-billing"),
    ("2026-10-04", "injection_detected", "critical", "agent-support"),
    ("2026-10-11", "injection_detected", "warning", "agent-support"),
    ("2026-10-12", "injection_detected", "warning", "agent-research"),
    ("2026-10-25", "injection_detected", "warning", "agent-research"),
    ("2026-10-05", "tool_blocked", "warning", "agent-billing"),
    ("2026-10-06", "tool_blocked", "warning", "agent-billing"),
    ("2026-10-18", "tool_blocked", "warning", "agent-research"),
    ("2026-10-07", "taint_violation", "critical", "agent-research"),
    ("2026-10-21", "taint_violation", "critical", "agent-research"),
    ("2026-10-08", "pii_detected", "warning", "agent-support"),
    ("2026-10-22", "pii_detected", "warning", "agent-support"),
    ("2026-10-09", "budget_exceeded", "warning", "agent-research"),
    ("2026-10-30", "signed_deny", "critical", "agent-billing"),
]
SECURITY_TOTAL, SECURITY_CRITICAL = 18, 6

OTHER = [
    ("2026-10-05", "approval_granted", "info", "alice@acme.example"),
    ("2026-10-13", "approval_granted", "info", "alice@acme.example"),
    ("2026-10-27", "approval_granted", "info", "bob@acme.example"),
    ("2026-10-06", "approval_rejected", "info", "alice@acme.example"),
    ("2026-10-14", "approval_rejected", "info", "bob@acme.example"),
    ("2026-10-16", "agent_disconnected", "warning", "alice@acme.example"),
    ("2026-10-17", "agent_reconnected", "info", "alice@acme.example"),
    ("2026-10-02", "login_success", "info", "alice@acme.example"),
    ("2026-10-08", "login_success", "info", "bob@acme.example"),
    ("2026-10-12", "login_success", "info", "alice@acme.example"),
    ("2026-10-19", "login_success", "info", "bob@acme.example"),
    ("2026-10-26", "login_success", "info", "alice@acme.example"),
    ("2026-10-09", "login_failed", "warning", "mallory@evil.example"),
    ("2026-10-09", "login_failed", "warning", "mallory@evil.example"),
    ("2026-10-02", "api_key_created", "info", "alice@acme.example"),
    ("2026-10-28", "api_key_revoked", "info", "alice@acme.example"),
    ("2026-10-19", "policy_changed", "info", "alice@acme.example"),
    ("2026-10-23", "config_changed", "info", "alice@acme.example"),
    ("2026-10-09", "incident_opened", "critical", "alice@acme.example"),
    ("2026-10-10", "incident_closed", "info", "alice@acme.example"),
]
# + 1 connexion pile à minuit le 1er octobre (début inclus) = 6 connexions réussies
ACME_TOTAL = SECURITY_TOTAL + len(OTHER) + 1


def seed_october(audit, clock, acme="org-acme", other="org-other"):
    """Peuple le journal : octobre pour `acme`, bruit pour `other`, et bornes hors période."""
    log(
        audit,
        clock,
        ts("2026-09-30", 23, 59, 59),
        acme,
        "login_success",
        actor="before@acme.example",
    )  # exclu
    log(
        audit,
        clock,
        ts("2026-10-01", 0, 0, 0),
        acme,
        "login_success",
        actor="alice@acme.example",
    )  # inclus
    for day, event, risk, actor in SECURITY + OTHER:
        log(
            audit,
            clock,
            ts(day),
            acme,
            event,
            risk,
            actor=actor,
            resource=f"span:{event[:6]}",
            action="blocked",
            details={
                "prompt": "PRIVATE-EVENT-CONTENT-4242",
                "matched": "MATCHED-VALUE-DO-NOT-PRINT",
            },
        )
    for i in range(7):  # une autre organisation : ne doit jamais apparaître chez acme
        log(
            audit,
            clock,
            ts("2026-10-15", 8 + i),
            other,
            "prompt_blocked",
            "critical",
            actor="agent-other",
        )
    log(
        audit,
        clock,
        ts("2026-11-01", 0, 0, 0),
        acme,
        "login_success",
        actor="after@acme.example",
    )  # exclu (fin exclusive)


def seed_spans(org_id, other_org="org-other"):
    """Actions surveillées : 200 pour org_id (12 bloquées), 50 pour une autre organisation."""
    from collector.auth.users import _db_execute
    from collector.db import sql_placeholder

    p = sql_placeholder()
    sql = (
        "INSERT INTO spans (trace_id, span_id, span_type, timestamp, blocked, block_reason, "
        f"detection_layer, org_id, created_at) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p})"
    )

    def add(i, org, blocked, layer, created):
        _db_execute(
            sql,
            (
                f"t{i}",
                f"s{i}",
                "llm",
                0.0,
                blocked,
                "rule" if blocked else None,
                layer if blocked else None,
                org,
                created,
            ),
        )

    layers = ["regex"] * 7 + ["ml"] * 3 + ["llm"] * 2
    for i in range(200):
        blocked = i < 12
        day = 1 + (i % 28)
        add(
            i,
            org_id,
            blocked,
            layers[i] if blocked else None,
            f"2026-10-{day:02d} 10:00:00",
        )
    for i in range(50):
        add(1000 + i, other_org, i < 9, "regex", "2026-10-10 10:00:00")
    add(2000, org_id, True, "regex", "2026-09-30 23:59:59")  # exclu
    add(2001, org_id, True, "regex", "2026-11-01 00:00:00")  # exclu
