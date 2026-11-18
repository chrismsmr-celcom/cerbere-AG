"""Rapport de conformité (PDF) : preuves de contrôle pour un CISO ou un auditeur.

Le rapport résume, pour UNE organisation et UNE période :
  - l'activité surveillée (actions des agents, blocages) ;
  - les événements de sécurité, d'accès, de supervision humaine et d'incident ;
  - l'intégrité du journal d'audit, vérifiée de bout en bout (chaîne de hashs et
    signatures de checkpoints) au moment de la génération ;
  - la configuration des contrôles ;
  - la correspondance des événements avec des référentiels (OWASP LLM Top 10, etc.).

Principes :
  - Les chiffres viennent des données enregistrées ; rien n'est présenté comme réussi
    quand la vérification n'a pas pu avoir lieu (statuts VERIFIED / FAILED / UNAVAILABLE).
  - Aucun contenu d'événement (`details`, prompts, secrets) n'est lu ni affiché :
    seulement type, horodatage, acteur, ressource, action et niveau de risque.
  - Le rapport porte une empreinte SHA-256 de son contenu : deux générations sur les
    mêmes données donnent la même empreinte.
  - C'est une preuve technique de contrôles, pas une certification ni un avis juridique.

Réservé aux offres Team et Enterprise (fonctionnalité `compliance_reports`).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from calendar import monthrange
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

import structlog

from collector import licensing
from collector.db import is_postgres, sql_placeholder

logger = structlog.get_logger("agentguard.compliance")

REPORT_VERSION = 1
MAX_RANGE_DAYS = 366

# ── Catégories d'événements ───────────────────────────────────────────────

SECURITY_EVENTS = [
    "prompt_blocked",
    "injection_detected",
    "tool_blocked",
    "taint_violation",
    "pii_detected",
    "signed_deny",
    "budget_exceeded",
]
ACCESS_EVENTS = ["login_success", "login_failed", "api_key_created", "api_key_revoked"]
OVERSIGHT_EVENTS = [
    "approval_granted",
    "approval_rejected",
    "agent_disconnected",
    "agent_reconnected",
]
INCIDENT_EVENTS = [
    "incident_opened",
    "incident_closed",
    "incident_revealed",
    "incident_reveal_denied",
]
GOVERNANCE_EVENTS = ["policy_loaded", "policy_changed", "config_changed"]

# Marqueur : « tous les événements enregistrés » (journalisation automatique, EU AI Act art. 12)
ALL_EVENTS = "*"

EVENT_LABELS = {
    "prompt_blocked": "Prompt blocked",
    "injection_detected": "Injection detected",
    "tool_blocked": "Tool call blocked",
    "taint_violation": "Sensitive data flow blocked",
    "pii_detected": "Personal data detected",
    "signed_deny": "Signed deny decision",
    "budget_exceeded": "Budget exceeded",
    "login_success": "Successful sign-in",
    "login_failed": "Failed sign-in",
    "api_key_created": "API key created",
    "api_key_revoked": "API key revoked",
    "approval_granted": "Human approval granted",
    "approval_rejected": "Human approval rejected",
    "agent_disconnected": "Agent disconnected",
    "agent_reconnected": "Agent reconnected",
    "incident_opened": "Incident opened",
    "incident_closed": "Incident closed",
    "incident_revealed": "Incident evidence revealed",
    "incident_reveal_denied": "Evidence reveal denied",
    "policy_loaded": "Policy loaded",
    "policy_changed": "Policy changed",
    "config_changed": "Configuration changed",
}

# Correspondance événements -> référentiels. Formulation volontairement prudente :
# ce sont des PREUVES pertinentes pour un contrôle, pas une attestation de conformité.
# À faire relire par un conseil conformité avant toute communication commerciale.
FRAMEWORK_MAP = [
    (
        "OWASP LLM Top 10 (2025)",
        "LLM01",
        "Prompt injection",
        ["prompt_blocked", "injection_detected"],
    ),
    (
        "OWASP LLM Top 10 (2025)",
        "LLM02",
        "Sensitive information disclosure",
        ["pii_detected", "taint_violation"],
    ),
    (
        "OWASP LLM Top 10 (2025)",
        "LLM06",
        "Excessive agency",
        [
            "tool_blocked",
            "signed_deny",
            "approval_granted",
            "approval_rejected",
            "agent_disconnected",
        ],
    ),
    (
        "OWASP LLM Top 10 (2025)",
        "LLM10",
        "Unbounded consumption",
        ["budget_exceeded"],
    ),
    (
        "EU AI Act",
        "Art. 12",
        "Record-keeping (automatic logging)",
        ALL_EVENTS,
    ),
    (
        "EU AI Act",
        "Art. 14",
        "Human oversight",
        ["approval_granted", "approval_rejected", "agent_disconnected"],
    ),
    (
        "ISO/IEC 27001:2022",
        "A.8.15",
        "Logging",
        ["login_success", "login_failed", "config_changed", "policy_changed"],
    ),
    (
        "ISO/IEC 27001:2022",
        "A.8.16",
        "Monitoring activities",
        SECURITY_EVENTS,
    ),
]

_DISCLAIMER = (
    "This report is technical evidence of controls operated by Cerbere AG and recorded in "
    "its audit log. It is not a certification, an audit opinion or legal advice. Mappings to "
    "frameworks show which recorded events are relevant to a control; whether a control "
    "objective is met is for the organization and its auditors to assess."
)


class PeriodError(ValueError):
    """Période demandée invalide (message affichable)."""


# ── Période ───────────────────────────────────────────────────────────────


def _utc(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)


def parse_period(
    period: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Retourne {since, until, label, start, end, partial} (bornes UTC, fin exclusive).

    - period="2026-10"              : mois civil
    - date_from/date_to="2026-10-01"/"2026-10-15" : plage, fin incluse
    - rien                          : mois civil précédent
    """
    now = now or datetime.now(timezone.utc)
    try:
        if period and (date_from or date_to):
            raise PeriodError("Use either period or from/to, not both.")
        if period:
            parsed = datetime.strptime(period, "%Y-%m")
            start = _utc(parsed.year, parsed.month, 1)
            end = start + timedelta(days=monthrange(parsed.year, parsed.month)[1])
            label = period
        elif date_from or date_to:
            if not (date_from and date_to):
                raise PeriodError("Both from and to are required (YYYY-MM-DD).")
            first = datetime.strptime(date_from, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            last = datetime.strptime(date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            start, end = first, last + timedelta(days=1)
            label = f"{date_from}_to_{date_to}"
        else:
            first_of_month = _utc(now.year, now.month, 1)
            prev_end = first_of_month
            prev_last = first_of_month - timedelta(days=1)
            start = _utc(prev_last.year, prev_last.month, 1)
            end = prev_end
            label = start.strftime("%Y-%m")
    except ValueError as exc:
        if isinstance(exc, PeriodError):
            raise
        raise PeriodError(
            "Invalid date. Use period=YYYY-MM or from/to as YYYY-MM-DD."
        ) from exc

    if end <= start:
        raise PeriodError("The end of the period is before its start.")
    if (end - start).days > MAX_RANGE_DAYS:
        raise PeriodError(f"The period cannot exceed {MAX_RANGE_DAYS} days.")
    return {
        "since": start.timestamp(),
        "until": end.timestamp(),
        "label": label,
        "start": start.strftime("%Y-%m-%d"),
        "end": (end - timedelta(days=1)).strftime("%Y-%m-%d"),
        "partial": end > now,
    }


# ── Collecte ──────────────────────────────────────────────────────────────


def _iso(ts: float | None) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _truthy(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _db():
    from collector.auth.users import _db_execute

    return _db_execute


def org_name(org_id: str) -> str:
    try:
        row = _db()(
            f"SELECT name FROM orgs WHERE org_id = {sql_placeholder()}",
            (org_id,),
            fetchone=True,
        )
        return str(row[0]) if row and row[0] else org_id
    except Exception:
        return org_id


def _is_single_tenant() -> bool:
    try:
        row = _db()("SELECT COUNT(*) FROM orgs", fetchone=True)
        return int(row[0]) <= 1
    except Exception:
        return False


def _bound(ts: float):
    moment = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
    return moment if is_postgres() else moment.strftime("%Y-%m-%d %H:%M:%S")


def _activity(org_id: str, since: float, until: float) -> dict | None:
    """Actions surveillées (table spans) sur la période ; None si indisponible."""
    p = sql_placeholder()
    where = f"org_id = {p} AND created_at >= {p} AND created_at < {p}"
    params = (org_id, _bound(since), _bound(until))
    try:
        row = _db()(
            "SELECT COUNT(*), SUM(CASE WHEN blocked THEN 1 ELSE 0 END) "
            f"FROM spans WHERE {where}",
            params,
            fetchone=True,
        )
        total, blocked = int(row[0] or 0), int(row[1] or 0)
        layers = _db()(
            "SELECT COALESCE(detection_layer, 'unspecified'), COUNT(*) "
            f"FROM spans WHERE {where} AND blocked GROUP BY 1 ORDER BY 2 DESC",
            params,
            fetchall=True,
        )
    except Exception as exc:
        logger.warning("compliance_activity_unavailable", error=str(exc))
        return None
    return {
        "actions": total,
        "blocked": blocked,
        "block_rate": round(blocked / total, 4) if total else 0.0,
        "blocked_by_layer": {str(layer): int(n) for layer, n in layers},
    }


def _integrity(audit, single_tenant: bool) -> dict:
    """Vérifie TOUTE la chaîne maintenant. Ne dit jamais « vérifiée » sans l'avoir fait."""
    if audit is None:
        return {"status": "unavailable", "reason": "The audit log is not available."}
    try:
        valid, rep = audit.verify_chain_full()
        summary = audit.chain_summary()
    except Exception as exc:
        logger.error("compliance_integrity_check_failed", error=str(exc))
        return {
            "status": "unavailable",
            "reason": f"Verification could not complete: {exc}"[:240],
        }

    if rep.get("status") == "empty":
        status = "empty"
    else:
        status = "verified" if valid else "failed"
    violations = rep.get("violations", [])
    health = audit.status()
    signing = getattr(audit, "_verifier", None) is not None
    return {
        "status": status,
        "entries_checked": rep.get("entries_checked", 0) if single_tenant else None,
        "violations": len(violations),
        "violation_examples": [
            {"type": v.get("type"), "event_id": v.get("event_id")}
            for v in violations[:5]
        ],
        "signatures_verified": rep.get("signatures_verified", 0),
        "signatures_failed": rep.get("signatures_failed", 0),
        "signing_configured": signing,
        "head_hash": summary.get("head_hash"),
        "last_checkpoint": _iso(
            (summary.get("last_checkpoint") or {}).get("timestamp")
        ),
        "storage": "database" if getattr(audit, "database_url", None) else "local file",
        "write_state": health.get("state"),
        "persist_failures": health.get("persist_failures", 0),
    }


def _controls() -> dict:
    from collector.auth import config as auth_config
    from collector.auth.oidc import get_config as sso_config

    sso_active = sso_config() is not None
    lic = licensing.status_dict()
    return {
        "authentication": {
            "password": bool(auth_config.PASSWORD_LOGIN_ENABLED or not sso_active),
            "magic_link": bool(auth_config.MAGIC_LINK_ENABLED),
            "company_sso": sso_active,
            "public_signup": bool(auth_config.SIGNUP_ENABLED),
        },
        "detection": {
            "rules_and_patterns": True,
            "local_ml": _truthy("AGENTGUARD_USE_ML"),
            "llm_judge": _truthy("AGENTGUARD_USE_LLM_JUDGE"),
        },
        "plan": lic["plan"],
        "license_status": lic["status"],
    }


def _recent(audit, org_id: str, since: float, until: float) -> dict:
    """Quelques lignes d'exemple (métadonnées seulement, jamais `details`)."""

    def slim(entries):
        return [
            {
                "time": _iso(e.get("timestamp")),
                "ts": e.get("timestamp") or 0,
                "type": e.get("event_type"),
                "actor": e.get("actor"),
                "resource": e.get("resource"),
                "action": e.get("action"),
            }
            for e in entries
        ]

    if audit is None:
        return {"critical": [], "approvals": []}
    try:
        critical = audit.query(
            org_id=org_id, risk_level="critical", since=since, until=until, limit=25
        )
        granted = audit.query(
            org_id=org_id,
            event_type="approval_granted",
            since=since,
            until=until,
            limit=15,
        )
        rejected = audit.query(
            org_id=org_id,
            event_type="approval_rejected",
            since=since,
            until=until,
            limit=15,
        )
    except Exception as exc:
        logger.warning("compliance_recent_failed", error=str(exc))
        return {"critical": [], "approvals": []}
    approvals = sorted(slim(granted + rejected), key=lambda e: e["ts"], reverse=True)[
        :20
    ]
    ordered = sorted(slim(critical), key=lambda e: e["ts"], reverse=True)
    for item in ordered + approvals:
        item.pop("ts", None)
    return {"critical": ordered, "approvals": approvals}


def _frameworks(by_type: dict) -> list[dict]:
    total = sum(by_type.values())
    return [
        {
            "framework": framework,
            "reference": ref,
            "topic": topic,
            "events": total
            if types == ALL_EVENTS
            else sum(by_type.get(t, 0) for t in set(types)),
        }
        for framework, ref, topic, types in FRAMEWORK_MAP
    ]


def record_generation(audit, org_id: str, actor: str, data: dict) -> None:
    """Générer un rapport de conformité est lui-même une action auditée."""
    if audit is None:
        return
    try:
        from agentguard.audit import AuditEventType

        audit.log_event(
            AuditEventType.COMPLIANCE_REPORT_GENERATED,
            org_id=org_id,
            actor=actor,
            resource=f"report:{data['report_id']}",
            action="generated",
            details={
                "period": data["period"]["label"],
                "fingerprint": data["fingerprint"],
                "integrity": data["integrity"]["status"],
            },
        )
    except Exception as exc:
        logger.warning("compliance_report_not_audited", error=str(exc))


def fingerprint(data: dict) -> str:
    """SHA-256 du contenu du rapport (hors date de génération et empreinte elle-même)."""
    body = {
        k: v
        for k, v in data.items()
        if k not in {"fingerprint", "generated_at", "report_id"}
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def build_report_data(
    org_id: str,
    period: dict,
    audit=None,
    now: datetime | None = None,
    verify: bool = True,
) -> dict:
    """Assemble toutes les données du rapport (JSON sérialisable)."""
    now = now or datetime.now(timezone.utc)
    since, until = period["since"], period["until"]
    single = _is_single_tenant()

    aggregate = {
        "total": 0,
        "by_type": {},
        "by_risk": {},
        "by_type_risk": {},
        "by_day": {},
        "by_actor": {},
    }
    if audit is not None:
        try:
            aggregate = audit.aggregate_org(
                org_id, since, until, actor_event_types=SECURITY_EVENTS
            )
        except Exception as exc:
            logger.warning("compliance_aggregate_failed", error=str(exc))

    integrity = (
        _integrity(audit, single)
        if verify
        else {
            "status": "unavailable",
            "reason": "Verification was skipped for this report.",
        }
    )

    data = {
        "version": REPORT_VERSION,
        "period": {k: period[k] for k in ("label", "start", "end", "partial")},
        "org": {"id": org_id, "name": org_name(org_id)},
        "instance": {"single_tenant": single},
        "activity": _activity(org_id, since, until),
        "audit": aggregate,
        "recent": _recent(audit, org_id, since, until),
        "integrity": integrity,
        "controls": _controls(),
        "frameworks": _frameworks(aggregate["by_type"]),
    }
    data["fingerprint"] = fingerprint(data)
    data["report_id"] = "CR-" + data["fingerprint"][:12].upper()
    data["generated_at"] = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    return data


# ── Phrases de synthèse ───────────────────────────────────────────────────


def _n(value) -> str:
    return f"{int(value or 0):,}"


def summary_lines(data: dict) -> list[str]:
    audit = data["audit"]
    by_type = audit["by_type"]
    period = data["period"]
    lines: list[str] = []

    act = data["activity"]
    if act is None:
        lines.append(
            "Agent activity volumes were not available when this report was generated."
        )
    elif act["actions"] == 0:
        lines.append(f"No monitored agent actions were recorded for {period['label']}.")
    else:
        lines.append(
            f"Cerbere monitored {_n(act['actions'])} agent actions in this period and blocked "
            f"{_n(act['blocked'])} of them ({act['block_rate'] * 100:.2f}%)."
        )

    sec = sum(by_type.get(t, 0) for t in SECURITY_EVENTS)
    crit = sum(
        audit["by_type_risk"].get(t, {}).get("critical", 0) for t in SECURITY_EVENTS
    )
    if sec:
        lines.append(
            f"{_n(sec)} security events were recorded, {_n(crit)} of them at critical risk level."
        )
    else:
        lines.append(
            "No security events were recorded in the audit log for this period."
        )

    granted, rejected = (
        by_type.get("approval_granted", 0),
        by_type.get("approval_rejected", 0),
    )
    if granted or rejected:
        lines.append(
            f"Human reviewers decided {_n(granted + rejected)} approval requests: "
            f"{_n(granted)} granted, {_n(rejected)} rejected."
        )
    else:
        lines.append("No human approval decisions were recorded in this period.")

    failed, ok = by_type.get("login_failed", 0), by_type.get("login_success", 0)
    lines.append(f"Sign-ins: {_n(ok)} successful, {_n(failed)} failed.")

    integ = data["integrity"]
    status = integ["status"]
    if status == "verified":
        lines.append(
            "The audit log hash chain was verified from its first entry to the most recent one at "
            "generation time: no tampering or gaps were detected."
        )
    elif status == "failed":
        lines.append(
            f"ATTENTION: the audit log integrity check FAILED with {_n(integ['violations'])} "
            "violation(s). The recorded evidence cannot be relied upon until this is investigated."
        )
    elif status == "empty":
        lines.append("The audit log is empty, so there was nothing to verify.")
    else:
        lines.append(
            "The audit log integrity could NOT be verified for this report. "
            f"{integ.get('reason', '')}".strip()
        )
    return lines


# ── PDF ───────────────────────────────────────────────────────────────────


def render_pdf(data: dict) -> bytes:
    """Met en page le rapport (A4). Police intégrée : ASCII et Latin-1 uniquement."""
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.shapes import Drawing
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.platypus import (
        KeepTogether,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    ORANGE = colors.HexColor("#E8590C")
    CREAM = colors.HexColor("#FFF4E6")
    INK = colors.HexColor("#1F2933")
    GRAY = colors.HexColor("#6B7280")
    LINE = colors.HexColor("#E5D5C0")
    GREEN = colors.HexColor("#2F855A")
    RED = colors.HexColor("#C53030")
    AMBER = colors.HexColor("#B7791F")

    body = ParagraphStyle(
        "body",
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=INK,
        alignment=TA_LEFT,
    )
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=11, textColor=GRAY)
    cell = ParagraphStyle("cell", parent=body, fontSize=8.5, leading=11)
    cellb = ParagraphStyle("cellb", parent=cell, fontName="Helvetica-Bold")
    head = ParagraphStyle(
        "head", parent=cell, fontName="Helvetica-Bold", textColor=colors.white
    )
    mono = ParagraphStyle(
        "mono", parent=body, fontName="Courier", fontSize=7.5, leading=10
    )
    h1 = ParagraphStyle(
        "h1",
        parent=body,
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=ORANGE,
        spaceBefore=12,
        spaceAfter=4,
        keepWithNext=1,
    )
    title = ParagraphStyle(
        "title",
        parent=body,
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.white,
    )
    subtitle = ParagraphStyle(
        "subtitle", parent=body, fontSize=11, leading=15, textColor=colors.white
    )
    kpi_value = ParagraphStyle(
        "kpiv",
        parent=body,
        fontName="Helvetica-Bold",
        fontSize=17,
        leading=20,
        textColor=INK,
    )
    kpi_label = ParagraphStyle("kpil", parent=small, fontSize=7.5, leading=10)

    def P(text, style=cell):
        return Paragraph(escape(str(text)), style)

    def cut(text, limit=46):
        text = str(text if text is not None else "-")
        return text if len(text) <= limit else text[: limit - 3] + "..."

    def table(rows, widths, header=True, zebra=True, extra=None):
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
        style = [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ]
        if header:
            style.append(("BACKGROUND", (0, 0), (-1, 0), ORANGE))
        if zebra:
            for i in range(1 if header else 0, len(rows)):
                if i % 2 == 0:
                    style.append(("BACKGROUND", (0, i), (-1, i), CREAM))
        t.setStyle(TableStyle(style + (extra or [])))
        return t

    def status_cell(text, color):
        return Paragraph(
            f'<font color="{color.hexval().replace("0x", "#")}"><b>{escape(text)}</b></font>',
            cell,
        )

    usable = A4[0] - 36 * mm
    audit, integ, ctrl = data["audit"], data["integrity"], data["controls"]
    by_type = audit["by_type"]
    story = []

    # ── Couverture ──
    banner = Table(
        [
            [Paragraph("AI Agent Security &amp; Compliance Report", title)],
            [
                Paragraph(
                    f"{escape(data['org']['name'])}  |  {escape(data['period']['start'])} to {escape(data['period']['end'])} (UTC)",
                    subtitle,
                )
            ],
        ],
        colWidths=[usable],
    )
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), ORANGE),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("TOPPADDING", (0, 0), (0, 0), 16),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 14),
            ]
        )
    )
    story += [banner, Spacer(1, 10)]

    partial = " (period not yet complete)" if data["period"]["partial"] else ""
    meta_rows = [
        [P("Organization", cellb), P(f"{data['org']['name']}  ({data['org']['id']})")],
        [
            P("Reporting period", cellb),
            P(f"{data['period']['start']} to {data['period']['end']}{partial}"),
        ],
        [P("Generated", cellb), P(data["generated_at"])],
        [P("Report ID", cellb), P(data["report_id"])],
        [P("Plan", cellb), P(str(ctrl["plan"]).title())],
    ]
    story += [
        table(meta_rows, [38 * mm, usable - 38 * mm], header=False, zebra=False),
        Spacer(1, 10),
    ]

    act = data["activity"]
    status_map = {
        "verified": ("VERIFIED", GREEN),
        "failed": ("FAILED", RED),
        "empty": ("EMPTY", AMBER),
        "unavailable": ("UNAVAILABLE", AMBER),
    }
    chain_text, chain_color = status_map[integ["status"]]
    sec_total = sum(by_type.get(t, 0) for t in SECURITY_EVENTS)

    def kpi(value, label, color=INK):
        v = ParagraphStyle("v", parent=kpi_value, textColor=color)
        return [Paragraph(escape(str(value)), v), Paragraph(escape(label), kpi_label)]

    cards = Table(
        [
            [
                kpi(_n(act["actions"]) if act else "n/a", "AGENT ACTIONS MONITORED"),
                kpi(_n(act["blocked"]) if act else "n/a", "ACTIONS BLOCKED"),
                kpi(_n(sec_total), "SECURITY EVENTS"),
                kpi(chain_text, "AUDIT CHAIN INTEGRITY", chain_color),
            ]
        ],
        colWidths=[usable / 4] * 4,
    )
    cards.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CREAM),
                ("BOX", (0, 0), (-1, -1), 0.6, LINE),
                ("LINEAFTER", (0, 0), (-2, -1), 0.6, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story += [cards, Paragraph("Executive summary", h1)]
    for line in summary_lines(data):
        story.append(Paragraph("-  " + escape(line), body))
        story.append(Spacer(1, 3))

    # ── 1. Intégrité du journal d'audit ──
    story.append(Paragraph("1. Audit log integrity", h1))
    story.append(
        Paragraph(
            "Every audit entry is chained to the previous one by a cryptographic hash. The whole "
            "chain was re-verified, entry by entry, when this report was generated.",
            body,
        )
    )
    story.append(Spacer(1, 4))

    def result_cell():
        return status_cell(chain_text, chain_color)

    rows = [[P("Check", head), P("Result", head), P("Detail", head)]]
    if integ["status"] in {"verified", "failed", "empty"}:
        detail = {
            "verified": "No altered, missing or reordered entries.",
            "failed": f"{_n(integ['violations'])} violation(s) found. Examples: "
            + ", ".join(
                f"{v['type']} ({cut(v['event_id'], 12)})"
                for v in integ["violation_examples"]
            ),
            "empty": "No entries recorded yet.",
        }[integ["status"]]
        rows.append([P("Hash chain, first to last entry"), result_cell(), P(detail)])
        if integ["entries_checked"] is not None:
            rows.append(
                [
                    P("Entries verified"),
                    P(_n(integ["entries_checked"])),
                    P("Whole chain, all periods."),
                ]
            )
        if integ["signing_configured"]:
            ok = integ["signatures_failed"] == 0
            rows.append(
                [
                    P("Signed checkpoints"),
                    status_cell("PASS" if ok else "FAIL", GREEN if ok else RED),
                    P(
                        f"{_n(integ['signatures_verified'])} verified, {_n(integ['signatures_failed'])} failed."
                    ),
                ]
            )
        else:
            rows.append(
                [
                    P("Signed checkpoints"),
                    status_cell("NOT CONFIGURED", AMBER),
                    P(
                        "No signing key is configured, so checkpoints are not signed. The hash chain still applies."
                    ),
                ]
            )
        rows.append(
            [P("Last signed checkpoint"), P(integ["last_checkpoint"] or "none"), P("")]
        )
    else:
        rows.append(
            [
                P("Hash chain, first to last entry"),
                result_cell(),
                P(integ.get("reason", "")),
            ]
        )
    rows.append(
        [
            P("Audit storage"),
            P(str(integ.get("storage", "unknown")).title()),
            P(
                "Durable database storage."
                if integ.get("storage") == "database"
                else "Local file backup: use the database for durable evidence."
            ),
        ]
    )
    if integ.get("write_state"):
        healthy = integ["write_state"] == "OK"
        rows.append(
            [
                P("Audit write health"),
                status_cell("OK" if healthy else "DEGRADED", GREEN if healthy else RED),
                P(
                    f"{_n(integ.get('persist_failures', 0))} write failure(s) since start."
                ),
            ]
        )
    story.append(table(rows, [46 * mm, 34 * mm, usable - 80 * mm]))
    if integ.get("head_hash"):
        story += [
            Spacer(1, 5),
            Paragraph(
                "Chain head at generation time (SHA-256). Keep it to prove later that the chain was not rewritten:",
                small,
            ),
            Paragraph(escape(integ["head_hash"]), mono),
        ]

    # ── 2. Activité de sécurité ──
    story.append(Paragraph("2. Security activity", h1))
    if act is not None and act["blocked_by_layer"]:
        story.append(
            Paragraph(
                "Blocked actions by detection layer",
                ParagraphStyle("lh", parent=cellb, spaceAfter=3),
            )
        )
        layer_rows = [[P("Detection layer", head), P("Blocked actions", head)]]
        layer_rows += [
            [P(layer), P(_n(n))] for layer, n in act["blocked_by_layer"].items()
        ]
        story += [table(layer_rows, [70 * mm, 40 * mm]), Spacer(1, 8)]

    story.append(
        Paragraph(
            "Security events by type",
            ParagraphStyle("st", parent=cellb, spaceAfter=3, keepWithNext=1),
        )
    )
    sec_rows = [
        [
            P("Event", head),
            P("Total", head),
            P("Critical", head),
            P("Warning", head),
            P("Info", head),
        ]
    ]
    for t in SECURITY_EVENTS:
        n = by_type.get(t, 0)
        per_risk = audit["by_type_risk"].get(t, {})
        sec_rows.append(
            [
                P(EVENT_LABELS[t]),
                P(_n(n)),
                P(_n(per_risk.get("critical", 0))),
                P(_n(per_risk.get("warning", 0))),
                P(_n(per_risk.get("info", 0))),
            ]
        )
    story.append(
        table(sec_rows, [66 * mm, 24 * mm, 24 * mm, 24 * mm, usable - 138 * mm])
    )

    # graphique : événements de sécurité par jour (par semaine au-delà de 62 jours)
    start = datetime.strptime(data["period"]["start"], "%Y-%m-%d")
    end = datetime.strptime(data["period"]["end"], "%Y-%m-%d")
    days = [
        (start + timedelta(days=i)).strftime("%Y-%m-%d")
        for i in range((end - start).days + 1)
    ]
    per_day = [
        sum(audit["by_day"].get(d, {}).get(t, 0) for t in SECURITY_EVENTS) for d in days
    ]
    if sum(per_day):
        step = 1 if len(days) <= 62 else 7
        values = [sum(per_day[i : i + step]) for i in range(0, len(days), step)]
        names = []
        for idx, i in enumerate(range(0, len(days), step)):
            label = days[i][8:] if step == 1 else days[i][5:]
            keep = max(1, len(values) // 12)
            names.append(label if idx % keep == 0 else "")
        drawing = Drawing(usable, 150)
        chart = VerticalBarChart()
        chart.x, chart.y, chart.width, chart.height = 30, 22, usable - 40, 112
        chart.data = [values]
        chart.bars[0].fillColor = ORANGE
        chart.bars[0].strokeColor = None
        chart.categoryAxis.categoryNames = names
        chart.categoryAxis.labels.fontSize = 7
        chart.valueAxis.labels.fontSize = 7
        chart.valueAxis.valueMin = 0
        chart.valueAxis.visibleGrid = True
        chart.valueAxis.gridStrokeColor = LINE
        peak = max(values)
        step_value = max(1, -(-peak // 5))  # au plus ~5 graduations, toujours entières
        chart.valueAxis.valueStep = step_value
        chart.valueAxis.valueMax = -(-peak // step_value) * step_value
        chart.valueAxis.labelTextFormat = "%d"
        chart.barWidth = 6
        drawing.add(chart)
        story += [
            Spacer(1, 8),
            Paragraph(
                "Security events per " + ("day" if step == 1 else "week") + " (UTC)",
                ParagraphStyle("ch", parent=cellb, spaceAfter=2),
            ),
            drawing,
        ]

    if audit["by_actor"]:
        top = sorted(audit["by_actor"].items(), key=lambda kv: kv[1], reverse=True)[:10]
        actor_rows = [[P("Agent or user", head), P("Security events", head)]]
        actor_rows += [[P(cut(a)), P(_n(n))] for a, n in top]
        story += [
            Spacer(1, 6),
            KeepTogether(
                [
                    Paragraph(
                        "Top sources of security events",
                        ParagraphStyle("ta", parent=cellb, spaceAfter=3),
                    ),
                    table(actor_rows, [90 * mm, 40 * mm]),
                ]
            ),
        ]

    # ── 3. Supervision humaine ──
    story.append(Paragraph("3. Human oversight and agent control", h1))
    over_rows = [[P("Event", head), P("Count", head)]]
    over_rows += [
        [P(EVENT_LABELS[t]), P(_n(by_type.get(t, 0)))] for t in OVERSIGHT_EVENTS
    ]
    story.append(table(over_rows, [90 * mm, 40 * mm]))
    approvals = data["recent"]["approvals"]
    if approvals:
        ap_rows = [
            [
                P("Time (UTC)", head),
                P("Decision", head),
                P("Decided by", head),
                P("Request", head),
            ]
        ]
        for e in approvals:
            ap_rows.append(
                [
                    P(e["time"]),
                    P("Granted" if e["type"] == "approval_granted" else "Rejected"),
                    P(cut(e["actor"], 28)),
                    P(cut(e["resource"], 40)),
                ]
            )
        story += [
            Spacer(1, 6),
            Paragraph(
                "Most recent decisions",
                ParagraphStyle("rd", parent=cellb, spaceAfter=3),
            ),
            table(ap_rows, [40 * mm, 22 * mm, 46 * mm, usable - 108 * mm]),
        ]

    # ── 4. Accès et administration ──
    story.append(Paragraph("4. Access and administration", h1))
    acc_rows = [[P("Event", head), P("Count", head)]]
    for t in ACCESS_EVENTS + GOVERNANCE_EVENTS:
        acc_rows.append([P(EVENT_LABELS[t]), P(_n(by_type.get(t, 0)))])
    story.append(table(acc_rows, [90 * mm, 40 * mm]))
    auth = ctrl["authentication"]
    det = ctrl["detection"]

    def onoff(flag, yes="Enabled", no="Disabled"):
        return status_cell(yes if flag else no, GREEN if flag else GRAY)

    cfg_rows = [
        [P("Control (configuration at generation time)", head), P("State", head)],
        [P("Company single sign-on (OIDC)"), onoff(auth["company_sso"])],
        [P("Password sign-in"), onoff(auth["password"])],
        [P("Email magic-link sign-in"), onoff(auth["magic_link"])],
        [
            P("Public self-registration"),
            status_cell(
                "Enabled" if auth["public_signup"] else "Disabled",
                AMBER if auth["public_signup"] else GREEN,
            ),
        ],
        [P("Rules and pattern detection"), onoff(det["rules_and_patterns"])],
        [P("Local machine-learning detection"), onoff(det["local_ml"])],
        [P("LLM judge"), onoff(det["llm_judge"])],
    ]
    story += [Spacer(1, 8), table(cfg_rows, [90 * mm, 40 * mm])]

    # ── 5. Incidents ──
    story.append(Paragraph("5. Incidents", h1))
    inc_rows = [[P("Event", head), P("Count", head)]]
    inc_rows += [
        [P(EVENT_LABELS[t]), P(_n(by_type.get(t, 0)))] for t in INCIDENT_EVENTS
    ]
    story.append(table(inc_rows, [90 * mm, 40 * mm]))

    # ── 6. Correspondance avec les référentiels ──
    story.append(Paragraph("6. Evidence relevant to common frameworks", h1))
    story.append(
        Paragraph(
            escape(
                "Number of events recorded in this period that are relevant to each control topic."
            ),
            small,
        )
    )
    story.append(Spacer(1, 4))
    fw_rows = [
        [
            P("Framework", head),
            P("Reference", head),
            P("Topic", head),
            P("Events", head),
        ]
    ]
    for f in data["frameworks"]:
        fw_rows.append(
            [P(f["framework"]), P(f["reference"]), P(f["topic"]), P(_n(f["events"]))]
        )
    story.append(
        table(
            fw_rows, [46 * mm, 22 * mm, usable - 46 * mm - 22 * mm - 22 * mm, 22 * mm]
        )
    )

    # ── Annexe : événements critiques ──
    crit = data["recent"]["critical"]
    story.append(Paragraph("Appendix: most recent critical events", h1))
    if crit:
        cr_rows = [
            [
                P("Time (UTC)", head),
                P("Event", head),
                P("Source", head),
                P("Resource", head),
                P("Action", head),
            ]
        ]
        for e in crit:
            cr_rows.append(
                [
                    P(e["time"]),
                    P(EVENT_LABELS.get(e["type"], e["type"])),
                    P(cut(e["actor"], 24)),
                    P(cut(e["resource"], 28)),
                    P(cut(e["action"], 14)),
                ]
            )
        story.append(
            table(
                cr_rows,
                [
                    40 * mm,
                    36 * mm,
                    34 * mm,
                    usable - 40 * mm - 36 * mm - 34 * mm - 20 * mm,
                    20 * mm,
                ],
            )
        )
        story.append(Spacer(1, 3))
        story.append(
            Paragraph(
                "Event contents (prompts, tool arguments, matched values) are intentionally not reproduced in this report.",
                small,
            )
        )
    else:
        story.append(
            Paragraph("No critical events were recorded in this period.", body)
        )

    # ── Méthode et limites ──
    story.append(Paragraph("About this report", h1))
    story.append(Paragraph(escape(_DISCLAIMER), body))
    story.append(Spacer(1, 5))
    story.append(
        Paragraph(
            "Report fingerprint (SHA-256 of the report data, excluding generation time):",
            small,
        )
    )
    story.append(Paragraph(escape(data["fingerprint"]), mono))

    # ── Pied de page « Page X sur Y » ──
    org_label = cut(data["org"]["name"], 32)

    class NumberedCanvas(rl_canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved = []

        def showPage(self):
            self._saved.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._saved)
            for state in self._saved:
                self.__dict__.update(state)
                self._decorate(total)
                super().showPage()
            super().save()

        def _decorate(self, total):
            width, height = A4
            self.setStrokeColor(ORANGE)
            self.setLineWidth(1.2)
            self.line(18 * mm, height - 11 * mm, width - 18 * mm, height - 11 * mm)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(GRAY)
            self.drawString(
                18 * mm,
                10 * mm,
                f"Cerbere AG - Compliance report - {org_label} - {data['period']['label']} - {data['report_id']}",
            )
            self.drawRightString(
                width - 18 * mm, 10 * mm, f"Page {self._pageNumber} of {total}"
            )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=17 * mm,
        title=f"Compliance report - {data['org']['name']} - {data['period']['label']}",
        author="Cerbere AG",
        subject=f"Report {data['report_id']}",
    )
    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
