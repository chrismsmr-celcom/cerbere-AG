"""GET /api/compliance/report : rapport de conformité (PDF ou JSON).

Réservé au rôle auditeur et aux rôles supérieurs (les rôles sont hiérarchiques : admin > developer >
auditor > viewer), et aux offres Team et Enterprise.
Paramètres : period=YYYY-MM | from=YYYY-MM-DD&to=YYYY-MM-DD, format=pdf|json.
Sans période : le mois civil précédent.
"""

import re

from flask import Response, g, jsonify, request

from collector import compliance_report as report
from collector import licensing
from collector.api.helpers import api_bp
from collector.audit_routes import get_audit_log
from collector.auth.rbac import require_role
from collector.extensions import limiter


def _actor() -> str:
    user = getattr(g, "authenticated_user", None)
    if user is not None and len(user) > 3:
        return str(user[3])
    return "api-key"


@api_bp.route(
    "/api/compliance/report", methods=["GET"], endpoint="api_compliance_report"
)
@require_role("auditor")  # auditeur et au-dessus ; un viewer est refusé
@limiter.limit("12 per hour")  # la vérification complète de la chaîne est coûteuse
def api_compliance_report():
    if not licensing.has_feature("compliance_reports"):
        return (
            jsonify(
                {
                    "error": "Compliance reports are part of the Team and Enterprise plans.",
                    "feature": "compliance_reports",
                    "required_plan": "team",
                }
            ),
            403,
        )

    fmt = (request.args.get("format") or "pdf").lower()
    if fmt not in {"pdf", "json"}:
        return jsonify({"error": "format must be pdf or json"}), 400
    try:
        period = report.parse_period(
            request.args.get("period"), request.args.get("from"), request.args.get("to")
        )
    except report.PeriodError as exc:
        return jsonify({"error": str(exc)}), 400

    audit = get_audit_log()
    data = report.build_report_data(g.org_id, period, audit=audit)
    report.record_generation(audit, g.org_id, _actor(), data)

    if fmt == "json":
        response = jsonify(data)
        response.headers["Cache-Control"] = "no-store"
        return response

    safe_org = (
        re.sub(r"[^A-Za-z0-9_.-]+", "-", data["org"]["name"]).strip("-")[:40] or "org"
    )
    filename = f"cerbere-compliance-{safe_org}-{data['period']['label']}.pdf"
    return Response(
        report.render_pdf(data),
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
