"""GET /api/license : plan et état de la licence de cette instance (administrateurs)."""

from flask import jsonify

from collector import licensing
from collector.api.helpers import api_bp
from collector.auth.rbac import require_role


@api_bp.route("/api/license", methods=["GET"], endpoint="api_license")
@require_role("admin")
def api_license():
    return jsonify(licensing.status_dict()), 200
