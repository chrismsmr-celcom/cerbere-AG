"""TEMPORAIRE : GET /api/_whoami renvoie l'adresse que le collector voit pour TON appel,
et les en-têtes posés par les proxys (Render/Cloudflare). Sert à choisir le bon nombre de
proxys de confiance (AGENTGUARD_TRUSTED_PROXIES) pour que le limiteur de débit
distingue les clients au lieu de tous les voir comme l'adresse du proxy.

Installation : copier dans collector/api/ + ajouter `import collector.api.whoami` dans
collector/api/__init__.py. À SUPPRIMER une fois la valeur trouvée.
Protégé comme le reste de l'API (clé API ou session) ; ne renvoie que TES propres infos."""

from flask import jsonify, request

from collector.api.helpers import api_bp
from collector.auth import require_auth

_HEADERS = ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP", "Forwarded", "X-Forwarded-Proto")


@api_bp.route("/api/_whoami", methods=["GET"], endpoint="api_whoami")
def api_whoami():
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(
        {
            "remote_addr_vu_par_flask": request.remote_addr,
            "en_tetes": {h: request.headers.get(h) for h in _HEADERS if request.headers.get(h)},
        }
    ), 200
