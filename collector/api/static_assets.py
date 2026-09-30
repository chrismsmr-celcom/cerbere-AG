"""Assets statiques : logo, favicon."""

import os
import structlog
from flask import send_from_directory

from collector.api.helpers import api_bp, logger


@api_bp.route("/logo.svg")
def serve_logo():
    static_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
    try:
        return send_from_directory(static_path, "logo.svg", mimetype="image/svg+xml")
    except Exception as e:
        logger.warning("logo_serve_failed", error=str(e))
        fallback_svg = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
  <rect width="100" height="100" fill="#2563eb"/>
  <text x="50" y="60" font-family="sans-serif" font-size="40" fill="white" text-anchor="middle">AG</text>
</svg>"""
        return fallback_svg, 200, {"Content-Type": "image/svg+xml"}


@api_bp.route("/favicon.ico")
def serve_favicon():
    static_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
    try:
        return send_from_directory(static_path, "logo.svg", mimetype="image/x-icon")
    except Exception:
        return "", 204