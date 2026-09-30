"""Health / readiness."""

import time
from datetime import datetime

from flask import jsonify, current_app

from collector.api.helpers import api_bp


@api_bp.route("/health", methods=["GET"])
def health_check():
    checks = {}
    is_healthy = True

    try:
        start = time.time()
        from collector.db import get_db
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        latency = round((time.time() - start) * 1000, 2)
        checks["database"] = {"status": "ok", "latency_ms": latency}
    except Exception as e:
        checks["database"] = {"status": "error", "message": str(e)}
        is_healthy = False

    try:
        if hasattr(current_app, 'extensions') and 'limiter' in current_app.extensions:
            current_app.extensions['limiter'].storage.client.ping()
            checks["redis"] = {"status": "ok"}
    except Exception as e:
        checks["redis"] = {"status": "degraded", "message": str(e)}

    status_code = 200 if is_healthy else 503
    return jsonify({
        "status": "healthy" if is_healthy else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "0.2.1",
        "checks": checks
    }), status_code


@api_bp.route("/readiness", methods=["GET"])
def readiness_check():
    return jsonify({"ready": True, "timestamp": datetime.utcnow().isoformat()}), 200