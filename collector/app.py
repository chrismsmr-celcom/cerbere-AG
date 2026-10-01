"""
Application factory and Flask configuration for Cerbere / AgentGuard.
"""

import os
import secrets
import time

import structlog
from datetime import datetime

from flask import Flask, jsonify
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer

from collector.extensions import limiter
from collector.db import get_db


# ==============================================================
# STRUCTLOG
# ==============================================================

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)

logger = structlog.get_logger("agentguard.collector")


# ==============================================================
# APPLICATION FACTORY
# ==============================================================

def create_app() -> Flask:
    """Create and configure the Flask application."""

    static_folder = os.path.join(
        os.path.dirname(__file__),
        "static",
    )

    app = Flask(
        __name__,
        static_folder=static_folder,
        static_url_path="/static",
    )

    # ==========================================================
    # ENVIRONMENT
    # ==========================================================

    app.config["ENVIRONMENT"] = os.environ.get(
        "AGENTGUARD_ENVIRONMENT",
        "development",
    )

    is_production = (
        app.config["ENVIRONMENT"].lower() == "production"
    )

    app.config["ALLOW_LEGACY_SYSTEM_KEY"] = (
        os.environ.get(
            "AGENTGUARD_ALLOW_LEGACY_SYSTEM_KEY",
            "false",
        ).lower()
        == "true"
    )

    # ==========================================================
    # FLASK SECRET
    # ==========================================================

    flask_secret = os.environ.get(
        "AGENTGUARD_FLASK_SECRET"
    )

    if not flask_secret:
        if is_production:
            raise RuntimeError(
                "AGENTGUARD_FLASK_SECRET must be configured "
                "in production. Generate one with: "
                "python -c "
                "\"import secrets; print(secrets.token_urlsafe(32))\""
            )

        flask_secret = secrets.token_urlsafe(32)

        logger.warning(
            "flask_secret_auto_generated_dev_only"
        )

    app.secret_key = flask_secret

    # ==========================================================
    # REQUEST LIMITS
    # ==========================================================

    app.config["MAX_CONTENT_LENGTH"] = int(
        os.environ.get(
            "AGENTGUARD_MAX_BODY_BYTES",
            "262144",
        )
    )

    # ==========================================================
    # CORS
    # ==========================================================

    cors_origins = [
        origin.strip()
        for origin in os.environ.get(
            "AGENTGUARD_CORS_ORIGINS",
            "",
        ).split(",")
        if origin.strip()
    ]

    if is_production:
        if not cors_origins:
            raise RuntimeError(
                "AGENTGUARD_CORS_ORIGINS must be configured "
                "in production. Example: "
                "AGENTGUARD_CORS_ORIGINS="
                "https://dashboard.example.com"
            )

        CORS(
            app,
            origins=cors_origins,
            supports_credentials=True,
        )

        logger.info(
            "cors_strict_mode",
            origins=cors_origins,
        )

    else:
        CORS(
            app,
            origins=cors_origins or "*",
            supports_credentials=True,
        )

    # ==========================================================
    # RATE LIMITING
    # ==========================================================

    limiter_storage = os.environ.get(
        "AGENTGUARD_LIMITER_STORAGE",
        "memory://",
    )

    web_concurrency = int(
        os.environ.get(
            "WEB_CONCURRENCY",
            "1",
        )
    )

    if is_production:

        if (
            limiter_storage == "memory://"
            and web_concurrency > 1
        ):
            raise RuntimeError(
                "AGENTGUARD_LIMITER_STORAGE must be "
                "'redis://...' in production when "
                f"WEB_CONCURRENCY={web_concurrency} > 1. "
                "memory:// allows rate-limit bypass via "
                "replica hopping."
            )

        if limiter_storage == "memory://":
            logger.warning(
                "rate_limiter_memory_single_worker",
                note=(
                    "Safe with WEB_CONCURRENCY=1, but switch "
                    "to Redis for multi-replica deployments"
                ),
                web_concurrency=web_concurrency,
            )

        else:
            logger.info(
                "rate_limiter_redis_mode",
                storage=limiter_storage,
            )

    else:
        logger.info(
            "rate_limiter_mode",
            storage=limiter_storage,
        )

    app.config["RATELIMIT_DEFAULT"] = os.environ.get(
        "AGENTGUARD_RATE_LIMIT",
        "120 per minute",
    )

    app.config["RATELIMIT_STORAGE_URI"] = limiter_storage

    limiter.init_app(app)

    # Compatibility with existing code.
    app.limiter = limiter

    # ==========================================================
    # AUTHENTICATION SERIALIZERS
    # ==========================================================

    app.auth_serializer = URLSafeTimedSerializer(
        app.secret_key,
        salt="agentguard-auth-v1",
    )

    app.auth_session_ttl = int(
        os.environ.get(
            "AGENTGUARD_AUTH_SESSION_TTL",
            "900",
        )
    )

    app.auth_cookie_secure = (
        os.environ.get(
            "AGENTGUARD_COOKIE_SECURE",
            "true",
        ).lower()
        == "true"
    )

    # ==========================================================
    # HUMAN AUTHENTICATION
    # ==========================================================

    app.config["MAGIC_LINK_ENABLED"] = (
        os.environ.get(
            "AGENTGUARD_MAGIC_LINK_ENABLED",
            "true",
        ).lower()
        == "true"
    )

    app.config["MAGIC_LINK_TTL"] = int(
        os.environ.get(
            "AGENTGUARD_MAGIC_LINK_TTL",
            "600",
        )
    )

    app.config["HUMAN_SESSION_TTL"] = int(
        os.environ.get(
            "AGENTGUARD_HUMAN_SESSION_TTL",
            "28800",
        )
    )

    app.config["APP_URL"] = (
        os.environ.get(
            "AGENTGUARD_APP_URL",
            "",
        )
        .strip()
        .rstrip("/")
    )

    app.config["EMAIL_FROM"] = (
        os.environ.get(
            "AGENTGUARD_EMAIL_FROM",
            "",
        )
        .strip()
    )

    app.config["SMTP_HOST"] = (
        os.environ.get(
            "AGENTGUARD_SMTP_HOST",
            "",
        )
        .strip()
    )

    app.config["SMTP_PORT"] = int(
        os.environ.get(
            "AGENTGUARD_SMTP_PORT",
            "587",
        )
    )

    app.config["SMTP_USERNAME"] = (
        os.environ.get(
            "AGENTGUARD_SMTP_USERNAME",
            "",
        )
        .strip()
    )

    app.config["SMTP_PASSWORD"] = os.environ.get(
        "AGENTGUARD_SMTP_PASSWORD",
        "",
    )

    app.config["SMTP_USE_TLS"] = (
        os.environ.get(
            "AGENTGUARD_SMTP_USE_TLS",
            "true",
        ).lower()
        == "true"
    )

    app.config["HUMAN_AUTH_COOKIE"] = (
        "cerbere_session"
    )

    # ==========================================================
    # DATABASE
    # ==========================================================

    app.config["DB_TYPE"] = os.environ.get(
        "AGENTGUARD_DB_TYPE",
        "sqlite",
    )

    app.config["DATABASE_URL"] = os.environ.get(
        "DATABASE_URL",
        "",
    )

    # ==========================================================
    # MACHINE AUTHENTICATION
    # ==========================================================

    app.config["API_KEY"] = os.environ.get(
        "AGENTGUARD_API_KEY",
        None,
    )

    app.config["ADMIN_SECRET"] = os.environ.get(
        "AGENTGUARD_ADMIN_SECRET"
    )

    # Legacy API-key dashboard cookie.
    app.config["AUTH_COOKIE"] = "ag_auth"

    app.config["SPAN_RATE_LIMIT"] = os.environ.get(
        "AGENTGUARD_SPAN_RATE_LIMIT",
        "30 per minute",
    )

    # ==========================================================
    # PRODUCTION FAIL-CLOSED
    # ==========================================================

    if is_production:

        if not app.config["API_KEY"]:
            raise RuntimeError(
                "AGENTGUARD_API_KEY must be configured "
                "in production. Refusing to start without it."
            )

        if not app.config["ADMIN_SECRET"]:
            raise RuntimeError(
                "AGENTGUARD_ADMIN_SECRET must be configured "
                "in production. Admin endpoints require this "
                "secret. Refusing to start."
            )

    # ==========================================================
    # DEVELOPMENT API KEY
    # ==========================================================

    if not app.config["API_KEY"]:

        if (
            app.config["ENVIRONMENT"].lower()
            == "development"
        ):
            app.config["API_KEY"] = (
                "ag-" + secrets.token_urlsafe(32)
            )

            app.config["_API_KEY_WAS_GENERATED"] = True

            logger.warning(
                "api_key_generated_in_memory_dev_only"
            )

        else:
            raise RuntimeError(
                "AGENTGUARD_API_KEY required in "
                "non-development environments"
            )

    else:
        app.config["_API_KEY_WAS_GENERATED"] = False

    if (
        app.config["_API_KEY_WAS_GENERATED"]
        and app.config["DB_TYPE"] == "postgres"
    ):
        logger.warning(
            "api_key_generated_but_postgres_active",
            note=(
                "Configure AGENTGUARD_API_KEY in env "
                "to persist across restarts"
            ),
        )

    # ==========================================================
    # BLUEPRINTS
    # ==========================================================

    _register_blueprints(app)

    # ==========================================================
    # GLOBAL ERROR HANDLER
    # ==========================================================

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        from werkzeug.exceptions import HTTPException

        if isinstance(error, HTTPException):
            return error

        logger.exception(
            "unhandled_application_error",
            error_type=type(error).__name__,
        )

        return jsonify(
            {
                "error": "Internal server error",
            }
        ), 500

    # ==========================================================
    # FINAL LOG
    # ==========================================================

    logger.info(
        "app_created",
        environment=app.config.get(
            "ENVIRONMENT",
            "development",
        ),
        db_type=app.config.get(
            "DB_TYPE",
            "sqlite",
        ),
        legacy_key_allowed=app.config.get(
            "ALLOW_LEGACY_SYSTEM_KEY",
            False,
        ),
        magic_link_enabled=app.config.get(
            "MAGIC_LINK_ENABLED",
            True,
        ),
        rate_limiter=(
            limiter_storage.split("://")[0]
            if "://" in limiter_storage
            else limiter_storage
        ),
        cors_origins=cors_origins or ["*"],
        static_folder=static_folder,
    )

    return app


# ==============================================================
# BLUEPRINT REGISTRATION
# ==============================================================

def _register_blueprints(app: Flask):
    """Register all application blueprints."""

    from collector.auth import auth_bp
    from collector.api import api_bp
    from collector.admin import admin_bp
    from collector.audit_routes import audit_bp
    from collector.trace_view import trace_bp
    from collector.identity_routes import identity_bp
    from collector.legal import legal_bp
    from collector.billing import billing_bp
    from collector.docs import docs_bp
    from collector.devtools import devtools_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    # ==========================================================
    # SECURITY P0:
    #
    # DO NOT register the legacy mcp_bp here.
    #
    # The previous /mcp/* implementation had its own execution
    # path and could bypass the main authentication/policy/
    # ToolGuard/audit pipeline.
    #
    # MCP must be reintroduced only through the same security
    # enforcement path as every other tool execution.
    # ==========================================================

    app.register_blueprint(admin_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(trace_bp)
    app.register_blueprint(identity_bp)
    app.register_blueprint(legal_bp)
    app.register_blueprint(billing_bp)
    app.register_blueprint(docs_bp)
    app.register_blueprint(devtools_bp)

    # ==========================================================
    # HEALTH
    # ==========================================================

    @app.route("/health", methods=["GET"])
    def health_check():
        """
        Full health check for load balancers and production
        monitoring.

        Does not require authentication so infrastructure can
        check service availability.
        """

        checks = {}
        is_healthy = True

        # ------------------------------------------------------
        # DATABASE
        # ------------------------------------------------------

        try:
            start = time.time()

            db = get_db()
            cursor = db.cursor()

            cursor.execute("SELECT 1")
            cursor.fetchone()

            latency_ms = round(
                (time.time() - start) * 1000,
                2,
            )

            checks["database"] = {
                "status": "ok",
                "latency_ms": latency_ms,
            }

        except Exception:
            logger.exception(
                "health_database_check_failed"
            )

            checks["database"] = {
                "status": "error",
            }

            is_healthy = False

        # ------------------------------------------------------
        # RESPONSE
        # ------------------------------------------------------

        status_code = (
            200
            if is_healthy
            else 503
        )

        return jsonify(
            {
                "status": (
                    "healthy"
                    if is_healthy
                    else "unhealthy"
                ),
                "timestamp": datetime.utcnow().isoformat(),
                "version": os.environ.get(
                    "AGENTGUARD_VERSION",
                    "unknown",
                ),
                "checks": checks,
            }
        ), status_code

    # ==========================================================
    # READINESS
    # ==========================================================

    @app.route("/readiness", methods=["GET"])
    def readiness_check():
        """
        Lightweight readiness check.

        This intentionally does not perform a database query.
        Use /health when dependency health must be verified.
        """

        return jsonify(
            {
                "ready": True,
                "timestamp": datetime.utcnow().isoformat(),
            }
        ), 200


# ==============================================================
# DATABASE INITIALIZATION
# ==============================================================

def init_db():
    """Initialize the database at boot."""

    from collector.db import init_db as _init_db

    _init_db()
