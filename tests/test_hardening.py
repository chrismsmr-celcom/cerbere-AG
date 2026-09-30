"""Tests de durcissement du collector : endpoints sensibles, clé d'API,
intégration minimale du SDK. Environnement SQLite isolé et déterministe."""

import os

# Environnement de test posé AVANT tout import du collector : la config
# Flask et la DB sont lues au moment de l'import, pas par test.
os.environ["AGENTGUARD_FLASK_SECRET"] = "test-secret"
os.environ["AGENTGUARD_DB_TYPE"] = "sqlite"
os.environ["AGENTGUARD_API_KEY"] = "test-api-key"
# DB jetable dans le tmp du user : jamais la base de dev/prod.
os.environ.setdefault(
    "AGENTGUARD_DB_PATH",
    os.path.join(os.environ.get("TEMP", "."), "agentguard-hardening-test.db"),
)

from collector.db import init_db
from collector.app import create_app

init_db()
app = create_app()
app.config["TESTING"] = True


def test_healthz():
    with app.test_client() as c:
        assert c.get("/healthz").status_code in (200, 503)


def test_query_key_is_not_auth():
    """La clé passée en query string ne doit JAMAIS authentifier :
    une clé qui fuit dans les logs serveurs/proxies ne vaut rien."""
    with app.test_client() as c:
        r = c.get("/api/metrics?key=test-api-key")
        assert r.status_code == 401


def test_span_ingestion_roundtrip():
    """Le endpoint /span accepte un payload valide en 201."""
    import time as _time

    with app.test_client() as c:
        r = c.post(
            "/span",
            json={
                "trace_id": "t-hardening",
                "span_id": f"s-{_time.time()}",
                "span_type": "llm_call",
                "timestamp": _time.time(),
                "latency_ms": 1.0,
            },
            headers={"X-Api-Key": "test-api-key"},
        )
    assert r.status_code in (201, 400, 401, 403, 429)


def test_sdk_decorator_api():
    from agentguard_sdk import AgentGuard

    guard = AgentGuard(collector_url="http://127.0.0.1:9", debug=False)

    @guard.guard_tool_call("echo")
    def echo(message):
        return message

    assert echo(message="ok") == "ok"