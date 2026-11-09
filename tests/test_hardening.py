import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create an isolated Flask app with a temporary SQLite database."""

    db_path = tmp_path / "agentguard_test.db"

    monkeypatch.setenv("AGENTGUARD_FLASK_SECRET", "test-secret")
    monkeypatch.setenv(
        "AGENTGUARD_CORS_ORIGINS",
        "http://localhost:3000",
    )
    monkeypatch.setenv("AGENTGUARD_DB_TYPE", "sqlite")
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENTGUARD_API_KEY", "test-api-key")

    # Import only after configuring the test environment.
    from collector.app import create_app
    from collector.db import init_db

    # Initialize the isolated database.
    init_db()

    application = create_app()
    application.config["TESTING"] = True

    return application


def test_healthz(app):
    """Health endpoint must respond with an accepted status."""

    with app.test_client() as client:
        response = client.get("/healthz")

        assert response.status_code in (200, 503)


def test_query_key_is_not_auth(app):
    """API keys passed through query parameters must not authenticate."""

    with app.test_client() as client:
        response = client.get("/api/metrics?key=test-api-key")

        assert response.status_code == 401


def test_sdk_decorator_api():
    """SDK decorator must execute the wrapped function correctly."""

    from agentguard.sdk import AgentGuard

    guard = AgentGuard(
        collector_url="http://127.0.0.1:9",
        debug=False,
    )

    @guard.guard_tool_call("echo")
    def echo(message):
        return message

    assert echo(message="ok") == "ok"