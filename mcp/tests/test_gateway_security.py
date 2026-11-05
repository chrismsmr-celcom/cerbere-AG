"""Focused security tests for the HTTP gateway boundary.

Run from the repository root with:
    PYTHONPATH=mcp pytest -q mcp/tests/test_gateway_security.py
"""
import asyncio

import pytest
from gateway_config import GatewayConfig
from gateway_server import (
    APIKeyAuthMiddleware,
    current_api_key,
    current_identity,
)


def make_config():
    return GatewayConfig(
        agent_id="default",
        collector_url="http://127.0.0.1:9",
        budget=1.0,
        transport="http",
        host="127.0.0.1",
        port=8081,
        path="/mcp",
        api_keys={
            "test-key": {
                "agent_id": "auditor",
                "budget": 0.5,
                "allowed_servers": ["synthetic"],
            }
        },
    )


async def invoke(middleware, headers=()):
    seen = {}

    async def app(scope, receive, send):
        seen["api_key"] = current_api_key.get()
        seen["identity"] = current_identity.get()
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    messages = []
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    wrapped = APIKeyAuthMiddleware(app, make_config())
    scope = {"type": "http", "method": "POST", "path": "/mcp",
             "headers": list(headers)}
    await wrapped(scope, receive, send)
    return seen, messages


@pytest.mark.parametrize("headers", [(), ((b"x-api-key", b"wrong"),)])
def test_missing_or_invalid_key_is_rejected(headers):
    seen, messages = asyncio.run(invoke(None, headers))
    assert messages[0]["status"] == 401
    assert seen == {}


def test_x_api_key_sets_identity_and_resets_context_after_request():
    seen, messages = asyncio.run(invoke(
        None, ((b"x-api-key", b"test-key"),)
    ))
    assert messages[0]["status"] == 204
    assert seen["api_key"] == "test-key"
    assert seen["identity"]["agent_id"] == "auditor"
    assert current_api_key.get() is None
    assert current_identity.get() is None


def test_bearer_auth_sets_identity():
    seen, messages = asyncio.run(invoke(
        None, ((b"authorization", b"Bearer test-key"),)
    ))
    assert messages[0]["status"] == 204
    assert seen["api_key"] == "test-key"
    assert seen["identity"]["allowed_servers"] == ["synthetic"]


def test_non_http_scope_passes_without_identity():
    called = []
    async def app(scope, receive, send):
        called.append(scope["type"])
    middleware = APIKeyAuthMiddleware(app, make_config())
    asyncio.run(middleware({"type": "lifespan"}, None, None))
    assert called == ["lifespan"]
