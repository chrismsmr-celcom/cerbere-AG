import re

import pytest

from collector.app import create_app
from collector.auth.config import PUBLIC_ENDPOINTS


@pytest.fixture(scope="module")
def app():
    return create_app()


def _routes(app):
    for rule in app.url_map.iter_rules():
        methods = sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS"))
        if methods:
            yield rule, methods[0]


def test_public_list_has_no_typos(app):
    existing = {r.endpoint for r in app.url_map.iter_rules()}
    assert PUBLIC_ENDPOINTS <= existing, f"endpoints inconnus : {PUBLIC_ENDPOINTS - existing}"


def test_every_non_public_route_rejects_anonymous(app):
    client = app.test_client()
    leaks = []
    for rule, method in _routes(app):
        if rule.endpoint in PUBLIC_ENDPOINTS:
            continue
        url = re.sub(r"<[^>]+>", "x", rule.rule)
        status = client.open(url, method=method).status_code
        if status not in (401, 302):
            leaks.append((rule.endpoint, method, url, status))
    assert not leaks, f"routes accessibles sans authentification : {leaks}"


def test_admin_routes_reject_without_secret(app):
    client = app.test_client()
    for rule, method in _routes(app):
        if not rule.endpoint.startswith("admin."):
            continue
        url = re.sub(r"<[^>]+>", "x", rule.rule)
        assert client.open(url, method=method).status_code not in (200, 201), rule.endpoint