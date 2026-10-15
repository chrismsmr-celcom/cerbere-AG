"""Nouveau dashboard (SPA Vite servie par Flask en same-origin) + ancien dashboard sur /legacy."""

import re
from pathlib import Path

import pytest

from collector.app import create_app

_APP_DIR = Path(__file__).resolve().parents[1] / "collector" / "static" / "app"
_BUILT = (_APP_DIR / "index.html").is_file()


@pytest.fixture(scope="module")
def app():
    return create_app()


def test_dashboard_and_legacy_stay_behind_login(app):
    client = app.test_client()
    for url in ("/", "/legacy"):
        resp = client.get(url)
        assert resp.status_code in (302, 401), url
        if resp.status_code == 302:
            assert "/login" in resp.headers["Location"]


@pytest.mark.skipif(
    not _BUILT, reason="build du dashboard absent (cd dashboard && npm run build)"
)
def test_root_serves_spa_shell(app):
    from collector.auth.routes_session import dashboard

    with app.test_request_context("/"):
        resp = dashboard()
    html = resp.get_data(as_text=True)
    assert 'id="root"' in html
    assert "/static/app/assets/" in html
    assert resp.headers["Cache-Control"] == "no-cache"


@pytest.mark.skipif(not _BUILT, reason="build du dashboard absent")
def test_classic_flag_serves_legacy_dashboard(app):
    from collector.auth.routes_session import dashboard

    with app.test_request_context("/?classic=1"):
        resp = dashboard()
    html = resp.get_data(as_text=True)
    assert 'id="root"' not in html or "dashboard" in html.lower()
    assert "/static/app/assets/index-" not in html


@pytest.mark.skipif(not _BUILT, reason="build du dashboard absent")
def test_built_assets_exist_and_are_public(app):
    html = (_APP_DIR / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="(/static/app/assets/[^"]+)"', html)
    assert refs, "index.html ne référence aucun asset"
    client = app.test_client()
    for ref in refs:
        assert (_APP_DIR / ref.removeprefix("/static/app/")).is_file(), ref
        assert client.get(ref).status_code == 200, ref


def test_legal_pages_linked_from_the_dashboard_are_public(app):
    """Le pied de la barre latérale pointe vers /legal ; ces pages doivent répondre sans connexion."""
    client = app.test_client()
    for url in ("/legal", "/terms", "/privacy"):
        resp = client.get(url)
        assert resp.status_code == 200, url
