"""Open core : le cœur (Apache-2.0) fonctionne sans ee/ et n'en dépend jamais directement."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from collector import ee_loader

ROOT = Path(__file__).resolve().parent.parent


def test_loader_returns_none_when_ee_is_absent(monkeypatch):
    def missing(name):
        raise ModuleNotFoundError(f"No module named {name!r}", name=name.split(".")[0])

    monkeypatch.setattr(ee_loader.importlib, "import_module", missing)
    assert ee_loader.load_enterprise_module("ee.sso.routes") is None
    assert ee_loader.enterprise_available() is False
    assert ee_loader.sso_config() is None


def test_loader_never_hides_a_real_error_inside_ee(monkeypatch):
    def broken(name):
        raise ModuleNotFoundError("No module named 'jwt'", name="jwt")

    monkeypatch.setattr(ee_loader.importlib, "import_module", broken)
    with pytest.raises(ModuleNotFoundError):
        ee_loader.load_enterprise_module("ee.sso.oidc")


@pytest.mark.parametrize(
    "module",
    [
        "ee.sso.oidc",
        "ee.sso.routes",
        "ee.compliance.report",
        "ee.compliance.api",
        "collector.auth",
        "collector.api",
    ],
)
def test_modules_import_cleanly_in_any_order(module):
    """Pas d'import circulaire entre le cœur et ee/, quel que soit le module importé en premier."""
    pytest.importorskip("ee")
    run = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert run.returncode == 0, run.stderr[-800:]


def test_core_code_never_imports_ee_directly():
    """Seuls des chargements par nom (ee_loader) sont autorisés dans le cœur."""
    pattern = re.compile(r"^\s*(from\s+ee[\s.]|import\s+ee[\s.\n])", re.MULTILINE)
    offenders = []
    for folder in ("collector", "agentguard", "mcp"):
        for path in (ROOT / folder).rglob("*.py"):
            if pattern.search(path.read_text(encoding="utf-8", errors="replace")):
                offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_every_enterprise_python_file_states_its_license():
    files = [p for p in (ROOT / "ee").rglob("*.py")]
    assert files
    for path in files:
        head = path.read_text(encoding="utf-8")[:1200]
        assert "ee/LICENSE.md" in head, (
            f"{path.relative_to(ROOT)} must point to ee/LICENSE.md"
        )
    assert (ROOT / "ee" / "LICENSE.md").is_file()


def test_the_pypi_package_never_includes_the_enterprise_directory():
    """Le paquet publié sous Apache-2.0 ne doit jamais embarquer ee/ (ni le collector)."""
    import tomllib

    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    include = config["tool"]["setuptools"]["packages"]["find"]["include"]
    assert include and not any(
        pattern.startswith(("ee", "collector")) for pattern in include
    )


def test_repository_root_license_is_apache():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in text and "Version 2.0" in text


def test_enterprise_routes_are_registered_when_ee_is_present(tmp_path, monkeypatch):
    pytest.importorskip("ee")
    from tests.dbmode import configure_db

    configure_db(monkeypatch, tmp_path, "opencore")
    monkeypatch.setenv("AGENTGUARD_FLASK_SECRET", "test-flask-secret-for-ci-only")
    monkeypatch.delenv("AGENTGUARD_ENVIRONMENT", raising=False)
    from collector.app import create_app
    from collector.db import init_db

    init_db()
    rules = {rule.rule for rule in create_app().url_map.iter_rules()}
    assert {
        "/auth/sso/login",
        "/auth/sso/callback",
        "/api/compliance/report",
        "/api/license",
    } <= rules


SCRIPT = r"""
import json, os, sys
os.environ.update({
    "AGENTGUARD_DB_TYPE": "sqlite", "AGENTGUARD_DB_PATH": os.path.join(os.environ["WORKDIR"], "core.db"),
    "AGENTGUARD_FLASK_SECRET": "x" * 40, "AGENTGUARD_CORS_ORIGINS": "http://localhost:8080",
    "AGENTGUARD_COOKIE_SECURE": "false",
    # même avec une config SSO complète, sans ee/ le bouton ne doit pas apparaître
    "AGENTGUARD_OIDC_ISSUER": "https://idp.example.com", "AGENTGUARD_OIDC_CLIENT_ID": "c",
    "AGENTGUARD_OIDC_CLIENT_SECRET": "s", "AGENTGUARD_OIDC_ALLOWED_DOMAINS": "acme.example",
})
from collector.db import init_db
init_db()
from collector.app import create_app
app = create_app()
app.config["TESTING"] = True
rules = sorted(r.rule for r in app.url_map.iter_rules())
client = app.test_client()
login = client.get("/login")
html = login.data.decode()
import importlib.util
print(json.dumps({
    "ee_importable": importlib.util.find_spec("ee") is not None,
    "has_sso_route": "/auth/sso/login" in rules,
    "has_report_route": "/api/compliance/report" in rules,
    "has_license_route": "/api/license" in rules,
    "login_status": login.status_code,
    "sso_button": "/auth/sso/login" in html,
    "password_form": "/auth/password" in html,
}))
"""


def test_core_boots_and_works_without_the_enterprise_directory(tmp_path):
    work = tmp_path / "core-only"
    shutil.copytree(
        ROOT,
        work,
        ignore=shutil.ignore_patterns(
            "ee",
            ".git",
            "node_modules",
            "tests",
            "docs",
            "dashboard",
            "__pycache__",
            "*.gif",
            "*.mp4",
            "*.png",
            ".ruff_cache",
            ".pytest_cache",
            "garak-env",
        ),
    )
    env = {"PATH": "/usr/bin:/bin", "WORKDIR": str(work), "PYTHONPATH": str(work)}
    import os

    env.update(
        {
            k: v
            for k, v in os.environ.items()
            if k in {"SYSTEMROOT", "HOME", "VIRTUAL_ENV", "LANG"}
        }
    )
    run = subprocess.run(
        [sys.executable, "-c", SCRIPT],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert run.returncode == 0, run.stderr[-1500:]
    result = json.loads(run.stdout.strip().splitlines()[-1])
    assert result == {
        "ee_importable": False,
        "has_sso_route": False,
        "has_report_route": False,
        "has_license_route": True,  # l'API de licence fait partie du cœur
        "login_status": 200,
        "sso_button": False,
        "password_form": True,
    }

    cli = subprocess.run(
        [sys.executable, "-m", "collector.cli", "report", "--period", "2026-10"],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert cli.returncode == 1 and "Enterprise Edition" in cli.stderr
