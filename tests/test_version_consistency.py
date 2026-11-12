"""Une seule version, partout : pyproject.toml, SDK et endpoint /health."""

import re
from pathlib import Path

from agentguard._version import __version__

ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_version_matches_package():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "version introuvable dans pyproject.toml"
    assert m.group(1) == __version__


def test_sdk_version_is_single_sourced():
    from agentguard.sdk import SDK_VERSION

    assert SDK_VERSION == __version__


def test_changelog_mentions_current_version():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"[{__version__}]" in changelog


def test_mcp_package_license_matches_readme():
    text = (ROOT / "mcp" / "pyproject.toml").read_text(encoding="utf-8")
    assert 'license = "Apache-2.0"' in text
