"""Keep the MCP Registry manifest aligned with the published MCP package."""

import json
import tomllib
from pathlib import Path


def test_mcp_registry_manifest_matches_package_metadata():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "mcp" / "server.json").read_text(encoding="utf-8"))
    package = tomllib.loads(
        (root / "mcp" / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]

    assert manifest["version"] == package["version"]
    assert len(manifest["packages"]) == 1
    published_package = manifest["packages"][0]
    assert published_package["registryType"] == "pypi"
    assert published_package["identifier"] == package["name"]
    assert published_package["version"] == package["version"]
    assert published_package["transport"]["type"] == "stdio"
    assert published_package["runtimeHint"] == "uvx"
    assert "cerbere-ag-mcp" in package["scripts"]
