"""Keep the MCP Registry manifest aligned with the published MCP package."""

import json
from pathlib import Path


def test_mcp_registry_manifest_matches_package_metadata():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "mcp" / "server.json").read_text(encoding="utf-8"))
    package_pyproject = (root / "mcp" / "pyproject.toml").read_text(encoding="utf-8")
    package = manifest["packages"][0]

    assert len(manifest["packages"]) == 1
    assert package["registryType"] == "pypi"
    assert package["identifier"] == "cerbere-ag-mcp"
    assert package["version"] == manifest["version"]
    assert package["transport"]["type"] == "stdio"
    assert package["runtimeHint"] == "uvx"
    assert f'name = "{package["identifier"]}"' in package_pyproject
    assert f'version = "{manifest["version"]}"' in package_pyproject
    assert 'cerbere-ag-mcp = "mcp_server:main"' in package_pyproject
