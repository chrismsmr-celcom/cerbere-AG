"""Tests unitaires de la gateway Cerbere (sans serveur MCP réel).

Couverture :
  - validation de la config (fail-closed)
  - redaction des réponses
  - taint registry : exfiltration bloquée même encodée (base64/hex/URL)

Run from the repo root:
    pip install -e "mcp[dev]"
    pytest tests/test_gateway_core.py -q
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp"))

from gateway_config import ConfigError, load_config  # noqa: E402
from gateway_inspection import ResponseInspector, TaintRegistry  # noqa: E402

# ---------------------------------------------------------------- config

MINIMAL = {
    "transport": "stdio",
    "servers": [
        {
            "label": "fs",
            "command": ["npx", "-y", "server-fs", "/tmp"],
            "allowed_tools": ["read_file"],
        }
    ],
}


def _load(raw: dict):
    import os

    os.environ["CERBERE_GATEWAY_CONFIG_JSON"] = json.dumps(raw)
    try:
        return load_config(None)
    finally:
        del os.environ["CERBERE_GATEWAY_CONFIG_JSON"]


def test_minimal_config_loads():
    cfg = _load(MINIMAL)
    assert cfg.transport == "stdio"
    assert len(cfg.servers) == 1
    assert cfg.servers[0].allows("read_file")
    assert not cfg.servers[0].allows("delete_file")


def test_no_servers_fails_closed():
    with pytest.raises(ConfigError):
        _load({"transport": "stdio", "servers": []})


def test_no_allowed_tools_fails_closed():
    raw = json.loads(json.dumps(MINIMAL))
    del raw["servers"][0]["allowed_tools"]
    with pytest.raises(ConfigError):
        _load(raw)


def test_http_requires_api_keys():
    raw = json.loads(json.dumps(MINIMAL))
    raw["transport"] = "http"
    with pytest.raises(ConfigError):
        _load(raw)


def test_key_identity():
    cfg = _load(
        {
            "transport": "http",
            "http": {
                "api_keys": {
                    "ag-key": {
                        "agent_id": "a",
                        "budget": 1.5,
                        "allowed_servers": ["web"],
                    }
                }
            },
            "servers": [
                {
                    "label": "web",
                    "command": ["x"],
                    "allowed_tools": ["*"],
                    "external": True,
                }
            ],
        }
    )
    ident = cfg.key_identity("ag-key")
    assert ident["agent_id"] == "a"
    assert ident["budget"] == 1.5
    assert ident["allowed_servers"] == ["web"]
    with pytest.raises(ConfigError):
        cfg.key_identity("ag-unknown")
    default = cfg.key_identity(None)
    assert default["allowed_servers"] is None


# ----------------------------------------------------------- inspection


def test_redaction_masks_pii_and_registers_taints():
    insp = ResponseInspector(redact_pii=True, redact_secrets=True)
    out, findings = insp.inspect_text(
        "contact me at john.doe@example.com or key sk-abcdefghijklmnop1234567890"
    )
    assert "john.doe@example.com" not in out
    assert "[REDACTED_EMAIL]" in out
    assert "API_KEY" in findings
    assert insp.taints.find_in_arguments({"body": "sk-abcdefghijklmnop1234567890"})


def test_taint_registry_blocks_base64_hex_and_url():
    reg = TaintRegistry()
    secret = "ag-supersecretkey1234567890"
    reg.register(secret)

    import base64
    import binascii
    import urllib.parse

    assert reg.find_in_arguments({"body": secret}) is not None
    assert (
        reg.find_in_arguments({"body": base64.b64encode(secret.encode()).decode()})
        is not None
    )
    assert (
        reg.find_in_arguments({"body": binascii.hexlify(secret.encode()).decode()})
        is not None
    )
    assert (
        reg.find_in_arguments({"url": urllib.parse.quote(secret, safe="")}) is not None
    )
    assert reg.find_in_arguments({"body": "totally harmless"}) is None


def test_short_values_not_tainted():
    reg = TaintRegistry()
    reg.register("short")
    assert reg.find_in_arguments({"body": "short"}) is None
