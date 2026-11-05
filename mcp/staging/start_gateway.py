"""Launch the isolated Render staging gateway from platform environment variables."""
from __future__ import annotations

import json
import os
import sys


def main() -> None:
    api_key = os.environ.get("AGENTGUARD_API_KEY", "").strip()
    collector_hostport = os.environ.get("AGENTGUARD_COLLECTOR_HOSTPORT", "").strip()
    if not api_key:
        raise SystemExit("AGENTGUARD_API_KEY is required")
    if not collector_hostport:
        raise SystemExit("AGENTGUARD_COLLECTOR_HOSTPORT is required")

    config = {
        "agent_id": "cerbere-staging-auditor",
        "collector_url": f"http://{collector_hostport}",
        "budget": 0.25,
        "transport": "http",
        "workers": 1,
        "http": {
            "host": "0.0.0.0",
            "port": int(os.environ.get("PORT", "10000")),
            "path": "/mcp",
            "api_keys": {
                api_key: {
                    "agent_id": "external-auditor",
                    "budget": 0.25,
                    "allowed_servers": ["synthetic"],
                }
            },
        },
        "response_inspection": {
            "redact_pii": True,
            "redact_secrets": True,
        },
        "servers": [
            {
                "label": "synthetic",
                "command": [sys.executable, "mcp/staging_synthetic_upstream.py"],
                "allowed_tools": [
                    "echo",
                    "increment_counter",
                    "get_counter",
                ],
                "external": False,
            }
        ],
    }
    os.environ["CERBERE_GATEWAY_CONFIG_JSON"] = json.dumps(config)
    from gateway_server import main as gateway_main
    gateway_main()


if __name__ == "__main__":
    main()
