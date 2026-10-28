"""Chargement et validation de la configuration de la gateway.

Format JSON (ou YAML si PyYAML est installé) :

{
  "agent_id": "gateway-default",
  "collector_url": "http://localhost:8080",
  "budget": 5.0,
  "transport": "stdio" | "http",
  "http": {
    "host": "127.0.0.1",
    "port": 8081,
    "path": "/mcp",
    "api_keys": {
      "ag-alice": {"agent_id": "alice-agent", "budget": 3.0},
      "ag-bob":   {"agent_id": "bob-agent", "allowed_servers": ["github"]}
    }
  },
  "response_inspection": {"redact_pii": true, "redact_secrets": true},
  "servers": [
    {
      "label": "fs",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "allowed_tools": ["read_file", "list_directory"],
      "budget": 2.0,
      "external": false
    },
    {
      "label": "web",
      "command": ["npx", "-y", "@modelcontextprotocol/server-fetch"],
      "allowed_tools": ["*"],
      "external": true
    }
  ]
}

Fail-closed : une config sans serveur, sans allowlist par serveur, ou
sans api_keys en mode http, est rejetée au démarrage.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


class ConfigError(Exception):
    """Erreur de configuration : la gateway refuse de démarrer."""


@dataclass
class ServerSpec:
    label: str
    command: list[str]
    allowed_tools: list[str]  # ["*"] autorise tout, choix explicite
    budget: float | None = None
    external: bool = False  # si true : taint tracking bloque tout secret en entrée

    @property
    def allow_all(self) -> bool:
        return "*" in self.allowed_tools

    def allows(self, tool: str) -> bool:
        return self.allow_all or tool in self.allowed_tools


@dataclass
class GatewayConfig:
    agent_id: str
    collector_url: str
    budget: float
    transport: str
    host: str
    port: int
    path: str
    api_keys: dict[str, dict[str, Any]] = field(default_factory=dict)
    redact_pii: bool = True
    redact_secrets: bool = True
    servers: list[ServerSpec] = field(default_factory=list)
    workers: int = 4

    def server(self, label: str) -> ServerSpec:
        for s in self.servers:
            if s.label == label:
                return s
        raise ConfigError(f"Unknown upstream label: {label}")

    def key_identity(self, api_key: str | None) -> dict[str, Any]:
        """Résout l'identité d'une clé API. En stdio (pas de clé), identité par défaut."""
        if not api_key:
            return {"agent_id": self.agent_id, "budget": self.budget, "allowed_servers": None}
        ident = self.api_keys.get(api_key)
        if ident is None:
            raise ConfigError("Unknown API key")
        return {
            "agent_id": ident.get("agent_id", self.agent_id),
            "budget": float(ident.get("budget", self.budget)),
            "allowed_servers": ident.get("allowed_servers"),
        }


def _load_raw(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yml", ".yaml")):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ConfigError("PyYAML required for YAML configs: pip install pyyaml") from exc
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ConfigError("Config root must be an object")
    return data


def load_config(path: str | None = None) -> GatewayConfig:
    path = path or os.environ.get("CERBERE_GATEWAY_CONFIG", "gateway.json")

    if os.environ.get("CERBERE_GATEWAY_CONFIG_JSON"):
        raw = json.loads(os.environ["CERBERE_GATEWAY_CONFIG_JSON"])
    else:
        if not os.path.exists(path):
            raise ConfigError(
                f"Config file not found: {path}\n"
                "Set CERBERE_GATEWAY_CONFIG or pass --config."
            )
        raw = _load_raw(path)

    # --- serveurs amonts -------------------------------------------------
    servers: list[ServerSpec] = []
    for entry in raw.get("servers", []):
        label = entry.get("label")
        command = entry.get("command")
        allowed = entry.get("allowed_tools")
        if not label or not isinstance(label, str):
            raise ConfigError("Each server needs a 'label'")
        if not command or not isinstance(command, list) or not command:
            raise ConfigError(f"Server '{label}': 'command' must be a non-empty list")
        if any(s.label == label for s in servers):
            raise ConfigError(f"Duplicate server label: {label}")
        if not allowed or not isinstance(allowed, list) or not any(allowed):
            raise ConfigError(
                f"Server '{label}': 'allowed_tools' is required (fail-closed). "
                "Use [\"*\"] to explicitly allow all tools."
            )
        if "*" in allowed and len(allowed) > 1:
            raise ConfigError(f"Server '{label}': '*' must be alone in allowed_tools")
        servers.append(
            ServerSpec(
                label=label,
                command=[str(c) for c in command],
                allowed_tools=[str(t) for t in allowed],
                budget=float(entry["budget"]) if entry.get("budget") is not None else None,
                external=bool(entry.get("external", False)),
            )
        )

    if not servers:
        raise ConfigError("No upstream servers defined: nothing to guard")

    # --- transport --------------------------------------------------------
    transport = raw.get("transport", "stdio")
    if transport not in ("stdio", "http"):
        raise ConfigError(f"Unknown transport: {transport}")

    http_cfg = raw.get("http", {}) or {}
    api_keys = {str(k): v for k, v in (http_cfg.get("api_keys") or {}).items()}
    if transport == "http" and not api_keys:
        raise ConfigError(
            "HTTP transport requires 'http.api_keys' "
            "(each key maps to an agent identity, its budget and optional allowed_servers)."
        )

    inspection = raw.get("response_inspection", {}) or {}

    return GatewayConfig(
        agent_id=str(raw.get("agent_id", "cerbere_gateway")),
        collector_url=str(raw.get("collector_url", os.environ.get("AGENTGUARD_COLLECTOR_URL", "http://localhost:8080"))),
        budget=float(raw.get("budget", 5.0)),
        transport=transport,
        host=str(http_cfg.get("host", "127.0.0.1")),
        port=int(http_cfg.get("port", 8081)),
        path=str(http_cfg.get("path", "/mcp")),
        api_keys=api_keys,
        redact_pii=bool(inspection.get("redact_pii", True)),
        redact_secrets=bool(inspection.get("redact_secrets", True)),
        servers=servers,
        workers=int(raw.get("workers", 4)),
    )
