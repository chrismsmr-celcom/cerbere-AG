# 🐕‍🦺 CerbereAG MCP Server & Gateway

**Runtime security for AI agents — as an MCP server, and as a universal gateway.**

Two components ship in this package:

1. **`cerbere-ag-mcp`** — an advisory security MCP server: any MCP-compatible
   agent (Claude, Cursor, Cline, custom agents on the Anthropic API) can call
   `check_prompt_security` or `authorize_tool_call` like any other tool.
2. **`cerbere-ag-gateway`** — a universal **MCP gateway**: one guarded door
   between your agent and any number of upstream MCP servers, with tool
   allowlists, per-identity budgets, per-server budgets, PII/secret redaction
   and taint-based exfiltration blocking. No agent code changes required.

## 🚀 Quick start — advisory server (30 seconds)

### 1. Install

```bash
pip install cerbere-ag-mcp
```

### 2. Configure your MCP client

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cerbereag": {
      "command": "cerbere-ag-mcp",
      "env": {
        "AGENTGUARD_MCP_COLLECTOR_URL": "https://YOUR_AGENTGUARD_HOST",
        "AGENTGUARD_API_KEY": "ag-your-key",
        "AGENTGUARD_AGENT_ID": "my-agent"
      }
    }
  }
}
```

**Cursor** — add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "cerbereag": {
      "command": "cerbere-ag-mcp",
      "env": {
        "AGENTGUARD_MCP_COLLECTOR_URL": "https://YOUR_AGENTGUARD_HOST",
        "AGENTGUARD_API_KEY": "ag-your-key",
        "AGENTGUARD_AGENT_ID": "my-agent"
      }
    }
  }
}
```

## 🛠️ Advisory tools

| Tool | Purpose |
|---|---|
| `check_prompt_security(text)` | Checks a text for prompt injection patterns or PII leakage before it's sent onward. |
| `authorize_tool_call(tool_name, params_json, agent_id?)` | Checks whether a planned tool call is allowed under the active policy and remaining budget. |
| `redact_pii(text)` | Replaces detected PII (emails, phone numbers, card numbers, SSNs, API keys) with `[REDACTED_TYPE]` placeholders. |
| `get_audit_trail(limit?)` | Fetches the most recent entries from the security audit log on the Collector. |
| `calculate_token_cost(model, text)` | Estimates token count and USD cost for a piece of text against a given model's pricing. |

## 📚 Advisory resource

| Resource | Purpose |
|---|---|
| `cerbereag://policies/summary` | Returns a summary of the currently active tool allowlist and detection settings. |

## ⚙️ Advisory configuration

| Environment variable | Required | Default | Description |
|---|---|---|---|
| `AGENTGUARD_MCP_COLLECTOR_URL` | No | `http://localhost:8080` | URL of your CerbereAG Collector instance. |
| `AGENTGUARD_API_KEY` | Recommended | — | API key used to authenticate against the Collector. |
| `AGENTGUARD_AGENT_ID` | No | `cerbereag_mcp_client` | Identifier used to scope policy and budget checks. |
| `AGENTGUARD_MAX_BUDGET` | No | `10.0` | Max USD spend before `authorize_tool_call` starts blocking on budget. |

---

# 🚪 The universal MCP gateway

## Topologie

```
Agent (local)   --stdio-->  \
                              \
Agent (remote)  --HTTP---->  Cerbere MCP Gateway  ---> Collector (audit)
                              /        | enforcement (AgentGuard)
                              |        v
   (aucun code à changer)     /     Upstream 1 (fs)
                              \\    Upstream N (github, db, web...)
```

- Outils exposés : `<label>__<tool>` (ex. `fs__read_file`) — pas de collision
  entre serveurs, traçabilité lisible dans les spans (`mcp:<label>:<tool>`).
- **Fail-closed** partout : config invalide, amont injoignable, authorization
  indisponible ou budget épuisé ⇒ l'appel est bloqué, jamais forwardé.

## Install

```bash
pip install "cerbere-ag-mcp[gateway-http]"   # transport Streamable HTTP
```

## Configuration (`gateway.json`)

```json
{
  "agent_id": "cerbere_gateway",
  "collector_url": "http://localhost:8080",
  "budget": 5.0,
  "transport": "http",
  "http": {
    "host": "127.0.0.1",
    "port": 8081,
    "path": "/mcp",
    "api_keys": {
      "ag-alice-key": { "agent_id": "alice-agent", "budget": 3.0 },
      "ag-bob-key": { "agent_id": "bob-agent", "budget": 1.0, "allowed_servers": ["web"] }
    }
  },
  "response_inspection": { "redact_pii": true, "redact_secrets": true },
  "servers": [
    {
      "label": "fs",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "allowed_tools": ["read_file", "list_directory", "write_file"],
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
```

Règles de validation (fail-closed au démarrage) :

- chaque serveur doit avoir un `label` unique, une `command` non vide et une
  `allowed_tools` explicite (`["*"]` seul autorise tout) ;
- `transport: "http"` exige `http.api_keys` (chaque clé = une identité) ;
- aucun serveur défini ⇒ la gateway refuse de démarrer.

## Lancer la gateway

```bash
# stdio (agent local)
cerbere-ag-gateway --config gateway.json

# HTTP (agents distants, auth par clé API)
cerbere-ag-gateway --config gateway.json   # transport lu dans la config

# Config inline (CI, tests)
CERBERE_GATEWAY_CONFIG_JSON='{"transport":"stdio", ...}' cerbere-ag-gateway
```

## Sécurité appliquée automatiquement

| Mécanisme | Effet |
|---|---|
| **Allowlist par serveur** | Un outil absent de `allowed_tools` est refusé avant tout forward. |
| **Enforcement AgentGuard** | Chaque appel est évalué (injection, policy, budget identité) avant exécution ; indisponible ⇒ DENY. |
| **Budget par serveur** | `budget` facultatif par serveur : plafond USD heuristique (arguments + réponse, ≈ 4 chars/token) par identité. |
| **Redaction réponse** | PII et secrets dans les résultats amonts sont remplacés par `[REDACTED_TYPE]` avant retour à l'agent. |
| **Taint tracking** | Toute valeur sensible vue en interne (API key, carte, SSN) est mémorisée ; si elle réapparaît — même en base64, hex ou URL-encodé — dans un appel vers un serveur `external: true`, l'appel est bloqué. |
| **Auth HTTP** | Clé API via `x-api-key` ou `Authorization: Bearer` → identité, budget et `allowed_servers` dédiés. |

## 🔗 Related

* Core SDK (decorator-based integration for Python agents): [`cerbere-ag`](https://pypi.org/project/cerbere-ag/)
* Dashboard, policy docs, other framework integrations (LangGraph, CrewAI, Composio, HTTP gateway): [app.cerbereag.site](https://app.cerbereag.site)
* Source: [github.com/chrismsmr-celcom/agentguard](https://github.com/chrismsmr-celcom/agentguard)
