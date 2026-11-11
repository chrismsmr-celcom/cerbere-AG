# Quickstart

Get Cerbère AG running in a few minutes. Pick the path that fits what you want to do:

| I want to... | Go to | Time |
|---|---|---|
| See Cerbère block an attack, with nothing to install but Python | [1. Offline demo](#1-offline-demo) | ~2 min |
| Protect my own agent's tool calls | [2. Add the SDK to your agent](#2-add-the-sdk-to-your-agent) | ~5 min |
| Run my own collector and dashboard | [3. Self-host the collector](#3-self-host-the-collector-and-dashboard) | ~5 min |
| Use it from Claude, Cursor or another MCP client | [4. MCP server](#4-mcp-server) | ~2 min |

Requirements: Python 3.10+. Docker 24+ with the Compose plugin is only needed for path 3.

---

## 1. Offline demo

No collector, no API key, no network. The demo shows an agent reading a `.env` file, then a prompt injection trying to send its content to an external server.

```bash
git clone https://github.com/chrismsmr-celcom/cerbere-AG.git
cd cerbere-AG
pip install -e .
python examples/taint_demo.py
```

Expected output:

```
[1] The agent reads .env                         ✓ allowed (internal tool)
[2] The agent posts a harmless report            ✓ 200 OK
[3] A prompt injection tries to exfiltrate .env  ✗ BLOCKED: sensitive taint reaches high-impact sink
[4] Same attempt, secret base64-encoded          ✗ BLOCKED: sensitive taint reaches high-impact sink
```

Cerbère follows the **data**, not only the prompt. The secret read in step 1 is remembered in memory, so it is caught even when it is re-encoded in step 4. Details in the [README](../README.md#-taint-tracking).

Other demos live in `examples/` (`approval_demo.py`, `langchain_example.py`, `crewai_example.py`, `mcp_example.py`) and in `demo/`.

---

## 2. Add the SDK to your agent

```bash
pip install cerbere-ag
```

Wrap the functions your agent uses with the decorators. Each call is inspected and decided (`ALLOW`, `REQUIRE APPROVAL` or `BLOCK`) **before** it runs.

```python
from agentguard import AgentGuard

guard = AgentGuard(
    collector_url="http://localhost:8080",   # your collector (see section 3)
    api_key="ag-your-key",
    agent_id="my-agent",
)


@guard.guard_tool_call("send_email")
def send_email(to, subject, body):
    return email_service.send(to, subject, body)


@guard.guard_llm_call
def call_openai(messages):
    return client.chat.completions.create(model="gpt-4o", messages=messages)
```

Use a unique `agent_id` per agent: policies, budgets and the kill switch are scoped to it.

**Data that does not come from a guarded tool** (a database driver, an env var, an API client) must be declared so taint tracking can follow it. `track_input` returns the value unchanged:

```python
row = guard.track_input(db.fetch_one(query), source="customer_db", level="CONFIDENTIAL")
```

**Optional extras**

| Extra | Adds |
|---|---|
| `cerbere-ag[signing]` | Ed25519 verification of signed server decisions (opt-in via `AGENTGUARD_PUBLIC_KEY`) |
| `cerbere-ag[pii]` | Advanced PII detection via Presidio |
| `cerbere-ag[redis]` | Distributed rate limiting and LLM-judge cache |
| `cerbere-ag[ml]` | Local ML classifier (torch + transformers) |

**Good to know before going to production**

- By default the SDK **fails closed**: if the collector is unreachable, calls are not silently allowed. Set `AGENTGUARD_FAIL_OPEN=true` (or `fail_open=True`) only if you accept that trade-off.
- The kill switch stops an agent if the collector status cannot be refreshed for `AGENTGUARD_STATUS_MAX_AGE` seconds (default `300`, `0` disables).
- Approvals are single-use and bound to the exact tool and arguments.

---

## 3. Self-host the collector and dashboard

The collector receives the traces, makes server-side decisions and serves the dashboard. The default stack is the collector, PostgreSQL and Redis.

```bash
git clone https://github.com/chrismsmr-celcom/cerbere-AG.git
cd cerbere-AG

./scripts/selfhost-init.sh            # writes .env with random secrets
docker compose up -d --build          # collector + PostgreSQL + Redis
docker compose exec collector python -m collector.cli create-admin --email you@company.com
```

`selfhost-init.sh` never overwrites an existing `.env`. The `create-admin` command asks for a password (12 characters minimum), stored hashed. No email server or external identity provider is needed.

Then:

1. Check health: `curl http://localhost:8080/healthz`
2. Open `http://localhost:8080/login` and sign in with the admin you just created.
3. Create an API key in the dashboard, or reuse `AGENTGUARD_API_KEY` from your `.env`.
4. Point your agent at it, as in [section 2](#2-add-the-sdk-to-your-agent) (`collector_url="http://localhost:8080"`).

Run your agent, then watch its calls appear in the dashboard with their latency, cost, taint level and risk score.

### Before you expose it beyond localhost

The defaults are meant for a local evaluation over plain HTTP. For anything else, put a reverse proxy providing HTTPS in front of it, then set in `.env`:

```bash
AGENTGUARD_PUBLIC_URL=https://cerbere.example.com
AGENTGUARD_CORS_ORIGINS=https://cerbere.example.com
AGENTGUARD_COOKIE_SECURE=true
AGENTGUARD_TRUSTED_PROXIES=1
```

Keep `AGENTGUARD_SIGNUP_ENABLED=false`: public signup creates an admin workspace for any visitor.

### Optional detection layers

Rules are always on. The other two layers are off by default:

| Layer | How to enable | Note |
|---|---|---|
| Local ML classifier | Build with `INSTALL_ML=true`, set `AGENTGUARD_USE_ML=true` | Needs more RAM than the default 2 GB setup |
| LLM judge | `AGENTGUARD_USE_LLM_JUDGE=true`, `AGENTGUARD_JUDGE_API_KEY`, `AGENTGUARD_JUDGE_URL` | Flagged content is sent to `AGENTGUARD_JUDGE_URL`. For a fully on-site setup, point it to your own server (Ollama, vLLM, a private deployment) |

Everything else (TLS to PostgreSQL, SSO with OIDC, licensing, alerts) is covered in [SELF_HOSTING.md](SELF_HOSTING.md).

---

## 4. MCP server

For agents built on Claude, Cursor or any MCP-capable client, no SDK wiring is needed.

Hosted instance:

```bash
claude mcp add cerbereag --transport sse https://app.cerbereag.site/mcp/sse
```

Or run it locally against your own collector:

```bash
pip install cerbere-ag-mcp
```

```json
{
  "mcpServers": {
    "cerbereag": {
      "command": "cerbere-ag-mcp",
      "env": {
        "AGENTGUARD_MCP_COLLECTOR_URL": "http://localhost:8080",
        "AGENTGUARD_API_KEY": "ag-your-key",
        "AGENTGUARD_AGENT_ID": "my-agent"
      }
    }
  }
}
```

Restart the client. The agent can then call `check_prompt_security`, `authorize_tool_call`, `redact_pii`, `get_audit_trail` and `calculate_token_cost`. See [README_MCP.md](../README_MCP.md) for the full list.

---

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `docker compose up` refuses to start and mentions `selfhost-init.sh` | `.env` is missing. Run `./scripts/selfhost-init.sh` first. |
| Cannot sign in over HTTPS, or the session is lost | Set `AGENTGUARD_COOKIE_SECURE=true` only when you really serve HTTPS. Keep it `false` for plain `http://localhost`. |
| Browser calls fail with a CORS error | Add your dashboard origin to `AGENTGUARD_CORS_ORIGINS`. |
| Rate limits hit every client at once behind a proxy | Set `AGENTGUARD_TRUSTED_PROXIES=1` so the real client IP is used. |
| Agent stops with `AgentStatusStaleException` | The collector was unreachable for longer than `AGENTGUARD_STATUS_MAX_AGE`. Check `/healthz`, or adjust the setting. |
| A legitimate call is blocked | Check the span in the dashboard timeline: its taint level and risk score show why. See [DEBUG.md](DEBUG.md). |

## Next steps

- [SELF_HOSTING.md](SELF_HOSTING.md): production setup, HTTPS, TLS to the database, SSO, licensing
- [POSTGRESQL.md](POSTGRESQL.md): database setup and backups
- [BENCHMARK.md](BENCHMARK.md): detection numbers and method
- [EVIDENCE_RECOVERY.md](EVIDENCE_RECOVERY.md): incident capture and evidence recovery
- [../CONTRIBUTING.md](../CONTRIBUTING.md) and [../SECURITY.md](../SECURITY.md)

> Cerbère reduces risk in AI agent systems. It does not guarantee protection against every attack: use it as one layer of defense in depth.
