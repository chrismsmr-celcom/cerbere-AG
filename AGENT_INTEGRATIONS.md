# Agent Integrations

Cerbere AG is designed to sit at the execution boundary of an agent system. It does not replace the agent, model provider, framework, or workflow orchestrator. It evaluates actions through the existing AgentGuard policy engine and records the resulting security evidence.

This document is the integration coverage reference. It distinguishes a working enforcement surface from a client that can merely connect to MCP or a framework that can be instrumented manually.

## Status definitions

| Status | Meaning |
|---|---|
| **Available** | The integration surface is implemented and documented for use. Its stated coverage still applies; it is not a guarantee of complete host coverage. |
| **Experimental** | An initial adapter exists, but coverage and host-version compatibility are limited. Validate it in a non-production environment first. |
| **Planned** | The integration is on the roadmap or represented in the registry, but a supported adapter is not shipped. |
| **Protocol-compatible** | A client can connect through the standard MCP protocol. This does not mean Cerbere has a dedicated native adapter for that client. |

## Coverage matrix

### Runtime and protocol integrations

| Integration | Connection method | Status | Enforced events / scope |
|---|---|---|---|
| Python agents | AgentGuard Python SDK and decorators | **Available** | Instrumented LLM and tool calls |
| MCP Gateway | Proxy between an MCP client and configured upstream MCP servers | **Available** | Routed MCP tool calls before forwarding; configured response inspection |
| MCP advisory server | Agent calls Cerbere security tools such as `authorize_tool_call` | **Available** | Only checks the agent explicitly requests; not automatic interception |

### Native coding-agent integrations

| Agent | Connection method | Status | Current coverage |
|---|---|---|---|
| Claude Code | Native `PreToolUse` hook; MCP also available | **Experimental** | Matched pre-tool events |
| Cursor | Native hooks; MCP also available | **Experimental** | `preToolUse`, `beforeShellExecution`, `beforeMCPExecution` |
| OpenAI Codex | Native lifecycle adapter | **Planned** | No native adapter shipped |
| Gemini CLI | MCP where supported by the client configuration | **Protocol-compatible** | MCP-routed calls only; no dedicated native hook adapter |
| GitHub Copilot | MCP where supported by the client/product surface | **Protocol-compatible** | MCP-routed calls only; no dedicated native hook adapter |
| OpenCode | MCP where supported by the client configuration | **Protocol-compatible** | MCP-routed calls only; no dedicated native hook adapter |
| Cline | MCP | **Protocol-compatible** | MCP-routed calls only; no dedicated native hook adapter |
| Continue | MCP where supported by the client configuration | **Protocol-compatible** | MCP-routed calls only; no dedicated native hook adapter |
| Goose | MCP | **Protocol-compatible** | MCP-routed calls only; no dedicated native hook adapter |
| OpenHands | MCP / external tool integration where configured | **Protocol-compatible** | Only calls routed through the configured integration |
| Other MCP clients | Standard MCP server or gateway | **Protocol-compatible** | MCP-routed calls only |

A client appearing in this table does not imply a tested, first-party native adapter. MCP compatibility depends on the client's supported MCP transport and configuration.

### Agent frameworks

| Framework | Integration path | Status | Notes |
|---|---|---|---|
| LangChain / LangGraph | Python SDK instrumentation | **Planned** | Example code is illustrative; a verified first-party adapter is not shipped |
| CrewAI | Python SDK instrumentation | **Planned** | Example code is illustrative; a verified first-party adapter is not shipped |
| OpenAI Agents SDK | Python SDK instrumentation | **Planned** | Dedicated adapter not shipped |
| Google ADK | Python SDK instrumentation | **Planned** | Dedicated adapter not shipped |
| Pydantic AI | Python SDK instrumentation | **Planned** | Dedicated adapter not shipped |
| Custom Python agents | AgentGuard SDK decorators | **Available** | The developer explicitly wraps the LLM and tool execution points |

### Business and workflow agents

Cerbere's policy engine and MCP gateway are not limited to coding agents. CRM, customer-support, finance, research and workflow agents can be protected when their tool execution is routed through the MCP gateway or instrumented with the SDK.

There are currently no dedicated vendor-specific adapters for business-agent products. Treat these as integration patterns, not named product support.

## Choosing the right integration

- **Use the MCP gateway** when you need enforcement in front of existing MCP servers. Configure the agent to use the gateway instead of connecting directly to those upstream servers.
- **Use the native hook** when a coding agent exposes a pre-execution hook and you need to check actions such as shell or tool calls before the host runs them.
- **Use the Python SDK** when you own the agent code and can wrap the actual LLM and tool execution functions.
- **Use the advisory MCP server** for explicit security checks initiated by the agent. It is not a substitute for a gateway or native pre-execution hook when automatic enforcement is required.

## Important coverage boundaries

1. **Only intercepted traffic is governed.** A gateway cannot inspect a direct connection to an upstream server that bypasses it. A hook cannot govern events the host does not emit or the configured hook does not match.
2. **MCP is not a universal operating-system boundary.** MCP-only integration does not automatically intercept direct shell commands, filesystem access, browser actions, or other native tools.
3. **Pre-execution and result inspection are different controls.** Native Claude Code and Cursor hooks currently provide initial pre-execution coverage; do not assume they inspect every tool result or lifecycle event.
4. **No complete multi-agent delegation adapter is shipped.** Cross-agent delegation, scoped authority propagation, hierarchical revocation and complete cross-agent lineage remain roadmap work.
5. **Fail-closed behavior is configuration- and integration-specific.** Review the relevant hook or gateway documentation and test collector outages, timeouts, malformed events and missing credentials before production use.
6. **Defense in depth remains necessary.** Keep least-privilege host permissions, credential isolation, network controls and OS/container sandboxing. Cerbere is not an OS sandbox and does not guarantee detection of every attack.

## Setup documentation

- [Native coding-agent hooks](docs/coding-agent-integrations.md)
- [MCP server and gateway](mcp/README.md)
- [Python SDK quick start](README.md#-quick-start)
- [Self-hosting](docs/SELF_HOSTING.md)
- [Security policy and vulnerability reporting](SECURITY.md)

## Querying the integration registry

The SDK repository exposes a registry for integration metadata:

```python
from agentguard.integrations import list_integrations

for integration in list_integrations():
    print(
        integration["name"],
        integration["status"],
        integration["surfaces"],
        integration["events"],
    )
```

The registry is descriptive metadata. An entry marked planned is not an implemented adapter. Keep this document aligned with the registry and the actual adapter tests when coverage changes.
