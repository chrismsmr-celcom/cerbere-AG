# Framework and agent coverage

This page is a short, user-facing summary of Cerbere AG integration coverage.
The detailed, maintained status and event boundaries live in
[AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md).

## Status definitions

| Status | Meaning |
|---|---|
| **Available** | The integration path is implemented and documented. It only governs the events explicitly listed for that path. |
| **Experimental** | An initial adapter exists; validate compatibility and failure behavior in a non-production environment. |
| **Protocol-compatible** | The client can connect using MCP, but Cerbere does not ship a dedicated native adapter for it. |
| **Planned** | No supported adapter is currently shipped. |

## Current coverage

| Agent / framework | Integration path | Status | What is covered |
|---|---|---|---|
| Custom Python agents | AgentGuard SDK and decorators | **Available** | Only LLM and tool execution points explicitly wrapped by the application |
| MCP clients | Cerbere advisory MCP server | **Available** | Security checks the agent explicitly invokes; not automatic interception |
| MCP clients | Cerbere MCP Gateway | **Available** | MCP tool calls routed through the configured gateway; configured response inspection |
| Claude Code | Native PreToolUse hook | **Experimental** | Matched pre-tool events received by the hook |
| Cursor | Native hooks | **Experimental** | Configured preToolUse, beforeShellExecution and beforeMCPExecution events |
| Gemini CLI, Copilot, OpenCode, Cline, Continue, Goose, OpenHands and other MCP clients | Standard MCP connection | **Protocol-compatible** | Only calls routed through the configured MCP server or gateway |
| OpenAI Codex | Native lifecycle adapter | **Planned** | No native adapter shipped |
| LangChain / LangGraph, CrewAI, OpenAI Agents SDK, Google ADK, Pydantic AI | Framework-specific adapters | **Planned** | Use the documented Python SDK instrumentation patterns only where the application explicitly wraps execution |

## Choose an integration

- **You own the Python agent code:** use the SDK and wrap the actual model/tool execution functions.
- **You need to govern existing MCP servers:** route the client through the MCP Gateway and configure explicit upstream allowlists.
- **You need agent-invoked checks:** use the advisory MCP server. The agent must call the security tools itself.
- **You use Claude Code or Cursor:** treat the native hooks as experimental and test the exact host version and event types.

## Coverage limitations

1. Cerbere cannot govern a tool call that bypasses its configured integration point.
2. MCP-only integration does not automatically intercept native shell, filesystem, browser or operating-system operations.
3. Native hooks cover only the host events they receive; they are not a complete host sandbox.
4. Framework compatibility is not the same as a first-party, tested adapter.
5. Fail-closed behavior must be tested for the specific gateway, hook or SDK path, including collector outages and timeouts.
6. Cerbere is not a replacement for least-privilege host permissions, network controls or OS/container sandboxing.

Do not use this summary as a substitute for the detailed integration matrix:
[AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md).
