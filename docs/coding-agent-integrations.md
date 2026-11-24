# Coding-agent integrations

Cerbere can be called from native coding-agent hooks. The hook adapter does not
contain its own detection or policy engine: it normalizes the host event and
asks the existing AgentGuard SDK to authorize the action before the host runs it.

## Integration registry

The supported surfaces and event coverage are queryable from the SDK:

~~~python
from agentguard.integrations import list_integrations

for item in list_integrations(kind="coding_agent"):
    print(item["id"], item["status"], item["events"])
~~~

The registry is intentionally conservative: Claude Code and Cursor native hooks are experimental; Codex remains planned. MCP gateway coverage is listed separately because it only sees traffic routed through that gateway.

## Current first-pass support

| Host | Pre-execution event | Coverage in this adapter |
|---|---|---|
| Claude Code | PreToolUse | All matched tool calls, including MCP tools |
| Cursor | preToolUse | Generic tool calls |
| Cursor | beforeShellExecution | Shell commands |
| Cursor | beforeMCPExecution | MCP tool calls |

This is an initial integration surface, not a claim that every event or every
agent operation is covered. Post-tool results, file reads outside the host's
pre-tool event, subagents, and other coding agents require separate adapters
and conformance tests.

## Requirements

- Install the Cerbere SDK in the same Python environment used by the hook (`pip install -e .` from a source checkout, or the published package after the hook command is released).
- Set AGENTGUARD_COLLECTOR_URL.
- Set AGENTGUARD_API_KEY to an agent-scoped key.
- Set AGENTGUARD_AGENT_ID to the registered agent identity.\n- If signed server decisions are enabled, configure `AGENTGUARD_PUBLIC_KEY` and install the `signing` extra.
- Configure the hook with a blocking timeout appropriate for your collector
  and approval workflow.

The adapter always uses fail_open=False. Missing credentials, malformed
input, authorization errors, and collector failures result in a denial.
Human approval continues through Cerbere's existing approval workflow. A
host hook may remain blocked while that workflow is pending; configure the
host timeout accordingly.

## Claude Code

Add this to the project's .claude/settings.json, merging it with existing
settings rather than replacing the file:

~~~json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "cerbere-agent-hook --agent claude-code",
            "timeout": 310
          }
        ]
      }
    ]
  }
}
~~~

The hook receives the native event on stdin. Cerbere emits a structured
PreToolUse deny response when an action is rejected and emits no decision
when it is allowed, leaving Claude Code's normal permission flow intact.

## Cursor

Add the following entries to .cursor/hooks.json, merging with existing hooks:

~~~json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "command": "cerbere-agent-hook --agent cursor",
        "failClosed": true
      }
    ],
    "beforeShellExecution": [
      {
        "command": "cerbere-agent-hook --agent cursor",
        "failClosed": true
      }
    ],
    "beforeMCPExecution": [
      {
        "command": "cerbere-agent-hook --agent cursor",
        "failClosed": true
      }
    ]
  }
}
~~~

Cursor's failClosed setting is important: a crashed hook must not silently
allow a protected operation. The hook returns the host's permission response.

## Tool naming

Native tools retain their host tool names (for example, Bash, Write, or Shell).
MCP tools are namespaced as mcp:<server>:<tool> so two MCP servers with the same
tool name cannot accidentally share a policy entry.

Register these exact names in the agent's Cerbere tool policy. Do not rely on
a display label or a user-supplied agent name as an authorization identity;
the agent-scoped API key remains the credential.

## Security limitations

- A hook is an enforcement point only for events the host actually emits.
- A user or agent able to edit the hook configuration can remove the control.
  Use managed configuration or OS-level controls for stronger guarantees.
- A host may apply its own timeout. A timeout that terminates the hook before
  a decision is returned must be configured to fail closed.
- The adapter authorizes the action but does not execute it. The coding agent
  remains responsible for the actual tool call.
- This adapter does not yet inspect post-tool output. MCP gateway result
  scanning and result-side taint handling remain separate controls.
