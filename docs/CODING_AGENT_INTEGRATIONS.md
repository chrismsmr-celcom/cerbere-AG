# Coding-agent integrations

Cerbere uses one normalized event contract and agent-specific adapters. An
adapter must declare the exact events it can observe and enforce. MCP support
does not imply interception of an agent's native shell or filesystem tools.

## Integration registry

The initial registry is available in Python:

```python
from agentguard.integrations import list_integrations

for integration in list_integrations(kind="coding_agent"):
    print(integration["id"], integration["status"], integration["events"])
```

Statuses are deliberately conservative:

- `available`: integration and enforcement path shipped.
- `mcp`: only actions routed through MCP are covered.
- `experimental`: native adapter exists but needs broader compatibility testing.
- `planned`: no adapter shipped.

## Claude Code: experimental PreToolUse enforcement

The first native adapter evaluates tool calls through Cerbere's existing
`POST /api/decide` endpoint. It accepts only a valid Ed25519 decision bound to
the exact tool name, arguments and nonce. A missing key, unreachable collector,
invalid signature, unknown tool or any non-ALLOW decision blocks the action.

### Install

From a checkout:

```bash
pip install '.[integrations]'
```

Or install the published package with its optional dependency:

```bash
pip install 'cerbere-ag[integrations]'
```

### Configure credentials

Set these variables in the environment inherited by Claude Code:

```bash
AGENTGUARD_COLLECTOR_URL=https://app.cerbereag.site
AGENTGUARD_API_KEY=ag-your-agent-key
AGENTGUARD_AGENT_ID=claude-code
# Optional: pin the collector's Ed25519 public key instead of fetching it.
AGENTGUARD_PUBLIC_KEY='-----BEGIN PUBLIC KEY-----...'
```

Use an agent-scoped API key where possible. The signing public key can be
pinned with `AGENTGUARD_PUBLIC_KEY`; if omitted, the adapter retrieves it from
the collector's public-key endpoint.

### Add the hook

Add this to `.claude/settings.local.json` (or the appropriate shared Claude
Code settings file):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "cerbere-ag-claude-code"
          }
        ]
      }
    ]
  }
}
```

The hook receives Claude Code's event JSON on stdin and returns a
`hookSpecificOutput.permissionDecision` response. Start with a narrow matcher
for the tools your team has configured in Cerbere, then expand deliberately.

### Register tool permissions

The adapter sends Claude Code's native tool names (for example `Bash`,
`Read`, `Write` and `Edit`) to `/api/decide`. The collector's active policy
must explicitly allow the tools that should run. Unknown or unregistered tools
are denied by default. Do not add broad permissions merely to make the hook
green.

### Current limits

- This adapter currently enforces `PreToolUse`; it does not yet collect the
  complete prompt, post-tool result, subagent or session lifecycle.
- It only controls actions that Claude Code routes through this hook.
- It is not an OS sandbox. Direct process activity, network access or file
  operations outside the hooked tool path require separate system controls.
- Human approval is not yet bridged into Claude Code's native approval UX;
  decisions other than signed `ALLOW` are denied.
- The first shell inspection rules cover known-dangerous patterns (for
  example `rm -rf`, `sudo`, `chmod 777`, `mkfs`, `dd` and download-to-shell
  pipes). This is a starter ruleset, not comprehensive command analysis. Keep
  tool allowlists and OS-level sandboxing in place.
- Validate against the Claude Code version and settings mode used by your
  environment before production rollout.

## Next adapters

Codex and Cursor native lifecycle adapters will implement the same normalized
event envelope. Their status will remain `planned` or `MCP-only` until
interception and enforcement are verified with integration tests.
