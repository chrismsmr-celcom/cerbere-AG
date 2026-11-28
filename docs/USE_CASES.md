# Cerbere AG use cases

These workflows describe what can be done with the current integration surfaces.
They are intentionally limited to shipped capabilities; planned integrations
are labelled as such.

## Contents

- [Developer: govern MCP tools](#developer-govern-mcp-tools)
- [Security engineer: start in observe mode](#security-engineer-start-in-observe-mode)
- [Platform team: protect a Python agent](#platform-team-protect-a-python-agent)
- [Administrator: investigate a denied action](#administrator-investigate-a-denied-action)
- [Operator: prepare a self-hosted deployment](#operator-prepare-a-self-hosted-deployment)

---

## Developer: govern MCP tools

**Scenario:** An agent uses filesystem and GitHub MCP servers. You want tool
calls routed through Cerbere before they reach those upstream servers.

1. Deploy the self-hosted collector and create an agent-scoped API credential.
2. Install the MCP package:

   ```bash
   pip install "cerbere-ag-mcp"
   ```

3. Create a gateway configuration based on
   [mcp/gateway.example.json](../mcp/gateway.example.json). Declare each upstream
   server, its command, and an explicit `allowed_tools` list.
4. Start the gateway:

   ```bash
   cerbere-ag-gateway --config gateway.json
   ```

5. Configure the MCP client to connect to the gateway, not directly to the
   upstream servers.

The gateway exposes namespaced tools such as `filesystem__read_file`.
Calls routed through it are checked before forwarding and configured response
inspection runs before results return to the agent.

**Boundary:** a client that retains a direct connection to an upstream server
can bypass the gateway. The gateway does not intercept native shell or
filesystem tools outside MCP.

Reference: [MCP server and gateway](../mcp/README.md).

## Security engineer: start in observe mode

**Scenario:** You want to understand policy findings before enabling blocking.

Use the deployment's configured policy mode and inspect the events and
decisions collected by Cerbere. Review false positives and confirm that the
relevant agent calls actually reach the configured SDK, hook or gateway.

Do not assume that installing the advisory MCP server creates passive
monitoring. It exposes tools that the agent must explicitly invoke. For
automatic MCP call enforcement, route MCP traffic through the gateway.

Move to enforcement only after testing expected allow, deny and failure cases
on the actual integration path.

Reference: [Security primitives](SECURITY_PRIMITIVES.md).

## Platform team: protect a Python agent

**Scenario:** Your application owns the agent and its tool functions.

Install the SDK:

```bash
pip install cerbere-ag
```

Wrap the real execution points with AgentGuard:

```python
from agentguard import AgentGuard

guard = AgentGuard(
    collector_url="http://localhost:8080",
    api_key="ag-your-agent-scoped-key",
    agent_id="invoice-agent",
)

@guard.guard_tool_call("read_invoice")
def read_invoice(invoice_id: str):
    return invoice_service.read(invoice_id)

@guard.guard_tool_call("send_invoice")
def send_invoice(customer_id: str, document_id: str):
    return invoice_service.send(customer_id, document_id)
```

The guard must wrap the function that performs the side effect. A policy
definition or decorator on an unused function does not protect another
execution path.

Reference: [Python SDK quick start](../README.md#-quick-start).

## Administrator: investigate a denied action

**Scenario:** An agent reports that Cerbere denied a tool call.

1. Open the Cerbere dashboard and inspect the corresponding decision/event.
2. Confirm the agent identity, tool name, arguments metadata, policy result and timestamp.
3. Check whether the request reached the expected collector and integration.
4. If the denial is unexpected, adjust the narrowest relevant policy and
   reproduce the same test case.
5. Keep the denied event as evidence; do not disable the integration to make
   the workflow pass.

The exact evidence available depends on what the adapter sends. Do not assume
that every integration records complete prompts, tool outputs or session
history.

## Operator: prepare a self-hosted deployment

**Scenario:** You need to evaluate Cerbere inside your own infrastructure.

Follow [Self-hosting](SELF_HOSTING.md). The supported baseline uses Docker
Compose, PostgreSQL and Redis. Create an administrator, create agent-scoped
credentials, connect one integration, and verify health before adding more
agents.

For a first pilot, test:

- a permitted tool call;
- a policy-denied tool call;
- an expired or invalid credential;
- collector unavailability and timeout behavior;
- a direct upstream connection that bypasses the MCP gateway;
- persistence after restarting the deployment.

## Related references

- [Agent integration coverage](../AGENT_INTEGRATIONS.md)
- [Framework coverage summary](../FRAMEWORK_COVERAGE.md)
- [MCP package and gateway](../mcp/README.md)
- [Security primitives and their limits](SECURITY_PRIMITIVES.md)
- [Self-hosting](SELF_HOSTING.md)
