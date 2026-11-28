# Security primitives: implementation and operator visibility

This document is the operator-facing inventory for the security primitives in
Cerbere AG. It separates SDK primitives, collector enforcement, and dashboard
observability. A Python unit test proves a primitive's local behavior; it does
not prove that every production request passes through it.

## Primitive inventory

| Primitive | Code surface | Current guarantee / boundary | Dashboard visibility |
|---|---|---|---|
| Canonical agent events | `agentguard/event_contract.py`, `agentguard/event_runtime.py` | Normalized event contract and runtime helpers. Enforcement depends on the adapter emitting the event. | Feed, traces, and event views where the collector receives the event. |
| Unified decision engine | `agentguard/decision_engine.py`, `policy/` | Central policy evaluation. Each integration must call it; direct/unrouted host actions are outside coverage. | Policies, feed, approvals, decisions. |
| Data taint and provenance | `agentguard/taint.py`, `agentguard/tool_contracts.py` | Labels and origin metadata can constrain tool use. Provenance must be supplied and propagated by the integration. | Flow and Agent Graph visualize recorded flows; they are not a substitute for configuring provenance. |
| Tool contracts | `agentguard/tool_contracts.py` | Strict registry denies unknown tools; checks provenance, tenant/org boundary, data classes, and destination patterns. | No dedicated contract-management screen is currently documented. Do not imply contracts can be configured in the dashboard unless that UI is shipped. |
| Delegation | `agentguard/delegation.py` | In-memory reference registry with scope, tenant, parent/child, expiry, and revocation checks. It is not durable or shared across processes. | No dedicated delegation-management screen is currently documented. |
| Egress policy | `agentguard/egress.py` | Destination normalization and allow/deny evaluation. Not an OS firewall, DNS-rebinding defense, or network sandbox. | No dedicated egress-policy management screen is currently documented. |
| Trajectory analysis | `agentguard/trajectory.py` | Bounded in-memory sequence analysis for escalation and privilege-risk signals. | Feed/trace evidence only when the integration emits the relevant events. |
| Signed decisions | `agentguard/signing.py` | Ed25519 signatures bind decisions to request/action fields when supplied; runtime verification requires expiry. Persistent signing key required outside explicit local development. | Decisions and audit evidence; key management is an operator deployment concern. |
| Attestation bundles | `agentguard/attestation.py` | Canonical JSON digest and optional Ed25519 signature verification. | No dedicated attestation explorer is currently documented. |
| MCP Gateway | `collector/mcp_gateway.py`, `mcp/` | Governs traffic routed through the configured gateway. Direct upstream connections bypass it. | Integrations/Connect plus received events and decisions. |
| Native coding-agent hooks | `agentguard/integrations/hooks.py` | Claude Code and Cursor coverage is experimental and host-event dependent. | Connect snippets and resulting events; no claim of complete host coverage. |

## Important implementation boundaries

- The delegation registry currently stores state in process memory. Do not use it
  as a durable multi-worker authorization source until a persistent backend and
  cross-process tests exist.
- Egress checks are application-level policy helpers. Enforce network isolation
  separately at the container, host, firewall, or service-mesh layer.
- Tool contracts only protect calls that invoke the registry. A contract
  definition sitting unused does not protect an execution path.
- Trajectory analysis is context for a decision, not proof that every event in
  an agent's execution was observed.
- Attestation verification validates the bundle's digest and signature. It does
  not establish that the source events were truthful or complete.
- Dashboard visualizations show evidence collected by Cerbere. They do not
  imply that every primitive has a dashboard configuration surface.

## Required change checklist

For every new security primitive or enforcement feature:

1. Add or update unit tests for allow, deny, malformed input, expiry/revocation,
   tenant isolation, and failure behavior as applicable.
2. Add an integration test proving the collector, SDK, gateway, or hook actually
   invokes the primitive on the execution path.
3. Add a dashboard surface for configuration and/or operational visibility.
   If configuration is intentionally code/environment-only, say so in the UI.
4. Add an operator guide with defaults, required environment variables,
   limitations, and a reproducible example.
5. Update `AGENT_INTEGRATIONS.md`, the README, and the changelog when coverage
   or user-visible behavior changes.
6. Run Python tests, dashboard tests/build, and the self-hosted smoke test before
   describing the feature as ready.

## Local test command

Run the focused primitive regression suite:

```bash
pytest -q tests/test_security_primitives.py tests/test_trajectory_security.py
```

Then run the full repository CI test commands before merging. These tests have
not been executed by this documentation change alone.
