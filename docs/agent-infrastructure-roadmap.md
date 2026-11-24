# Agent Runtime Infrastructure — implementation contract

This branch adds reusable primitives for the ten roadmap areas. It does not claim host-level isolation or production persistence where those integrations are not present.

## P0 — consistent runtime decisions
- `agentguard.event_contract.AgentEvent` is the versioned surface-neutral event schema.
- Every adapter should normalize to this contract before policy evaluation.
- `decision_fingerprint` supports cross-surface conformance assertions.
- `agentguard.result_inspection` inspects tool results for high-confidence prompt-injection patterns and redacts selected secret formats. MCP gateway wiring is fail-closed for detected injections.
- `agentguard.tool_contracts` models accepted classifications, provenance, tenant/org boundaries, and destinations. Confidential data requires an explicit approval path; the contract module does not grant approvals itself.
- Conformance tests are in `tests/test_agent_infrastructure.py`; additional adapter fixtures must be added as integrations ship.

## P1 — agent coverage and delegated authority
- Registry categories distinguish coding, business, workflow, framework, and protocol surfaces. Planned entries are not shipped integrations.
- `DelegationRegistry` enforces tenant, parent/child identity, scopes, TTL and revocation. Its initial implementation is in-memory; production use requires shared durable storage and audit events.
- `SequencePolicyEngine` correlates ordered canonical events within bounded per-agent/session windows. Rules must be configured explicitly; no universal attack semantics are implied.

## P2 — network, host and evidence
- `evaluate_egress` provides host normalization and allow/deny policy evaluation. It is not an OS firewall, DNS-rebinding defense, or network namespace.
- Host sandbox and supply-chain enforcement require platform-specific providers and deployment privileges; no false sandbox claim is made by this SDK layer.
- `attestation` creates digest-checked portable bundles and optional Ed25519 signatures. Private keys must be managed outside the process and signatures do not prove that the source host was uncompromised.

## Integration requirements before production claims
1. Persist delegations and sequence state in a tenant-scoped shared store.
2. Emit canonical events from SDK, collector, MCP and native hooks; route all through one policy evaluator.
3. Apply tool contracts to actual taint labels before external sinks.
4. Add vendor-specific result adapters and verify that the MCP gateway cannot be bypassed.
5. Run identical fixtures across every surface and publish the exact matrix of supported events.
6. Add OS-level sandbox/network providers and independent supply-chain scanning before advertising host protection.
