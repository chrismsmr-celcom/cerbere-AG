# Public ChatGPT / Codex Plugin Architecture — Cerbere AG

Status: architecture proposal, not an implementation.
Branch: `feat/public-chatgpt-plugin`
Product repository: `chrismsmr-celcom/cerbere-AG`

## 1. Objective

Expose Cerbere AG as a public remote MCP app that lets an authorized human operator inspect and manage the security posture of the Cerbere tenant they already belong to.

Cerbere is the runtime trust and enforcement layer for AI agents. The ChatGPT/Codex integration is a **management and observability surface** for that control plane; it is not a substitute for the SDK or enforcing MCP gateway, and it must not become a bypass around runtime policy.

The integration should support both:
- **Operators / security teams:** inspect agents, policy posture, decisions, traces, audit evidence and pending approvals.
- **Developers:** inspect why an action was allowed, blocked or held, review agent identity and policy configuration, and troubleshoot integrations.

## 2. Repository facts observed

The repository README and source currently describe these components:

- `agentguard/`: Python SDK, identity model, runtime decision and policy enforcement.
- `collector/`: Flask control plane/API, authentication, authorization, persistence and audit/trace ingestion.
- `mcp/`: advisory MCP server and an MCP gateway/proxy. The gateway can enforce before forwarding calls to upstream MCP servers.
- Dashboard: human-facing tenant administration, agent management, trace/decision views and approval workflow.
- Persistence: SQLite/PostgreSQL support; Redis is used for selected distributed capabilities.
- Identity model in `agentguard/identity.py`: Tenant → Org → User / Agent → Session. Human roles are admin, developer, auditor and viewer; agent is a separate machine principal.
- Agent API credentials use the structured `ag_...` format. The identity module documents Argon2id hashing with legacy SHA-256 verification/migration.
- Authorization is centralized through `collector/authz.py` and role/resource checks in `collector/auth/rbac.py`.
- Human identity resolution is implemented in `collector/auth/identity_resolution.py`; identity CRUD and identity audit events live in `collector/identity_routes.py`.
- Platform service credentials (`agp_...`) are a separate service-to-service identity class in `collector/platform_identity.py`; they must not be reused as end-user OAuth credentials.
- The MCP gateway in `mcp/gateway_server.py` accepts HTTP API keys through `x-api-key` or Bearer, resolves each key to a configured identity, and creates an AgentGuard instance scoped to that identity. The gateway has stdio and HTTP modes.
- `mcp/README.md` documents an HTTP gateway with a configured `http.api_keys` map and fail-closed behavior.
- `README_MCP.md` describes the advisory MCP server tools: `check_prompt_security`, `authorize_tool_call`, `redact_pii`, `get_audit_trail`, and `calculate_token_cost`. These are advisory tools called by an agent; they do not automatically intercept every action.
- The main README explicitly states that multi-agent delegation is still being built and is not shipped. The plugin must not advertise delegation as an available capability.

These facts were checked against the repository's current default branch files while preparing this document. This is a focused architecture review, not a complete security audit or runtime verification.

## 3. Important architectural distinction

There are three different surfaces and they must remain distinct:

1. **Runtime enforcement:** SDK decorators and the MCP gateway inspect and gate agent activity before execution.
2. **Control plane:** Collector APIs manage tenant/org/user/agent identity, policies, credentials, approvals and operational state.
3. **Human management integration:** ChatGPT/Codex OAuth session acts as a human user against the control plane, with the same tenant/org and RBAC boundaries as the dashboard.

The public MCP server must call the authoritative Collector/control-plane services. It must not instantiate a privileged AgentGuard using a global service key and then expose cross-tenant results to the caller. It must not accept an arbitrary `tenant_id`, `org_id`, `agent_id` or role supplied by the model as proof of authorization.

## 4. Authentication and authorization target

### Recommended flow

Use OAuth 2.1 Authorization Code with PKCE (S256) for the remote MCP connection.

1. ChatGPT/Codex discovers the MCP server's OAuth protected-resource and authorization-server metadata.
2. The user is redirected to Cerbere's HTTPS authorization page.
3. The user signs in through Cerbere's existing human authentication path.
4. The user selects or confirms the tenant/org only if their account belongs to more than one.
5. Cerbere issues a short-lived, audience-restricted authorization code and exchanges it for an access token. PKCE, exact redirect URI matching, state, nonce where applicable, and one-time code use are mandatory.
6. The MCP request validates issuer, audience, expiry, signature, token revocation state and scopes.
7. The server resolves the authenticated human principal from server-side identity data and applies the existing authorization kernel to every operation.

### Token requirements

- Never use an agent `ag_...` credential as a human login.
- Never use a platform `agp_...` service credential as a user token.
- Never ask users to paste long-lived collector API keys into ChatGPT.
- Bind tokens to a human subject and one tenant/org context; do not trust tenant/org claims without validating current membership and active status.
- Use short-lived access tokens, refresh-token rotation, revocation and replay detection.
- Support least-privilege scopes, for example `agents:read`, `traces:read`, `audit:read`, `policies:read`, `approvals:read`, `approvals:write`, `agents:manage`, `policies:write`.
- Map OAuth scopes to existing RBAC actions. OAuth scopes are an additional restriction, not a replacement for tenant/org and role authorization.
- Default to read-only scopes. Request write scopes only when the user connects and the product actually needs them.
- Require fresh authorization / explicit confirmation for high-impact operations such as approving a risky action, revoking an agent credential, or changing enforcement policy.

### RBAC mapping

- `admin`: tenant administration, within tenant boundary.
- `developer`: agent operations and permitted runtime troubleshooting.
- `auditor`: read-only traces and audit evidence.
- `viewer`: limited read-only operational visibility.
- `agent`: machine identity only; no dashboard or human administration permissions.
- Platform service identities: internal service-to-service only; never exposed to public MCP users.

Every MCP tool must call the same authorization kernel and resource checks as the corresponding dashboard/API route. Do not duplicate a weaker authorization implementation in the MCP adapter.

## 5. MCP server architecture

Recommended topology:

```
ChatGPT / Codex
    |
    | HTTPS + OAuth 2.1 / PKCE
    v
Cerbere Remote MCP adapter
    |
    | verified human principal + tenant/org context
    v
Collector control-plane service layer
    |
    +--> Identity / RBAC / policy services
    +--> Agent registry and credential lifecycle
    +--> Traces / decisions / metrics
    +--> Approval workflow
    +--> Audit event store
    |
    v
PostgreSQL (authoritative persistent state)
```

The MCP adapter should be a thin protocol layer. It should not query database tables directly, bypass Flask authorization decorators, or maintain its own tenant/agent state.

The existing local stdio MCP package and gateway are useful integration surfaces, but neither should be assumed to provide the complete public human OAuth experience:
- The advisory MCP server lets an agent request checks; it is not enforcement by itself.
- The gateway currently documents configured API-key identities for HTTP. That is machine/client authentication, not the human OAuth flow required for a public ChatGPT/Codex app.
- The public management MCP service must be a separately authenticated adapter or a deliberately extended server with clear principal separation.

## 6. Initial tool surface

Ship a read-only MVP first. Every result must be tenant/org-scoped and redact secrets and sensitive payloads.

### Read-only tools

- `cerbere_get_security_overview`: high-level posture, counts and recent activity for the authenticated tenant/org.
- `cerbere_list_agents`: registered agents and safe identity/status metadata.
- `cerbere_get_agent`: details for one authorized agent; never return raw credentials.
- `cerbere_list_policy_rules`: active policy summary and enforcement mode.
- `cerbere_list_decisions`: allow/deny/approval decisions with redacted reason and metadata.
- `cerbere_get_trace`: one trace with spans, checks, latency and redacted arguments/results.
- `cerbere_list_pending_approvals`: pending items the current user is allowed to review.
- `cerbere_get_audit_events`: searchable audit evidence, respecting auditor/viewer permissions.
- `cerbere_get_metrics`: safe aggregate metrics for the authorized tenant/org.

### Write tools — phase 2, explicit confirmation

- `cerbere_approve_action` / `cerbere_reject_action`: require approval permission, exact approval ID, immutable action context and explicit user confirmation.
- `cerbere_revoke_agent`: require agent-management permission and explicit confirmation; never return or recreate the revoked secret.
- `cerbere_update_policy`: only after policy versioning, audit coverage, validation and rollback are proven; require explicit confirmation and show the diff before applying.
- `cerbere_create_agent` / `cerbere_rotate_agent_credential`: defer until secure one-time credential delivery and secret handling are implemented. Never reveal credentials in tool output or audit logs.

Do not initially expose:
- raw API keys, signing private keys, session tokens, environment variables or secrets;
- unrestricted SQL/database access;
- arbitrary tool execution or shell access;
- cross-tenant search or platform-admin operations;
- a tool that claims to enforce an action merely because the model called `authorize_tool_call`;
- multi-agent delegation tools before delegation is implemented and independently tested.

## 7. Data handling and security requirements

- Redact secrets, PII and sensitive tool arguments before MCP responses leave Cerbere.
- Enforce pagination and bounded result sizes on traces, decisions and audit events.
- Return stable IDs, timestamps, verdicts, policy/rule identifiers and redacted explanations; avoid returning full prompt bodies by default.
- Treat trace content and agent-provided text as untrusted data, never as instructions for the MCP server.
- Audit every management read that accesses sensitive evidence, and every write operation with actor, tenant, org, resource, before/after version and outcome.
- Preserve the existing hash-chain / signed-checkpoint evidence model; verify that management actions are included in the same trustworthy audit stream.
- Rate-limit OAuth endpoints and MCP tools; protect against token replay, cross-tenant IDOR, confused-deputy behavior and oversized payloads.
- Fail closed for authorization failures and approval writes. Read-only queries must not silently fall back to a global/system identity.
- Ensure the MCP process has no direct platform-admin credential available to user-facing tool handlers.

## 8. Current blockers / items to verify before implementation

1. **Human auth integration:** source has human identity resolution and human RBAC, but the exact production login/session flow and OAuth callback lifecycle must be traced end to end before choosing the authorization-server implementation.
2. **Gateway identity propagation:** `mcp/gateway_server.py` uses `ContextVar` values and an executor path. Verify context propagation under concurrent requests and prove that one request cannot inherit another request's identity or API key.
3. **Gateway identity fallback:** verify every missing/invalid credential path in `mcp/gateway_config.py` fails closed. The HTTP resolver itself rejects a missing API key; no anonymous/default identity may be accepted on remote HTTP.
4. **Authorization parity:** compare every candidate MCP operation with the existing route's `require_auth`, `require_role`, `authorize` and tenant/org resource checks. Do not assume a role name alone enforces tenant isolation.
5. **Audit completeness:** identity events are persisted by `collector/identity_routes.py`; verify approval, policy, agent lifecycle and MCP management events all reach the tamper-evident audit chain.
6. **Sensitive response handling:** verify redaction on traces and audit APIs, not only the runtime gateway's upstream response inspector.
7. **Public endpoint:** verify a stable production HTTPS MCP URL, OAuth metadata endpoints, health checks, deployment secrets, TLS and operational monitoring. Local stdio or a gateway configured with static API keys is not a public OAuth endpoint.
8. **Product documentation consistency:** reconcile old package documentation and current repository docs before publishing the integration. In particular, distinguish advisory MCP checks from gateway enforcement and describe only shipped functionality.

These are verification gates, not claims that every item is currently broken.

## 9. Delivery plan

### Phase 0 — complete the implementation audit
- Trace human sign-in, session issuance, session validation and logout/revocation.
- Trace tenant/org membership and every role/resource check.
- Map the APIs for agents, policies, decisions, traces, metrics, approvals and audit.
- Test gateway identity isolation and fail-closed behavior.
- Confirm audit-chain coverage and response redaction.

### Phase 1 — OAuth and read-only remote MCP
- Implement OAuth 2.1 authorization-code + PKCE and protected-resource metadata.
- Bind each token to a human identity and one authorized tenant/org.
- Implement the read-only tools through the Collector service layer.
- Add tests for no token, expired/revoked token, invalid audience, missing scope, wrong tenant, wrong org, insufficient role, IDOR and redaction.
- Deploy to a production HTTPS endpoint and run end-to-end tests with ChatGPT and Codex.

### Phase 2 — controlled writes
- Add approval/rejection and agent lifecycle operations with explicit confirmation, RBAC, idempotency and audit.
- Add policy editing only after versioning and rollback are safe.
- Add public integration docs, support/privacy/terms links, demo tenant and reviewer credentials.

### Phase 3 — public listing and review
- Prepare listing metadata, screenshots/demo, privacy and security disclosures, positive and negative test cases, and release notes.
- Submit through the official OpenAI app submission/review process. Public listing is not guaranteed until review and approval are complete.

## 10. Acceptance criteria

- OAuth login identifies the actual human user; no machine credential is accepted as a substitute.
- Every request is restricted to the token's currently authorized tenant/org.
- Existing RBAC and resource-level authorization are applied on every tool.
- No secrets or unredacted sensitive payloads are returned.
- Cross-tenant and cross-org IDOR tests fail.
- Concurrent requests cannot cross-contaminate identity.
- Read tools work without write scopes; write tools reject missing scopes and roles.
- High-impact writes require explicit confirmation and create tamper-evident audit evidence.
- The public endpoint is HTTPS, stable, monitored and supports MCP OAuth discovery.
- The plugin description accurately distinguishes control-plane management from runtime enforcement.

## 11. References

- `README.md`
- `agentguard/identity.py`
- `collector/identity_routes.py`
- `collector/auth/identity_resolution.py`
- `collector/auth/rbac.py`
- `collector/authz.py`
- `collector/platform_identity.py`
- `mcp/README.md`
- `mcp/README_MCP.md`
- `mcp/gateway_server.py`
- `mcp/gateway_config.py`
