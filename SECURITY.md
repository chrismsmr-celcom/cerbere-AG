# Security Policy

Cerbere is a security tool, so we hold ourselves to the standard we ask of others.
This page explains how to report a vulnerability, what you can expect from us, and which versions we patch.

## Reporting a vulnerability

**Do not open a public GitHub issue for an undisclosed vulnerability.**

Report it privately, by either route:

1. **Email:** [hello@cerbereag.site](mailto:hello@cerbereag.site), with the subject line `SECURITY: <short title>`.
2. **GitHub:** use *Security → Report a vulnerability* on the repository (private advisory).

Please include:

- affected version or commit (`/health` returns the running version)
- attack prerequisites (network position, role, configuration)
- reproduction steps or a redacted proof of concept
- the impact you observed

If you need an encrypted channel, say so in a first message without technical details and we will arrange one.

## What to expect from us

Cerbere is maintained by a very small team. These are targets we commit to try to meet, not a contractual SLA.

| Step | Target |
|---|---|
| Acknowledgement of your report | within **3 business days** |
| Initial assessment (valid / not valid, severity) | within **7 days** |
| Fix or mitigation, **Critical** (remote exploitation, auth bypass, data exposure) | within **14 days** |
| Fix or mitigation, **High** | within **30 days** |
| Fix or mitigation, **Medium / Low** | next regular release, within **90 days** |

We keep you informed of progress. Once a fix is released, we publish a security advisory and credit you,
unless you prefer to stay anonymous.

## Coordinated disclosure

We ask for **90 days** from your report before public disclosure, or until a fix is released, whichever comes first.
We will tell you if we need more time, and why.

There is currently **no paid bug bounty**. We are grateful for good-faith research and will credit it.

## Scope

In scope: the SDK (`agentguard/`), the MCP server and gateway (`mcp/`), the collector and dashboard
(`collector/`, `dashboard/`), the Docker images and the deployment files in this repository.

Examples we care about: authentication or authorization bypass, tenant isolation failures, policy or taint-tracking
bypass that lets a blocked tool call execute, audit-log tampering that goes undetected, secret or PII leakage,
injection (SQL, command, template), SSRF.

Out of scope: findings that need a compromised admin account or host, denial of service by raw traffic volume,
missing best-practice headers with no demonstrated impact, social engineering, and vulnerabilities in third-party
dependencies with no reachable path in Cerbere (report those upstream).

Detection bypasses (a prompt-injection string that scores low) are **welcome but are not security vulnerabilities**:
detection is probabilistic by design. Please send them as regular issues with the sample attached. See the benchmark
section of the README for current numbers.

## Safe harbor

If you act in good faith (no data destruction, no access to other people's data beyond what is needed to prove the
issue, no service degradation, private disclosure as above), we will not pursue legal action and will work with you
to resolve the issue.

## Supported versions

Only the **latest released minor version** receives security fixes. Upgrade notes are in [CHANGELOG.md](CHANGELOG.md).

| Version | Supported |
|---|---|
| Latest minor (see [Releases](../../releases)) | ✅ |
| Older versions | ❌ upgrade to the latest minor |

## Hardening requirements for deployments

- API credentials use `X-API-Key`; never put credentials in query parameters.
- Production deployments must use HTTPS (set `AGENTGUARD_COOKIE_SECURE=true` behind your reverse proxy).
- Prefer `AGENTGUARD_DETECTOR_FAILURE_MODE=fail_closed` for high-risk workloads.
- The LLM Judge is a detector, not an authorization authority.
- Tool execution must pass through a Cerbere enforcement point before side effects.
- Never commit `AGENTGUARD_API_KEY`, `AGENTGUARD_ADMIN_SECRET`, `AGENTGUARD_FLASK_SECRET`, provider keys or DB credentials.
- Run `python scripts/check_prod_secrets.py` before going to production.
- Database backups contain customer data: store them encrypted, outside the repository, never as CI artifacts.

## Supply chain

Every push runs Bandit, `pip-audit` and Gitleaks, plus a Trivy scan of the container image (rescanned weekly, since new
CVEs appear without new commits). Each release publishes a CycloneDX SBOM. Dependabot proposes dependency updates weekly.
