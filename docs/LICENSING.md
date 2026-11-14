# Cerbere AG — plans, licensing and how to operate them

*For the publisher. Customers only need the "License and plans" section of `SELF_HOSTING.md`.*

## The model

**Open core: the collector exists for everyone, paid plans add what teams and companies need.**

- **Community (free)**: the complete collector and dashboard, all detection layers, human approvals, audit log,
  API keys, alerts, password sign-in. It is free within the limits of `LICENSE-COMMERCIAL.md` (see "Open decision" below).
  This is what gets Cerbere adopted.
- **Pro / Team / Enterprise**: a signed license key unlocks extra capabilities and comes with support.

Principles that make this credible to customers and investors:

1. **Basic security is never paywalled.** Detection, blocking and the audit trail work the same on every plan,
   including when a license expires.
2. **You pay for what an organization needs**, not for being protected: single sign-on, compliance evidence,
   integration with their security stack, retention, support and contractual guarantees.
3. **Fixed, budgetable prices.** No metering, no overage bills.
4. **Works offline.** The key is verified locally. Air-gapped customers need nothing from you at runtime.

## Plans

Prices are starting hypotheses to test with 3 or 4 prospects, not validated numbers. Self-hosted annual price = 10 × monthly.

| | **Community** | **Pro** | **Team** | **Enterprise** |
|---|---|---|---|---|
| Price | Free | $199/mo ($1,990/yr) | $599/mo ($5,990/yr) | from $2,500/mo (~$30,000/yr), by quote |
| Full collector + dashboard, detection, approvals, audit log, alerts | ✔ | ✔ | ✔ | ✔ |
| Agents in production | fewer than 10 *(per `LICENSE-COMMERCIAL.md`, see "Open decision")* | no limit | no limit | no limit |
| Support | community (GitHub) | email, 72 h | email, 48 h | contractual SLA, dedicated channel |
| **Company SSO (OIDC)** | – | – | ✔ *available now* | ✔ *available now* |
| Extended audit retention and export | – | ✔ *planned* | ✔ *planned* | ✔ *planned* |
| **Compliance report (PDF)** | – | – | ✔ *available now* | ✔ *available now* |
| SIEM export (Splunk, Datadog, syslog) | – | – | ✔ *planned* | ✔ *planned* |
| Multiple workspaces | – | – | ✔ *planned* | ✔ *planned* |
| SAML bridge assistance, custom policies, air-gapped install, DPA, security review | – | – | – | ✔ (services and contract) |

**Rule: only list as available what exists.** Today two Team features are enforced by the code
(`FEATURES` in `collector/licensing.py`): **company SSO** and the **compliance report**. The *planned* rows are where
Pro and Team still have to earn their price. Suggested order of value per effort:
**SIEM export -> extended retention -> multi-workspace**.
Until retention/export exist, sell Pro honestly as "supported plan".

The hosted cloud keeps its own usage-based plans (Free / Pro / Team / Enterprise) and is unaffected by license keys.

## How a license works

- A key looks like `cerbere_lic_v1.<key id>.<payload>.<signature>`. The payload holds the plan, customer, dates,
  optional extra features and informational limits. It is signed with an Ed25519 private key that only you hold.
- The collector verifies the signature with the public key(s) in `PUBLIC_KEYS` (`collector/licensing.py`). No network call.
- Status: **active** → **grace** (14 days after expiry, everything keeps working, warning in logs and `/api/license`)
  → **community** (paid features off). Basic security and password sign-in are never switched off.
- Anti-lockout: password sign-in can only be hidden while SSO is genuinely working. If the SSO license lapses,
  the password form returns by itself.
- What it does **not** do: stop a customer who edits the source code. The collector is source-available, so
  enforcement of the paid features ultimately rests on the contract (see the legal section). That is normal for open core
  and is why the value of paid plans should be support, updates and compliance, not just a lock.

## Operating it (the publisher's checklist)

**One-time setup**

```bash
python scripts/cerbere_license.py keygen --out cerbere-license-private.key
```

1. Paste the printed `"k1": "..."` line into `PUBLIC_KEYS` in `collector/licensing.py`, then ship that build.
2. **Store `cerbere-license-private.key` offline and back it up** (encrypted password manager plus an encrypted offline copy).
   Never in the repository, the Docker image or a server. If it is lost you cannot issue or renew licenses; if it leaks anyone can forge them.
3. Until step 1 is done, no license is accepted and every instance runs as Community.

**Issuing**

```bash
python scripts/cerbere_license.py issue --key cerbere-license-private.key \
    --customer "ACME Corp" --plan team --days 365
python scripts/cerbere_license.py issue --key cerbere-license-private.key \
    --customer "Prospect SA" --plan team --days 30        # 30-day trial
python scripts/cerbere_license.py inspect "cerbere_lic_v1...."
```

Send the key to the customer, who installs it with `cli license install` or `AGENTGUARD_LICENSE_KEY`.
Keep the license id, customer, plan and expiry in your customer records. Renewal = issue a new key; the old one simply expires.
Trials are your best sales tool: a 30-day Team key lets a prospect try SSO with their own identity provider.

**Key rotation**: generate a second pair with `--kid k2`, add it to `PUBLIC_KEYS` next to `k1`, sign new licenses with it.
Existing `k1` licenses keep working.

## Open decision: how free is Community?

Two documents currently say different things, and they must be aligned before you announce anything.

- **`LICENSE-COMMERCIAL.md` (what is published today)**: the collector and dashboard are free for evaluation, personal,
  educational and research use, for teams with fewer than 10 agents in production, and for startups under $1M ARR
  during their first year. A commercial license is required beyond that, or to offer Cerbere as a hosted or managed service.
- **The model you described to me**: the collector exists for everyone without limits, and paid plans add what makes
  the experience professional (SSO, compliance, integrations, support).

| | **A. Free below a size** (the text today) | **B. Free for everyone, paid for features** |
|---|---|---|
| Adoption | good for small teams, a barrier for bigger ones | maximum |
| Revenue | any organization above the limits must buy, even if it needs no extra feature | only organizations that want the paid features |
| Story for investors | "fair-source": monetizes growth of usage | classic open core |
| Enforcement | by contract only (nothing in the code counts agents or revenue) | by license key (already built) |

Either works. Pick one, then make the license text, this table and the pricing page say the same thing.
What the code enforces today does not depend on the choice: **license keys gate features** (SSO, compliance report),
never agent counts or revenue.

## Before you announce this (blocking items)

1. **`LICENSE-COMMERCIAL.md` must match the decision above, and be reviewed by a lawyer** (this is not legal advice).
   Points to raise with them:
   - It says free below 10 agents and commercial above 10: **exactly 10 agents is not covered**.
   - "Startup", "ARR" and "first year" are not defined (who counts as affiliated, from which date).
   - It does not say that **removing, disabling or circumventing the license-key functionality, or using paid features
     without a license, is not allowed**. The code verifies keys, but only a clause makes bypassing them a breach.
   - Paid plans need a commercial agreement (term, fees, support, usage audit right, trial terms, liability limits).
   - Well-known licenses with this kind of restriction (for example the Elastic License 2.0 or the Business Source License)
     can serve as a base, so you do not start from a blank page.
2. **Naming.** A source-available collector is not "open source" in the OSI sense, and calling it that tends to draw criticism
   from developer communities. Use **Open source** for the SDK and MCP server (true), and **Community edition** for the free collector.
3. **Pricing page honesty.** Show planned features as "coming soon" with no date promises.
4. **Billing without Stripe.** Self-hosted licenses are annual and invoiced by bank transfer; issue the key on payment.
   For the cloud and small plans, plan a merchant of record such as Paddle or Lemon Squeezy.

## Not built yet

- **Usage metering and limits.** Limits in a license (`--limit agents=50`) are informational today. Hard caps would
  contradict "free and complete for everyone", so the recommendation is contractual fair use for Enterprise only.
- **A license page in the dashboard.** State is available through `GET /api/license`, `cli license status` and the startup log.
- **Optional usage report** (a monthly counter with no content, sent by the customer) for usage-based Enterprise deals.
