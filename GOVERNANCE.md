# Governance

Cerbere AG is currently a **maintainer-led project**. This document says plainly who decides what, so contributors
and adopters know what to expect.

## Roles

- **Maintainer**: Christopher Dikesa ([@chrismsmr-celcom](https://github.com/chrismsmr-celcom)). Owns the roadmap,
  reviews and merges pull requests, publishes releases and has the final say on design and licensing.
- **Contributor**: anyone who opens an issue, a discussion or a pull request.
- **Committer** (future): a contributor invited by the maintainer after a sustained record of good, reviewed contributions.
  Committers can merge changes in the areas they are trusted with. There are none today.

## How decisions are made

- Day-to-day changes are decided in pull requests. The maintainer merges once CI passes and a review approves it.
- Larger changes (new integration surface, change to the decision format, new dependency with a heavy footprint,
  anything that affects security guarantees) start with an issue that states the problem and the proposed approach.
- Disagreements are resolved by discussion on the issue. If there is no consensus, the maintainer decides and
  records the reason in the issue.

## Licensing

- The core is licensed under [Apache-2.0](LICENSE). The `ee/` directory is under its own license ([ee/LICENSE.md](ee/LICENSE.md))
  and does not accept external pull requests for now.
- Paid features may move into `ee/` only when they serve organizations rather than individuals (single sign-on, compliance
  evidence, integrations with security stacks, retention). **Basic security is never paywalled**: detection, blocking and
  the audit trail work the same on every plan.
- Any change to these rules is announced in the changelog before it takes effect.

## Releases

- Versions follow [Semantic Versioning](https://semver.org/). While the major version is 0, minor releases may contain
  breaking changes; they are always listed under **Changed** or **Removed** in [CHANGELOG.md](CHANGELOG.md).
- Each release is tagged and published on GitHub with an SBOM. The SDK (`sdk-v*`) and the MCP server (`mcp-v*`) are released
  independently.

## Security

Vulnerabilities are handled privately, following [SECURITY.md](SECURITY.md).

## Conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
