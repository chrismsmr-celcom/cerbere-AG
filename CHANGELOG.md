# Changelog

All notable changes to Cerbere are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/). While the major version is 0, minor releases may contain breaking changes;
they will always be listed under **Changed** or **Removed**.

## [Unreleased]

### Added
- `SECURITY.md`: reporting channel, response and fix targets, coordinated disclosure, safe harbor, supported versions.
- `CHANGELOG.md` and a release workflow that publishes a GitHub Release with a CycloneDX SBOM on every `v*` tag.
- Supply-chain workflow: Trivy scan of the Docker image (fails on fixable CRITICAL vulnerabilities) and SBOM generation.
- Dependabot for Python, npm (dashboard), Docker and GitHub Actions.
- `collector/LICENSE.md` and `dashboard/LICENSE.md` stating the license that applies to those directories.
- `tests/test_version_consistency.py`: the version is checked across `pyproject.toml`, the SDK and `/health`.

### Changed
- The version now has a single source, `agentguard/_version.py`. `/health` reported a hard-coded `0.2.1`; it now reports the real version.
- `mcp/pyproject.toml` declared `MIT` while the README and `LICENSE` state Apache-2.0 for the MCP server. It now declares `Apache-2.0`.

## [0.6.2]

### Security
- API keys are hashed with Argon2id. Legacy bare SHA-256 hashes are still accepted on read and migrated on first use.

> History before this changelog was started is not itemized here. See `git log` for details.

[Unreleased]: https://github.com/chrismsmr-celcom/cerbere-AG/compare/v0.6.2...HEAD
[0.6.2]: https://github.com/chrismsmr-celcom/cerbere-AG/releases/tag/v0.6.2
