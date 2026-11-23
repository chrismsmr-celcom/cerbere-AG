# Contributing to Cerbere AG

Thank you for contributing. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) and [GOVERNANCE.md](GOVERNANCE.md) first.

## Licensing of contributions

- Everything outside `ee/` is licensed under [Apache-2.0](LICENSE). By opening a pull request you agree that your
  contribution is licensed under the same terms (inbound = outbound). No CLA is required.
- The `ee/` directory (Enterprise Edition, see [ee/LICENSE.md](ee/LICENSE.md)) does not accept external pull requests for now.
  Open an issue to discuss an enterprise feature instead.
- Never include code you do not have the right to relicense under Apache-2.0.

## Development setup

```bash
git clone https://github.com/chrismsmr-celcom/cerbere-AG.git
cd cerbere-AG
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install          # enables gitleaks and the regression hooks
```

## Conventions

- **Branches**: `feat/...`, `fix/...`, `refactor/...`, `chore/...`, `test/...`
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/), for example `fix(auth): ...`.
  Commits must be **signed** (see below).
- **Size**: no file larger than 1000 lines in `collector/` (see issue #4).
- **Tests**: every pull request must keep `pytest tests/` green. New behavior needs a test.
- **Detection patterns** belong in the pattern module of the SDK, never duplicated in the collector.

## Pull request process

1. Create a branch from `main`.
2. Run `pytest tests/ -v` locally.
3. Open the pull request and reference the issue (`Closes #N`).
4. The `Tests` workflow must pass and a `CODEOWNERS` review is required.
5. Squash-merge only.

## Signing your commits (required)

```bash
# SSH (recommended)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

## Security

Never commit secrets: `gitleaks` runs in pre-commit and in CI. To report a vulnerability, follow [SECURITY.md](SECURITY.md)
and do not open a public issue.
