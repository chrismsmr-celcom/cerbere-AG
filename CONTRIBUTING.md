# Contributing to ActRun

Thanks for your interest in ActRun. This is an early-stage project, so contributions of every size matter, and so does honest feedback.

## The most useful contribution right now

**Evidence.** ActRun is a bet that agents sharing mutable state need real coordination primitives. We want to know whether that is true for you.

If you run several agents against shared state, please open a [multi-agent failure report](https://github.com/chrismsmr-celcom/ActRun/issues/new?template=multi_agent_failure.yml). A concrete story ("two agents rewrote the same file", "a run deadlocked", "I could not tell who changed what") is worth more than a pull request at this stage.

## Ways to contribute

- **Report failures** you have hit with multi-agent systems.
- **Challenge the design.** If part of the direction in the README looks wrong, open an issue and say so.
- **Fix bugs and add tests.** The prototype is small and test coverage is thin.
- **Improve the docs.** Anything unclear, outdated, or overclaiming is a good first contribution.
- **Build features** from the [roadmap](README.md#roadmap), after discussing them first (see below).

Issues labeled `good first issue` are meant for newcomers.

## Before you write code

For anything larger than a small fix, **open an issue first**. This applies in particular to:

- a new public API or a change to an existing one,
- any change to the event schema,
- a new dependency,
- a new component or language boundary (Python vs Rust).

This avoids wasted work on a direction the project cannot accept.

## Development setup

Requirements: Python 3.10+, Git, and the Rust toolchain (stable) for the trace engine.

```bash
git clone https://github.com/chrismsmr-celcom/ActRun.git
cd ActRun

# Python
cd python
python -m pip install -e ".[dev]"
pytest

# Rust
cd ../rust/trace-engine
cargo test
```

## Project layout

```
ActRun/
├── python/                  Python runtime and evaluation (package: agent_harness)
│   ├── src/agent_harness/
│   └── tests/
├── rust/trace-engine/       Rust trace engine (reads JSONL events)
├── example-trace.jsonl      Sample event log used by the Rust engine
├── README.md
├── CONTRIBUTING.md
└── SECURITY.md
```

The Python package is still named `open-agent-harness` and will be renamed to `actrun`. Please do not rely on the current import name in new documentation.

## Checks

CI runs the same commands. Please run them locally before opening a pull request.

```bash
# Python (from python/)
pytest

# Rust (from rust/trace-engine/)
cargo fmt --check
cargo clippy --all-targets
cargo test
```

Run `cargo fmt` to fix formatting automatically.

## Coding guidelines

**General**

- Keep the core small. A new dependency needs a justification in the pull request.
- Every behavior change comes with a test. Every bug fix comes with a regression test.
- Keep the core provider-neutral: no model-vendor-specific code in the runtime.

**Python**

- Python 3.10+ compatible.
- Type hints on all public functions and classes.
- The runtime is async-first.

**Rust**

- Stable toolchain. Code must pass `cargo fmt` and should be free of `clippy` warnings.
- Avoid `unsafe`. If you need it, explain why in a comment and in the pull request.

## Event schema changes

Events are written to JSONL and read by the Rust engine, so the event format is a versioned contract. A change to it must:

1. bump `schema_version`,
2. update `example-trace.jsonl`,
3. update the Rust trace engine and its tests,
4. be described in the pull request, including whether old logs remain readable.

## Documentation must not overclaim

ActRun's README separates what exists from what is planned. Keep it that way. Do not describe a planned feature as implemented, and mark design sketches as sketches. Contributions that blur this line will be asked to change.

## Commits and pull requests

- One logical change per pull request. Small pull requests are reviewed faster.
- Write commit messages in the imperative mood ("Add lease timeout"), and reference the related issue.
- Fill in the pull request template.
- This is a small project: reviews may take a few days.

## Security and data

- Never commit secrets, credentials, or real user data. This includes event logs and test fixtures.
- Report security vulnerabilities as described in [SECURITY.md](SECURITY.md), not in public issues.

## License

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).

## Code of conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
