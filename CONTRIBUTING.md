# Contributing to tamga-python

## Dev setup

This repo uses [`uv`](https://docs.astral.sh/uv/) for environment and dependency management.

```bash
uv sync --all-extras --dev   # install runtime + dev deps into .venv
```

## Commands

There is no single `just check`-style umbrella command yet — run each step individually, in the
order CI runs them (`.github/workflows/ci.yml`):

```bash
uv run ruff check .                                                        # lint
uv run ruff format --check .                                                # format check
uv run mypy src/                                                              # type check (strict)
uv run pytest --cov=tamga --cov-fail-under=80 --cov-report=term-missing        # tests + coverage
```

Auto-fix locally before committing:

```bash
uv run ruff check --fix .
uv run ruff format .
```

## Test-driven development

Write the test in the same task as the implementation, not after — the section-by-section task
breakdown lives in `docs/plans/tamga-python.plan.md` in the sibling `tamga-sdk` workspace, one
directory up, not inside this repo. Fixtures live in `tests/conftest.py` (mock-transport HTTP client via
`httpx.MockTransport`, throwaway Ed25519/RSA/ECDSA keypairs) — reuse these rather than
hand-rolling new ones per test file.

Golden-byte/known-answer tests matter more than structural-equality tests for the crypto paths —
e.g. the offline-proof payload test asserts an exact expected byte string, and the HKDF
derivation test asserts an exact 32-byte key for a fixed input, not just "produces 32 bytes".

## Crypto changes require a security review

Any change touching `src/tamga/crypto/`, `src/tamga/checkout/`, or `src/tamga/proof.py` requires
a `security-reviewer` pass before merge — a general code-quality review alone is not sufficient.
See Section 4 (Quality Gates) of `docs/plans/tamga-python.plan.md` in the sibling `tamga-sdk`
workspace, and [`SECURITY.md`](SECURITY.md) for the specific assumptions those files encode.

## Pull request expectations

- Conventional Commits format (`feat: …`, `fix: …`, `docs: …`, etc.) — `release-please` parses
  commit history directly to compute the next version and generate `CHANGELOG.md`; a
  non-conforming commit type can silently skip a release.
- Required checks before requesting review (these are also what CI enforces — see
  `.github/workflows/ci.yml`): `ruff check`, `ruff format --check`, `mypy src/`, and
  `pytest --cov=tamga --cov-fail-under=80` all passing. Branch protection on `main` should require
  all of these plus the full Python version matrix (3.9–3.13) before merge.
- Keep PRs scoped to one plan section (or one bug/feature) where practical — crypto-bearing
  sections in particular should not be batched with unrelated changes, so a security review can
  stay scoped to exactly the files that changed.

## Branch & commit convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`.

## Release

Handled by CI (`release-please` + PyPI Trusted Publishing) — see [`CLAUDE.md`](CLAUDE.md)'s
"Release" section. Manual/local publish, if ever needed: `uv build && uv publish` (not `twine`).
