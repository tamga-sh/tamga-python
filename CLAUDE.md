# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`tamga-python` is the official Python SDK for Tamga, a license-management API. It is one of the
eight SDKs in the Tamga family; this package re-implements the full validation and
cryptographic-verification surface natively in Python, with no FFI binding and no native build
step.

The authoritative wire-level protocol reference (endpoints, field names, enum values, and the
**Known Server-Side Gaps** section — read that before touching anything protocol-shaped) lives
in the server repository, which is private; there is no public URL to link.

**Repo status:** fully implemented and published. Every module under `src/tamga/` has real, tested
logic — client/transport, license validation/check-in/checkout, machine checkout/management/offline
proof, components/processes, entitlements, error model. Published on PyPI as `tamga-sdk` via
Trusted Publishing (OIDC); the importable package name is `tamga`. All three crypto-bearing areas
— license checkout, machine checkout, offline proof — have each passed a mandatory
`security-reviewer` pass; see "Security-reviewer history" under Critical Dependency Notes below for
the specific findings, since they aren't otherwise surfaced anywhere outside commit message bodies.

## Architecture

Pure Python, no Rust extension, no native build step. `hatchling` build backend, src-layout.
`cryptography` (pyca) supplies every crypto primitive (Ed25519, RSA-PKCS1/PSS, ECDSA-P256,
AES-256-GCM, HKDF); `httpx` supplies the HTTP transport.

```
src/tamga/
├── __init__.py         # public re-exports: TamgaClient, TamgaConfig, errors, __version__
├── py.typed             # PEP 561 marker
├── client.py             # TamgaClient façade + namespaced sub-clients (licenses/machines/
│                         #   components/processes/entitlements) + all endpoint methods
├── transport.py          # httpx wiring, 5 auth transports, header handling
├── proof.py               # offline proof payload build + verify
├── errors.py               # TamgaError hierarchy, JSON:API error envelope parsing
├── models/
│   ├── validation.py     # ValidationCode (24 members), ValidationMeta, ValidationResult
│   ├── license.py        # LicenseResource, LicenseScope, LicenseFileResource
│   ├── machine.py        # MachineResource, ComponentResource, ProcessResource, HeartbeatStatus
│   └── policy.py         # PolicyResource + policy-derived enums, Entitlement
├── crypto/
│   ├── ed25519.py         # Ed25519 verify (license checkout, one of 4 machine-checkout schemes)
│   ├── rsa.py              # RSA-PKCS1v15 + RSA-PSS verify (machine checkout, offline proof)
│   ├── ecdsa.py            # ECDSA-P256 verify (machine checkout)
│   ├── aes_gcm.py          # AES-256-GCM decrypt (both checkout flows)
│   └── hkdf.py              # HKDF-SHA256 key derivation (license file AND machine file)
└── checkout/
    ├── license_file.py    # .lic parse + verify pipeline (format v2, enforces signed exp)
    └── machine_file.py    # machine-file parse + multi-scheme verify pipeline
```

**Vertical-ish grouping, not one flat client.** `TamgaClient` exposes `.licenses`, `.machines`,
`.components`, `.processes`, `.entitlements` sub-clients instead of one giant method namespace —
mirrors the resource grouping in the Tamga API protocol specification, keep new endpoint methods on
the matching sub-client rather than bolting everything onto `TamgaClient` directly.

**Crypto stays out of `client.py`.** Signature verification and key derivation live under
`crypto/`, one primitive per file, so a security review can be scoped to exactly the files that
changed. `checkout/license_file.py` and `checkout/machine_file.py` orchestrate `crypto/` calls but
never implement a primitive inline.

## Dev Commands

This repo uses [`uv`](https://docs.astral.sh/uv/) for environment and dependency management.

```bash
uv sync --all-extras --dev   # install runtime + dev deps into .venv
uv run pytest                 # run tests
uv run pytest --cov=tamga --cov-fail-under=80 --cov-report=term-missing   # tests + coverage gate
uv run ruff check .            # lint
uv run ruff check --fix .       # lint, auto-fix
uv run ruff format .             # format
uv run ruff format --check .      # format check (CI mode, no writes)
uv run mypy src/                   # type check (strict mode — see pyproject.toml [tool.mypy])
uv build                            # build sdist + wheel
uv publish                           # manual/local publish — see "Release" below
```

There is no single `just check`-style umbrella command yet — CI runs each step above
individually; see `.github/workflows/ci.yml` for the exact order
(ruff check → ruff format --check → mypy → pytest+coverage).

## GOTCHAS

### This SDK's own crypto traps

- **Signing-message trap (license checkout).** The Ed25519 signature in a `.lic` file covers
  `enc`'s **base64 string bytes** (`enc.encode("ascii")`), not `base64.b64decode(enc)`. Getting
  this backwards makes every signature fail to verify even with the correct key and data. See
  `checkout/license_file.py`'s module docstring and the dedicated regression test that covers it.
- **Both file-encryption keys are HKDF-SHA256 (`crypto/hkdf.py`).** They differ only in salt and
  `info`: license file uses salt `tamga:license-file-key-v1` + `info` `license-file`; machine file
  uses salt `tamga:machine-file-key-v1` + `info` = the target machine's fingerprint. The old
  zero-pad/truncate license-file transform and the `crypto/naive_key.py` module that implemented
  it are **removed, not deprecated** — do not reintroduce either, and treat any doc or comment
  still describing a "naive"/non-KDF license-file key as stale.
- **Format v2 only (license checkout).** `alg` must be `base64+ed25519+v2` or
  `aes-256-gcm+ed25519+v2`; `LicenseFile.parse` rejects anything else, and `LicenseFile.verify`
  enforces the signed `meta.exp` claim with a 60s clock-skew tolerance. There is deliberately no
  v1 fallback — accepting a v1 file would restore the bug v2 exists to close (the requested TTL
  lived outside the signature, so a trial file was valid forever).
- **Byte-exact serialization (offline proof).** The RSA signature over an offline-proof payload
  covers `{"account":{...},"machine":{...},"dataset":...}` serialized in exactly that key order.
  Field *presence* matching isn't enough — reordering the same fields into valid-but-different JSON
  must produce a different signed message. Build via an explicitly ordered structure +
  `json.dumps(..., separators=(",", ":"))`, never rely on incidental dict-ordering.
- **`RSA_2048_JWT_RS256` is rejected, not unsupported-and-ignored.** Machine-checkout scheme
  dispatch must raise `SchemeNotSupportedError` for this scheme explicitly — don't let it fall
  through to a different verifier, and don't silently skip verification.
- **`pid` is a string on the wire.** `ProcessResource.pid` and `processes.create(..., pid=...)` are
  typed `str`, matching the server exactly. Reject `int` input at the call boundary; don't
  `str()`-coerce it — that hides a caller bug instead of surfacing it.
- **`"DENY_ACCESS"` / `"NO_RESURRECTION"` are not real enum variants.** Freshly-created policies
  report these as their `overage_strategy`/`heartbeat_resurrection_strategy` defaults, but neither
  string is a valid member of `OverageStrategy`/`HeartbeatResurrectionStrategy`. Both silently
  behave as `NO_OVERAGE`/`NO_REVIVE` server-side — `PolicyResource` parsing must apply that
  fallback, not trust the field name's implication that access is denied by default.

### Protocol-specification "Known Server-Side Gaps" that apply to this repo

Only the gaps relevant to this SDK's actual scope (license validation, checkout, machine
management, entitlements) are listed — see the Tamga API protocol specification for the full list,
including analytics/EE items that don't touch this package at all.

- **Auth is not enforced server-side on license/machine endpoints** (gap #3). Send
  `Authorization: License <key>` (or another transport) on every call anyway — it's
  forward-compatible for when enforcement lands, but don't build any test or example that asserts
  a *missing* credential gets rejected today; it won't be.
- **Only 14 of 24 `ValidationCode` values are reachable** (gap #4). Model all 24 in
  `ValidationCode` with a lenient unknown-value fallback, but don't write tests or docs implying
  the other 10 (`BANNED`, `ENTITLEMENTS_MISSING`, `TOO_MANY_USERS`, `HEARTBEAT_DEAD`,
  `HEARTBEAT_NOT_STARTED`, `FINGERPRINT_SCOPE_MISMATCH`, `COMPONENTS_SCOPE_MISMATCH`,
  `CHECKSUM_SCOPE_MISMATCH`, `VERSION_SCOPE_MISMATCH`, plus `NOT_FOUND` which comes back as a raw
  HTTP 404 instead) can currently occur.
- **`429` is live and handled client-side.** Credential-accepting endpoints run on a tight per-IP
  budget that a heartbeat timer reaches easily. `client.py`'s `_request_with_retry` retries while
  the server answers `429`, using `_retry_delay` (server `Retry-After` preferred but capped at
  60s, else jittered exponential backoff) and `_is_retryable` (every `GET`, plus exactly five
  `POST` actions: `validate`, `validate-key`, `check-in`, `check-out`, `ping`). Creates are
  deliberately excluded — retrying `POST /machines` risks burning a second seat. When the retry
  budget is spent the caller gets `errors.RateLimitedError` carrying `retry_after`. `X-RateLimit-*`
  response headers are still not set server-side, so `Retry-After` is the only server signal —
  don't build header parsing for the others.
- **`Tamga-Environment` header is not implemented** (gap #7). Don't add it to `transport.py`'s
  request headers even though it's documented as a planned EE feature — no server code path reads
  it yet.
- **`heartbeat_status` ignores `policy.heartbeat_duration`** (gap #8). The window is a hardcoded
  600s for machines regardless of what a license's policy declares. `HeartbeatScheduler`'s
  recommended interval (~200s) is sized against that hardcoded constant, not against
  `policy.heartbeat_duration` — don't wire the scheduler to read the policy value, it wouldn't
  matter server-side anyway.
- **RFC 9421 response signing is dead code** (gap #6) and the auto-update/release-check endpoint
  is unusable (Tamga API protocol specification §12). Neither is in this SDK's scope at all —
  there is no `releases` sub-client and none should be added until the server side is real.

## Testing

- Coverage gate: `--cov-fail-under=80`, enforced in CI via `pytest --cov=tamga --cov-fail-under=80`.
  Run the same command locally before opening a PR.
- Fixtures live in `tests/conftest.py` (mock-transport HTTP client, throwaway Ed25519/RSA/ECDSA
  keypairs) and `tests/fixtures/` (sample `.lic`/machine-file certificates, canned JSON:API error
  bodies) — reuse these rather than hand-rolling new keypairs or HTTP mocks per test file.
  `httpx.MockTransport` is a hard requirement for HTTP tests; do not spin up a real server or mock
  at the `requests` level.
- The three crypto-bearing areas — license checkout, machine checkout, offline proof — require a
  **mandatory, non-skippable** `security-reviewer` pass before merge. A `python-reviewer`-only pass
  is not sufficient for them.
- Golden-byte/known-answer tests matter more than structural-equality tests for the crypto paths —
  e.g. the offline-proof payload test must assert an exact expected byte string, and the HKDF
  derivation test must assert an exact 32-byte key for a fixed input, not just "produces 32 bytes".

## Critical Dependency Notes

- **`cryptography` (pyca) is the sole crypto dependency.** It wraps OpenSSL/BoringSSL under the
  hood and covers all four algorithm families this SDK needs (Ed25519, RSA, ECDSA, AES-GCM) plus
  HKDF. Do not add `pynacl`, `pycryptodome`, or any other crypto library as an alternate/backup for
  something `cryptography` already covers — that doubles the audit surface for no benefit.
- **`httpx`, not `requests`.** Async-capable, has first-class `MockTransport` support for tests,
  and is what `transport.py` and `tests/conftest.py` are built around. Don't introduce `requests`
  or `urllib3` calls anywhere in `src/tamga/`.
- **`mypy --strict`.** Every public function needs real type hints, not `Any` escape hatches,
  except where a value is genuinely opaque server-side (e.g. token strings — see the `tok-` prefix
  gotcha below).
- **mypy is pinned to `<2`.** mypy 2.0 dropped support for checking against `python_version =
  "3.9"` (our `[tool.mypy]` target, matching `requires-python`) — running `uv run mypy src/` with
  an unpinned/2.x mypy either errors outright or silently checks against the wrong Python version.
  Don't remove the `<2` pin without also bumping `requires-python` and the CI matrix's floor.
- **Every issued server token is `tok-`-prefixed regardless of documented type.** Do not build
  prefix-based token type detection into `transport.py`; treat all bearer tokens as opaque strings.

**Security-reviewer history (back-filled from commit messages — not previously surfaced here).**
License checkout, machine checkout, and offline proof have each undergone an independent
`security-reviewer` pass, all in commit `d0524d8`: license checkout approved with no findings;
machine checkout had 2 MEDIUM findings fixed (the `alg` field wasn't validated against a closed
vocabulary); offline proof had 1 HIGH finding fixed (`build_proof_payload` was missing
`ensure_ascii=False`, which would have silently diverged from the server's UTF-8 wire output for any
non-ASCII field value). All three fixes are live in the current code; this note exists so the review
trail is discoverable without archaeology through commit history.

## Release

`release-please` (config: `release-please-config.json`, manifest:
`.release-please-manifest.json`) tracks `pyproject.toml`'s `version` and
`src/tamga/__init__.py`'s `__version__` together, opening/updating a release PR with the generated
changelog on every push to `main`. Publishing to PyPI happens in the **same workflow run**, in a
`publish` job gated on the `release-please` job's `release_created` output, via
`pypa/gh-action-pypi-publish@release/v1` using **PyPI Trusted Publishing (OIDC)** — there is no
`PYPI_API_TOKEN` secret in this repo, and one should not be added. Do not "fix" that gating into
a separate `on: release: types: [published]` trigger: release-please creates the GitHub Release
with this workflow's own `GITHUB_TOKEN`, and GitHub's loop-prevention means such an event never
triggers another run (the reasoning is repeated in `release.yml` itself).

**Manual/local publish** (only if ever needed outside CI): `uv publish`, not `twine` — keep the
tooling consistent between CI and any manual escape hatch.

## Branch & Commit Convention

Branches: `feat/*`, `fix/*`, `chore/*`, `refactor/*`, `docs/*`
Commits: [Conventional Commits](https://www.conventionalcommits.org/) format (`feat: …`, `fix: …`,
etc.) — `release-please` parses these to compute the next version and changelog entry, so
non-conforming commit messages silently produce no release.
