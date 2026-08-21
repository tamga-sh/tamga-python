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
- **`MachineOverLimitError` inherits `ValueError` on purpose — never remove that base.**
  `activate_machine`'s two rejection paths originally raised a bare `ValueError`. Narrowing them
  to a typed error would have been breaking, so the exception subclasses `TamgaError` **and**
  `ValueError`: existing `except ValueError:` handlers keep catching it, and it also becomes
  reachable through the `except TamgaError:` convention this SDK documents everywhere. The MRO is
  `MachineOverLimitError -> TamgaError -> ValueError -> Exception`, which resolves cleanly because
  both bases descend from `Exception` independently. Dropping `ValueError` in a later "tidy-up"
  would silently break callers; `test_over_limit_error_is_still_caught_by_a_bare_value_error_handler`
  and `test_over_limit_error_mro_keeps_both_bases_reachable` exist to stop that and must not be
  deleted. Carry `validation_code` (the equivalent `ValidationCode`) and `rolled_back` (`False` =
  refused at create, nothing to delete; `True` = created under a permissive overage strategy, then
  deleted) on it. Note the mixed signal this resolves: the offline parsers in `checkout/` and
  `proof.py` raise plain `ValueError` for malformed input, where "fail closed" is the right
  handling — an over-limit rejection must not land in that same bucket.
- **`pid` is a string on the wire.** `ProcessResource.pid` and `processes.create(..., pid=...)` are
  typed `str`, matching the server exactly. Reject `int` input at the call boundary; don't
  `str()`-coerce it — that hides a caller bug instead of surfacing it.
- **`memory` and `disk` are megabytes, not bytes.** The server's `machines` table documents the
  unit explicitly, and those columns feed the license's `machines_memory_count` /
  `machines_disk_count` totals that create-time and validate-time limit checks compare against.
  A caller reporting 16 GB as `17179869184` inflates the license total by ~1e6 and trips
  `MEMORY_LIMIT_EXCEEDED` on the next activation. Never document these as bytes.
- **`"DENY_ACCESS"` / `"NO_RESURRECTION"` are not real enum variants.** Freshly-created policies
  report these as their `overage_strategy`/`heartbeat_resurrection_strategy` defaults, but neither
  string is a valid member of `OverageStrategy`/`HeartbeatResurrectionStrategy`. Both silently
  behave as `NO_OVERAGE`/`NO_REVIVE` server-side — `PolicyResource` parsing must apply that
  fallback, not trust the field name's implication that access is denied by default.

### Server behaviour this SDK has to match

Verified against the server source. Where an older note in this file said otherwise, the note was
wrong — these replace it.

- **Auth IS enforced.** License-key auth (`Authorization: License <key>`, and the `license:<key>`
  Basic sub-form) is only accepted when the license's policy sets `authentication_strategy` to
  `LICENSE` or `MIXED`. The column defaults to `TOKEN`, and `NONE` behaves identically at that
  gate, so the server answers `401 LICENSE_NOT_ALLOWED` (`errors.LicenseNotAllowedError`) until
  someone turns license-key auth on. Treat that as a configuration precondition, never as a
  retryable auth failure. Likewise `expiration_strategy: REVOKE_ACCESS` stops an expired license
  from authenticating at all (`401 LICENSE_EXPIRED`); the other three strategies still
  authenticate it and report expiry via the validation `meta.code`.
- **16 of 24 `ValidationCode` values are reachable.** Model all 24 with the lenient
  unknown-value fallback. `ENTITLEMENTS_MISSING` and `FINGERPRINT_SCOPE_MISMATCH` are now
  genuinely emitted — `scope.entitlements` and `scope.fingerprint` are enforced (codes compared
  case-insensitively and de-duplicated, satisfied by policy-inherited entitlements too; the
  fingerprint matches any machine on the license regardless of heartbeat status). Still
  unreachable: `BANNED`, `TOO_MANY_USERS`, `HEARTBEAT_DEAD`, `HEARTBEAT_NOT_STARTED`,
  `COMPONENTS_SCOPE_MISMATCH`, `NOT_FOUND` (raw HTTP 404 instead), and
  `CHECKSUM_SCOPE_MISMATCH`/`VERSION_SCOPE_MISMATCH` — the latter two because those scope keys are
  *rejected* rather than evaluated (see below).
- **`scope.version` / `scope.checksum` are rejected, not ignored.** The server fails the whole
  validate call with `422 SCOPE_NOT_SUPPORTED` (pointer `/meta/scope`) the moment either key is
  present, before any validation runs — the caller gets no `meta.valid` at all. `_scope_to_dict`
  therefore does not emit them. Keep the fields on `LicenseScope` (removing a public field is
  breaking) and keep them out of the request.
- **Machine creation enforces limits.** `POST /machines` checks machines/cores/memory/disk through
  the policy's overage strategy *before* inserting, returning `422 MACHINE_LIMIT_EXCEEDED` /
  `CORE_LIMIT_EXCEEDED` / `MEMORY_LIMIT_EXCEEDED` / `DISK_LIMIT_EXCEEDED`. Under a permissive
  overage strategy the create still succeeds and the limit only surfaces at validate. Both paths
  must stay in `activate_machine`: create-time 422 raises without a rollback DELETE (no row
  exists), validate-time over-limit deletes the row first. The uniqueness pre-check runs before
  the limit checks, so a duplicate fingerprint always yields `409 FINGERPRINT_TAKEN`.
- **`GET /licenses/{id}/entitlements` cannot be paginated.** The listing unions direct and
  policy-inherited rows, so the server accepts `page[after]` and ignores it — every "next page"
  repeats the first. `entitlements.list` must send an explicit `limit` (the SDK sends the server
  max, 100), must never return a `next_after`, and `list_all` must be a single request. Looping
  here hangs the process. The listing tops out at 100 effective entitlements with no total count,
  so a negative `has_entitlement` is only authoritative below that ceiling. Entitlements carry an
  `inherited` flag, and `entitlements.get` resolves direct attachments only — it 404s for an
  inherited row, so list-then-get-each is not a valid pattern here.
  `/machines/{id}/components` is different: keyset paging genuinely works there.
- **Never omit `limit` on a list call.** The server defaults to 25 and exposes no `links` or
  `meta.page`, so an omitted page size makes truncation indistinguishable from completion. Send
  `MAX_PAGE_SIZE` and derive the cursor from that known value.
- **`429` is live and handled client-side.** The limiter buckets per `(caller, route pattern)`,
  and with proxy headers untrusted every caller shares one bucket per route — a fleet throttles
  itself on exactly the calls it makes on a timer. `client.py`'s `_request_with_retry` retries
  while the server answers `429`, using `_retry_delay` (server `Retry-After` preferred but capped
  at 60s, else jittered exponential backoff) and `_is_retryable` (every `GET`, plus seven `POST`
  actions: `validate`, `validate-key`, `check-in`, `check-out`, `ping`, `ping-heartbeat`,
  `reset-heartbeat`). Note `/actions/ping-heartbeat` does **not** end with `/actions/ping` — that
  suffix matches only the process route — so it needs its own entry; leaving it out silently
  dropped the machine heartbeat under throttling. Both heartbeat writes are bare idempotent
  `UPDATE`s, so repeating them is safe. Creates stay excluded — retrying `POST /machines` risks
  burning a second seat. When the retry budget is spent the caller gets `errors.RateLimitedError`
  carrying `retry_after`.
- **`Tamga-Environment` header is not implemented** (gap #7). Don't add it to `transport.py`'s
  request headers even though it's documented as a planned EE feature — no server code path reads
  it yet.
- **The heartbeat window comes from the policy.** It is `policy.heartbeat_duration`, falling back
  to 600s only when that column is unset — not a fixed constant. `HeartbeatScheduler`'s default
  ~200s interval is sized against the *fallback*, so a policy with a shorter window needs an
  explicit interval. Do not schedule off the ping response's `next_heartbeat_at`: that code path
  does not join the policy. Reading the policy-correct value needs `GET /machines/{id}` or
  `GET /licenses/{id}/policy`, neither of which this SDK exposes yet.
- **The heartbeat loop must not stop on any status.** State the rule as the general one:
  `HeartbeatScheduler.run_forever` pings until `stop()`, until the runtime cancels it, or until
  the ping raises. It reads nothing off the response to decide whether to continue. Do not
  reintroduce a status-based stop condition in any form. The only terminal signal is a `404` from
  the ping, which propagates to the caller for re-activation.
- **Whether `heartbeat_status` can say `DEAD` depends on whether the server wrote or read.** A
  response the server built off a write it just performed cannot: `ping-heartbeat` writes
  `last_heartbeat_at = NOW()` and derives the status from that same timestamp (age ~0 → always
  `ALIVE` or `RESURRECTED`), `reset-heartbeat` nulls it (`NOT_STARTED`), `POST /machines` never
  sets it (`NOT_STARTED`), and validation never emits `HEARTBEAT_DEAD`. **Machine checkout is a
  read** — it resolves the row by id, with the policy joined and nothing just written — so the
  status inside the signed machine-file payload is a genuine staleness verdict and can be `DEAD`.
  This repo surfaces it: `checkout/machine_file.py` parses `heartbeat_status` (leniently, with a
  `NOT_STARTED` fallback for unrecognized values) onto the `MachineResource` that
  `MachineFile.verify` returns. So the enum member is live, not forward-compatibility ballast —
  never delete it or the `heartbeat_status` field. (`generate_offline_proof` resolves the machine
  the same way, but this SDK returns only a `ProofResult` from it. `GET /machines/{id}` and the
  machine list would also report it; neither is exposed yet — M11/M36.) `run_forever` used to
  `break` on a `DEAD` response: unreachable on the ping route, and catastrophic if it ever had
  fired, since the break was permanent with nothing to restart the loop. A `DEAD` reading from
  *any* source still means only "last ping older than the window", never "row deleted" —
  `require_heartbeat` defaults to `false`, so a default policy culls nothing and the next ping
  revives the machine anyway.
- **`reset_heartbeat` and `generate_offline_proof` always 403 under license-key auth.** Both are
  gated on the caller's *role* (admin / developer / product token / environment token), not just a
  permission, and a `LicenseToken` holds none of them — even though it does hold
  `machine.proofs.generate`. `ping_heartbeat` is permission-only and works. Document the 403;
  don't present `reset_heartbeat` to an embedded license-key client as a recovery tool.
- **`quick_validate` skips its write when an `Origin` header is present.** The server suppresses
  the `last_validated_at` update on any quick-validate request carrying `Origin`, and the response
  is byte-identical either way. This SDK never sends `Origin` — keep it that way, and never add
  it to a non-cookie transport. When the write must happen, use `POST validate`
  (`validate_by_id`), which has no `Origin` branch.
- **The auto-update / upgrade-check endpoint works.** `GET /releases/actions/upgrade` routes to a
  live, public handler: `204 No Content` when already current, otherwise a `releases` resource.
  The artifact download route exists too, though it is currently walled off by a permission gap.
  The old note here claimed the endpoint 500s and forbade building against it — that was wrong.
  There is still no `releases` sub-client (out of scope for this release, not impossible), and
  RFC 9421 response signing genuinely is dead code.
- **`http://` hosts are preserved.** `build_base_url` upgrades a bare host to `https` but keeps an
  explicit `http://` scheme — a self-hosted deployment may serve plain HTTP, and rewriting the
  scheme made it unreachable with no useful diagnostic.
- **The default timeout is 45s, above the server's own 30s.** At an equal 30s the two race and a
  slow request surfaces as a local timeout with no `X-Request-Id`, instead of the server's `504`,
  which carries one.

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
