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
│                         #   components/processes/entitlements/policies/releases) + all
│                         #   endpoint methods + the two heartbeat schedulers
├── transport.py          # httpx wiring, 5 auth transports, header handling, URL builders
├── proof.py               # offline proof payload build + verify
├── errors.py               # TamgaError hierarchy, JSON:API error envelope parsing
├── models/
│   ├── validation.py     # ValidationCode (24 members), ValidationMeta, ValidationResult
│   ├── license.py        # LicenseResource, LicenseScope, LicenseFileResource
│   ├── machine.py        # MachineResource, ComponentResource, ProcessResource, HeartbeatStatus
│   ├── policy.py         # PolicyResource + policy-derived enums, Entitlement
│   ├── release.py        # ReleaseResource (auto-update check)
│   ├── signing_key.py    # SigningKey — one published Ed25519 key, current or retired
│   └── health.py         # HealthStatus — NOT a JSON:API resource, see below
├── crypto/
│   ├── ed25519.py         # Ed25519 verify + `key_id` (the `kid` a signed offline file names)
│   ├── rsa.py              # RSA-PKCS1v15 + RSA-PSS verify (machine checkout, offline proof)
│   ├── ecdsa.py            # ECDSA-P256 verify (machine checkout)
│   ├── aes_gcm.py          # AES-256-GCM decrypt (both checkout flows)
│   └── hkdf.py              # HKDF-SHA256 key derivation (license file AND machine file)
└── checkout/
    ├── key_set.py         # SigningKeySet + kid selection (survives a signing-key rotation)
    ├── license_file.py    # .lic parse + verify pipeline (format v2, enforces signed exp)
    └── machine_file.py    # machine-file parse + multi-scheme verify pipeline
```

**Vertical-ish grouping, not one flat client.** `TamgaClient` exposes `.licenses`, `.machines`,
`.components`, `.processes`, `.entitlements`, `.policies`, `.releases`, `.accounts` sub-clients
instead of one giant method namespace —
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
- **Format v2 only — for BOTH file types.** License checkout: `alg` must be
  `base64+ed25519+v2` or `aes-256-gcm+ed25519+v2`. Machine checkout: `alg` must be
  `{base64|aes-256-gcm}+{ed25519|ecdsa-p256|rsa-sha256|rsa-pss-sha256}+v2` — eight values, and
  the `+v2` marker is mandatory there too. Both `parse`s reject anything else and both `verify`s
  enforce the signed `meta.exp` claim through the *same* `_enforce_expiry` and the *same*
  `CLOCK_SKEW_TOLERANCE_SECONDS` (60s); do not define a second constant, or the two file types
  silently drift to different grace periods. Machine-file expiry raises `MachineFileExpired`,
  a subclass of `LicenseFileExpired` so one `except` covers both. There is deliberately no v1
  fallback — accepting a v1 file would restore the bug v2 exists to close (the requested TTL
  lived outside the signature, so a trial file was valid forever). `exp` itself is optional: a
  checkout made without a `ttl` produces a file with no `exp` that never expires, and an absent
  claim is not an error.
- **`alg` parsing: split at the FIRST `+` and the LAST `+`.** The encoding prefix
  (`aes-256-gcm`) and two of the four signing suffixes (`rsa-pss-sha256`, `ecdsa-p256`) contain
  hyphens, and both bracket a `+v2` marker, so a fixed index or a `split_once`-then-compare gets
  it wrong. **The signing suffix cannot identify the scheme**: the server emits `rsa-sha256` for
  both `RSA_2048_PKCS1_SIGN` and `RSA_2048_JWT_RS256`. `scheme` comes from the license via an
  authenticated response and is authoritative; `alg` is only ever cross-checked against it.
- **An encrypted machine file's `enc` is `"<nonce_b64>.<cipher_b64>"`.** Two *separately*
  base64'd halves joined by a literal `.`; the ciphertext half already includes the 16-byte GCM
  tag. A `.lic` file is the other layout — one `base64(nonce ‖ ciphertext ‖ tag)` blob — so the
  two decryptors are not interchangeable, and the server's own doc comment on
  `machine_file.rs:59` describing the blob layout for machine files is **stale and wrong**
  (reported upstream as `tamga-api-internal#2`; trust the code at `:79-84`). Python hid this for
  two years: `base64.b64decode` silently drops the `.` and `nonce_b64` is always 16 chars — a
  whole number of 4-char blocks — so the single-blob decode happened to produce the same bytes.
  Decode each half strictly (`validate=True`) and check its length. Order is load-bearing:
  verify the signature, *then* split, *then* decode, *then* decrypt.
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
- **`check_in_interval` is adverbial (`daily`), never a noun (`day`).** `policies/enums.rs:27`
  lists `["daily","weekly","monthly","yearly"]` and the column's `CHECK` constraint
  (`migrations/20240101000005:153-155`) rejects everything else. This SDK shipped the noun
  spellings through 1.0.4 *and* constructed the enum strictly, so every policy with a cadence
  configured raised `ValueError` out of `licenses.get_policy` / `policies.get` — the whole policy
  read, not just the cadence. It stayed invisible because every test used a policy with
  `require_check_in=false` and a null column; the fixture at `tests/test_policy_read.py:44` now
  carries a real `"daily"` and there is a parametrized test over all four values. **Do not
  re-narrow `CheckInInterval` and do not move the leniency into `from_api`.** It lives in
  `CheckInInterval._missing_` so every construction path gets it, the noun spellings are aliases
  (`DAY is DAILY`) so 1.0.x call sites keep matching, and `_missing_` scans members rather than
  re-entering `cls(...)`, which would recurse forever on an unknown value. An unknown cadence
  raising is also deliberate: `check_in_interval=None` already means "no cadence configured", so
  softening to `None` (tamga-swift's `init(rawValue:)` behaviour) would report no schedule on a
  license that has one.
  **The server does not honour the field either.** `check_in_interval_days`
  (`validate_license.rs:394-403`) matches the noun spellings, so no storable value hits an arm and
  `_ => 30` always wins — every cadence is enforced as thirty days. `tamga-api-internal#3`.
  Independent of the SDK bug; fixing this side did not fix that one.
  **Still missing:** `check_in_interval_count` is emitted (`policies/serializer.rs:34`) and is the
  multiplier on the period — count 2 plus `weekly` is every two weeks — but `PolicyResource` does
  not model it, so the cadence this SDK exposes is only half the answer. Harmless while the server
  ignores both, load-bearing the day `tamga-api-internal#3` is fixed. Not in scope for 1.1.0;
  needs its own item.
- **`max_memory` / `max_disk` are write-only server-side, and are no longer `PolicyResource`
  fields.** The columns exist (`policies/model.rs:187-188`, `Option<i64>`) and validation enforces
  them (`allows_memory`/`allows_disk`), and `POST`/`PATCH /policies` accept them in the request
  body — but **no serializer emits them**. `PolicyAttributes` (`policies/serializer.rs:22-53`) is
  the only response shape for the resource and it carries `max_machines`/`max_cores` and stops.
  Grep confirms it: every other hit is a query, a request body, or a test. So a read-only client
  can never populate them, which is why the two fields carried "always `None`" docstrings for as
  long as they existed. Removed from the dataclass in 1.1.0.
  **Two things not to undo.** (1) `PolicyResource.__getattr__` is a deliberate deprecation shim:
  it returns `None` for exactly those two names with a `DeprecationWarning` and re-raises
  `AttributeError` for everything else, so a `^1.0` consumer that auto-upgrades into 1.1.0 and
  reads `policy.max_memory` gets the same `None` it always got instead of a crash. Delete it in
  2.0.0 — not before, and not as tidying. (2) It is defined under `if not TYPE_CHECKING:` on
  purpose. A type-checker-visible `__getattr__` makes mypy accept *any* attribute name on the
  class, which would erase this dataclass's whole reason to exist and would give a caller no
  signal at all until the shim vanished under them. Hidden, mypy reports
  `"PolicyResource" has no attribute "max_memory"` at the caller's own line today while the
  runtime keeps working — verified, along with the fact that typos like `max_machiens` are still
  caught. Do not "fix" the conditional into an unconditional definition, and do not add a
  `# type: ignore` to make it visible.
- **A `kid` hashes the base64 STRING, never the 32 decoded key bytes.** `key_id`
  (`crypto/ed25519.py`) mirrors the server's `shared/crypto/license_file.rs:70-77`: the first
  **eight bytes** of `SHA-256` over the public key's published base64 text, lowercase hex —
  sixteen characters, not eight. The server takes a `&str` and calls `.as_bytes()` on it, so
  decoding first gives a plausible-looking but wrong id. Same shape of trap as the signature
  covering `enc`'s base64 string. Pinned from **both** directions by
  `tests/fixtures/signing_keys/signing-key-ids.json`, which carries a negative vector
  (`905f28def18eaac0` correct, `630dcd2966c43366` if you decode first) — a test asserting only the
  positive does not catch it. Corroborated independently by all twelve server-generated fixtures
  in `tests/fixtures/machine_files/manifest.json`, whose `kid` reproduces from the
  `public_key_b64` beside it under the same rule, across all four signing schemes.
- **`key_id("") == "e3b0c44298fc1c14"` is a real, reachable condition, not a curiosity.** Both
  checkout handlers build the claim as
  `key_id(account.ed25519_public_key.as_deref().unwrap_or_default())` (`check_out_license.rs:95`,
  `check_out_machine.rs:127`), so an account whose column was never populated signs every file
  with that one id. It surfaces as `SigningKeyNotPublishedError`, a subclass of
  `UnknownSigningKeyError`, because the remedy differs: refetching the key set cannot help and
  somebody has to rotate the account's key server-side (which backfills the column). Do not fold
  it back into the generic unknown-key error.
- **Key-set selection verifies first and reads the `kid` last — do not invert it.** The claim
  lives *inside* the signed (and possibly encrypted) payload, so resolving by `kid` first would
  mean parsing attacker-supplied bytes before anything vouched for them, breaking the ordering
  rule `checkout/machine_file.py`'s module docstring states. `_resolve_signing_key` tries every
  candidate key against the signature, and reads the `kid` only once all have failed — purely to
  choose between `UnknownSigningKeyError` ("your set is stale") and `InvalidSignature` ("forged").
  The happy path never touches the payload unverified, and there is a test that fails if it ever
  does. ⚠️ `tamga-rust` resolves by `kid` first instead. Both reach the same verdict on every
  file, but do not "align" this one to that one: this ordering is the one that holds this SDK's
  own stated invariant, and it additionally tolerates a server that mislabelled a key (selection
  matches the published `kid` **or** the locally computed one, and `SigningKeySet.inconsistent_keys`
  reports the disagreement).
- **A machine file's `kid` is Ed25519-only, whatever signed the file.**
  `check_out_machine.rs:86-99` picks the signing key by the license's `scheme`, while `:125-129`
  computes the `kid` from `account.ed25519_public_key` unconditionally — so for an RSA- or
  ECDSA-signed machine file the claim names a key that had no part in the signature, and
  `/signing-keys` publishes Ed25519 keys only anyway (`signing_keys.rs` hardcodes `'ed25519'` in
  both of its inserts). `MachineFile.verify_with_key_set` therefore raises
  `SigningKeyNotApplicableError` for any recognized non-Ed25519 scheme, and `RSA_2048_JWT_RS256`
  still raises `SchemeNotSupportedError` ahead of it — rejected, never reclassified. `.lic` files
  are unaffected: always Ed25519-signed, so their `kid` always names their signing key.
- **Every new key-set failure is a `ValueError` subclass, and `InvalidSignature` still means
  forged.** `SigningKeyError(ValueError)` is the base, so a caller written as the documented
  `except (ValueError, LicenseFileExpired):` keeps catching every rejection — the same contract
  gap that was a HIGH finding when `data["id"]` leaked `KeyError` past it. "Signature is bad" stays
  `InvalidSignature` on the new entry points exactly as on the old ones; do not convert it.

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
- **Request-body shape is PER-ENDPOINT: some take a JSON:API envelope, some take a flat object.**
  Responses are enveloped throughout; requests are not, and there is no rule to infer either from.
  The only reliable source is the handler's own body struct.
  - **Enveloped** — `POST /machines` (`create_machine.rs`, reads
    `body.data.relationships.license.data.id`) and `PATCH /machines/{id}`
    (`update_machine.rs:16-26`, `UpdateMachineRequest { data: { type, attributes } }`).
  - **Flat** — `POST /components` (`create_component.rs:13-20`,
    `CreateComponentBody { machine_id, fingerprint, name, metadata }`) and `POST /processes`
    (`create_process.rs:13-19`, `CreateProcessBody { machine_id, pid, metadata }`). Only
    `metadata` carries `#[serde(default)]`, so an enveloped body fails deserialization on every
    other field and axum answers **422** — which is what this SDK did to both endpoints until
    `fix/component-process-request-shape`. (`application/vnd.api+json` is accepted by axum's
    `Json` extractor — its suffix is `json` — so the request reaches deserialization rather than
    being turned away as an unsupported media type. That is why the failure is 422 and not 415.)
  - **`meta`-wrapped** — `validate` (`{meta:{scope,skip_touch}}`), both check-outs
    (`{meta:{encrypt,ttl}}`), `generate-offline-proof` (`{meta:{dataset}}`); all optional bodies.
  - **Bare field** — `validate-key` (`ValidateKeyBody { key }`).

  `tests/test_request_wire_shapes.py` asserts the enveloped and flat cases side by side precisely
  so "normalize them to match" fails loudly. Never assert a request body with
  `body["data"]["attributes"][…]` lookups on a flat endpoint: that is how this bug survived — the
  test pinned the broken shape instead of catching it, the same way tamga-dotnet's fixtures hid
  the mirror-image defect on the *response* axis for the same two endpoints. Prefer whole-body
  equality, which cannot pass against an extra wrapper.
- **`GET /licenses/{id}/entitlements` cannot be paginated.** The listing unions direct and
  policy-inherited rows, so the server accepts `page[after]` and ignores it — every "next page"
  repeats the first. `entitlements.list` must send an explicit `limit` (the SDK sends the server
  max, 100), must never return a `next_after`, and `list_all` must be a single request. Looping
  here hangs the process. The listing tops out at 100 effective entitlements with no total count,
  so a negative `has_entitlement` is only authoritative below that ceiling. Entitlements carry an
  `inherited` flag, and `entitlements.get` resolves direct attachments only — it 404s for an
  inherited row, so list-then-get-each is not a valid pattern here.
  `/machines/{id}/components` and `/machines/{id}/processes` are different: keyset paging
  genuinely works on both, and the cursor reaches the query.
- **`GET /machines` is the one OFFSET-paginated route on this surface.** It takes `page[number]` /
  `page[size]` (aliases `page` / `limit`), `sort`, `order`, and the filters
  `filter[q|license|owner|group|platform]`, and answers with
  `meta.page{number,size,total,totalPages}` — note the lone camelCase key in an otherwise
  snake_case protocol. `machines.list` therefore returns `OffsetPage`, not `Page`: the keyset
  `Page` synthesizes its cursor from `len(items) == limit`, which is wrong here and is exactly the
  shape of the bug that made `list_all` loop forever. `page[after]` on this route is accepted and
  ignored, and so is a page number on a keyset route.
- **There is no exact fingerprint filter, and a machine carries no license id.**
  `filter[q]` is a substring `ILIKE` over `name`/`hostname`/`fingerprint`, truncated to 200
  characters, so `machines.find_by_fingerprint` narrows with it and then compares exactly in
  Python — both approximations run toward a superset, so it never returns the wrong machine.
  `license_id` is a **required** argument, not an optional narrowing: `MachineResource` serializes
  no `license_id` and no `relationships`, so `filter[license]` is the only thing scoping the
  result and there is nothing on the resource to verify it against — an unscoped hit is a row the
  caller cannot attribute. (`filter[license]` is genuinely applied, unlike `page[after]` on
  entitlements: `queries.rs:257` → `any_uuid("m.license_id", …)` → a bound `= ANY($n)` at
  `list_filter.rs:256-263`.) The scan is bounded three ways (`max_pages`, the server's
  `totalPages`, an empty page) and written as a `range`, not a `while`.
- **Never omit `limit` on a keyset list call.** The server defaults to 25 and exposes no `links`
  or `meta.page` there, so an omitted page size makes truncation indistinguishable from
  completion. Send `MAX_PAGE_SIZE` and derive the cursor from that known value. `machines.list`
  sends an explicit page size too, but for a different reason: `total` already makes truncation
  visible, so it is about predictability rather than detection.
- **`409 FINGERPRINT_TAKEN` is a re-activation, not a failure — *within one license*.** The
  server checks uniqueness *before* the quota limits precisely so a repeat activation reports the
  conflict rather than `MACHINE_LIMIT_EXCEEDED`; its comment reads "already activated, carry on".
  `machines.activate_machine_idempotent` catches it and recovers the machine via
  `find_by_fingerprint(..., license_id=...)`. Two rules on that path, both load-bearing:
  - **Never validate-and-roll-back.** `activate_machine` deletes the machine it created on an
    over-limit verdict; doing that to a pre-existing row would destroy a seat the caller never
    asked to touch.
  - **Never recover across licenses.** All three strategies' `EXISTS` checks
    (`service.rs:52-84`) include the caller's own license — `UNIQUE_PER_LICENSE` binds
    `license_id = $2`, `UNIQUE_PER_POLICY` joins `l.policy_id = $2` where `$2` is *this license's*
    policy (`create_machine.rs:88-102`), `UNIQUE_PER_ACCOUNT` covers the account — so a genuine
    same-license re-activation always conflicts and is always found by a license-scoped lookup.
    An empty lookup therefore means the conflict came from **another** license, and that machine
    is not ours to hand back: the client would heartbeat and check it out while this license's
    `machines_count` stayed at zero, which is the seat-sharing `service.rs:47-50` says the wider
    scopes exist to prevent, and the caller could not detect it because the resource carries no
    license id. Re-raise the conflict. (tamga-js ships the same behaviour; a divergence between
    two SDKs on one 409 is worse than either choice alone.)
- **Nothing reaps process rows.** `DELETE /processes/{id}` exists and returns `204`; no scheduled
  job calls anything equivalent, so a process that stops pinging holds its `max_processes` slot
  forever. `processes.delete` is the raw route and `ProcessHeartbeatScheduler.dispose` pairs it
  with `stop()` (tolerating an already-deleted row, propagating everything else) — `stop()` alone
  leaks the slot, which is the whole reason `dispose` exists.
- **The license read routes are not license-scoped.** `GET /licenses/{id}` and
  `GET /licenses/{id}/policy` call `LicensePolicy.require_read` and nothing else — no
  `require_license_scope` — so any authenticated license key reads every license in the account,
  `attributes.key` in plain text included. The SDK cannot fix it; it must not describe the surface
  as safe. Reported upstream.
- **`/v1/health` is the only route outside `/v1/accounts/{account_id}`.** It is on the
  public-route allowlist (`require_auth.rs:53`, pinned by the test at `:147`) and bypasses the
  `Host`-header allowlist (`host_auth.rs:23`), and its handler returns a **bare**
  `{status, version, uptime_secs}` — not a JSON:API document, so it must not go through
  `parse_response`'s envelope unwrap. `transport.build_root_url` builds the account-less origin;
  `TamgaClient.health` sends an absolute URL through the same client so it keeps the pool and the
  429 backoff. Diagnostic value: health succeeding while everything else 403s with "The Host
  header does not match any configured host" identifies a `TAMGA_ALLOWED_HOSTS` problem, not a bad
  token.
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
- **`GET /signing-keys` is unreachable with a license key, and an empty result is normal.**
  `accounts/policy.rs:16-18` gates it on `account.read`, which `Role::LicenseToken`'s fixed
  permission set does not contain (`shared/authz/mod.rs:241-267`) — and unlike `policies.get` /
  `licenses.get_policy` there is no second route serving the same resource under a permission it
  does hold. The embedded client doing offline verification is exactly the one that gets `403`, so
  `SigningKeySet.from_public_keys` (pin keys at build time) is the documented answer, not a
  fallback. Separately, `account_signing_keys` is written **only** by `rotate_ed25519`, which
  backfills the account's current key on its way through, so an account that has never rotated has
  no rows and the endpoint answers `{"data": []}` — a healthy account, not a failure. Retired keys
  **are** returned, newest first; that is the whole point of the route.
- **The signing-key resource `id` IS the `kid`, and `publicKey` is its one camelCase attribute.**
  `accounts/serializer.rs:119-123` sets `id: k.kid` with a comment saying exactly that, which is
  why a fetched key needs no local hashing — `key_id` is for the pinned/offline case and
  `SigningKey.kid_is_self_consistent` is a cross-check, not a requirement. `SigningKeyAttributes`
  (`:108-117`) is snake_case except for an explicit `#[serde(rename = "publicKey")]`, so it joins
  `productId` and the two file-resource bags on the short list of camelCase attributes; the
  spelling is pinned by `tests/fixtures/signing_keys/list_response.json`, whose keys were derived
  from the Rust struct rather than from this SDK's field names. `retired` is **absent, not null**,
  while a key is active (`skip_serializing_if`).
- **`Tamga-Environment` header is not implemented** (gap #7). Don't add it to `transport.py`'s
  request headers even though it's documented as a planned EE feature — no server code path reads
  it yet.
- **The heartbeat window comes from the policy, and the SDK now reads it.** It is
  `policy.heartbeat_duration`, falling back to 600s only when that column is unset — not a fixed
  constant. `HeartbeatScheduler`'s default ~200s interval is sized against the *fallback*; use
  `HeartbeatScheduler.for_policy(machines, machine_id, policy)` (window / 3, floored at 1s via
  `heartbeat_interval_for_policy`) with a policy from `licenses.get_policy(license_id)`.
  ⚠️ **Both schedulers now hold that floor themselves, so an interval passed by hand is not
  honoured verbatim below one second.** The rule, stated so no reader has to run it: a
  non-positive `interval` becomes the scheduler's recommended default (200s machine, 10s
  process) and a positive one below `MIN_HEARTBEAT_INTERVAL` is raised to one second.
  `timedelta(seconds=40)` stays 40s; `timedelta(milliseconds=500)` becomes 1s;
  `timedelta(microseconds=1)` becomes 1s; `timedelta(0)` and a negative become the default.
  Nothing raises. ⚠️ Do **not** "improve" this back into a guard on the non-positive case
  alone — that was the first shape it shipped in, and it was rejected on measurement.
  `time.sleep` *honours* a sub-second request, so there is no runtime threshold to key a
  narrower rule to: measured on CPython 3.13 a bare sleep loop turns ~1,368,000/sec at
  `sleep(0)`, ~163,000/sec at `sleep(0.000001)` and ~696/sec at `sleep(0.001)`, the last to
  within 1.4x of what was asked. A rule keyed to what the runtime refuses to honour clamps
  `timedelta(0)` and passes a positive interval issuing 163,000 authenticated pings a second;
  that describes where a number came from, not what it does. The floor costs nothing a policy
  can ask for, because `heartbeat_duration` is an integer-**seconds** column. ⚠️ **And liveness
  is judged on truncated whole seconds**, which is what makes the flat floor safe on a short
  window: `heartbeat_status_within` computes `(Utc::now() - hb_ts).num_seconds() <= window_secs`
  and `num_seconds()` truncates (`Duration::milliseconds(1999).num_seconds() == 1`), so a
  machine first reads `DEAD` at `window_secs + 1` seconds and every window carries one free
  second. Do **not** restate that as "DEAD once the age passes the window" — the pessimistic
  reading makes a 1s window look unserveable at a 1s ping when it has 2s of slack. What the
  floor does cost is `HEARTBEAT_PINGS_PER_WINDOW`'s two-loss promise on windows under 3s:
  `heartbeat_duration` 3 is where floor and divisor agree, 2 keeps one spare ping, 1 keeps none.
  The one window that cannot be held is `0` — and note that this SDK reaches that verdict by a
  different route than tamga-js, because `effective_heartbeat_window_seconds` treats a
  non-positive `heartbeat_duration` as unset while the server's own
  `COALESCE(p.heartbeat_duration, 600)` substitutes only for `NULL`. The whole table is pinned
  by value in `tests/test_policy_read.py`.
  **Route matters:** `GET /policies/{id}` authorizes on `policy.read`, which is *not* in the
  license-token permission set (`tamga-api/src/shared/authz/mod.rs:236-261`), so `policies.get`
  403s under license-key auth; `GET /licenses/{id}/policy` authorizes on `license.read`, which is,
  so `licenses.get_policy` works. Do not schedule off a response's `next_heartbeat_at`: it is
  computed from whichever window the answering query joined, so create / ping-heartbeat /
  reset-heartbeat / `PATCH /machines/{id}` all use the 600s fallback while `GET /machines/{id}`,
  the machine list, check-out and offline-proof use the policy — and nothing on the wire says
  which kind you are holding.
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
  the same way, but this SDK returns only a `ProofResult` from it. `machines.get` and
  `machines.list` are reads too and report it truthfully. `PATCH /machines/{id}` is the awkward
  middle case: it writes, but never to `last_heartbeat_at`, so it *can* say `DEAD` — except its
  `UPDATE ... RETURNING` does not join `policies`, so it judges against the 600s fallback.)
  `run_forever` used to
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
- **`204` from the upgrade check means two things, and the SDK must not collapse them.**
  `GET /releases/actions/upgrade` is a live `OptionalAuth` handler taking four **required** query
  params — `product`, `platform`, `filetype` (one word), `version` — plus optional `channel` and
  `constraint`. It answers `204 No Content` both when nothing newer exists
  (`upgrade_release.rs:62-63`) *and* when something newer exists that this license is not entitled
  to (`:92-100`); the server's own comment says a denial in the second case would leak "a newer
  release exists but you can't have it". `releases.check_for_upgrade` returns `None` for both and
  documents it as *no update is available to you*, never "you are up to date" — there is no
  client-side way to separate them and there should not be. A **suspended** license is a distinct
  `403` (`:77-81`), not an ambiguous `204`. The artifact download route exists too, though it is
  currently walled off by a permission gap. An older note here claimed the endpoint 500s and
  forbade building against it — that was wrong. RFC 9421 response signing genuinely is dead code.
- **Attribute CASING is per-resource, and `releases` is the one that bites.** Most attribute
  structs are snake_case; exactly 10 of the server's 67 carry `rename_all = "camelCase"`. Three are
  SDK-relevant:
  - `ReleaseAttributes` (`releases/serializer.rs:24`) — **`product_id` goes over the wire as
    `productId`.** `_parse_release_resource` reads it with a bare subscript, so getting this wrong
    is a `KeyError` on every real upgrade response, not a silently missing field.
  - `LicenseFileAttributes` (`licenses/serializer.rs:196`) and `MachineFileAttributes`
    (`machines/serializer.rs:136`) — also camelCase, but every field is a single word
    (`certificate`, `algorithm`, `includes`, `ttl`, `expiry`, `issued`), so it is invisible today.
    A multi-word field added to either would arrive camelCased.

  `MachineAttributes`, `PolicyAttributes`, `LicenseAttributes`, `ComponentAttributes` and
  `ProcessAttributes` are snake_case, so this cannot be applied as a blanket rule in either
  direction.

  **The exception inside the exception:** `ReleaseAttributes.created_at`/`updated_at` would become
  `createdAt`/`updatedAt` under `rename_all`, but each carries an explicit
  `#[serde(rename = "created")]` / `#[serde(rename = "updated")]` (`serializer.rs:41,43`), and an
  explicit rename overrides `rename_all`. They are `created`/`updated`, exactly like every other
  resource. Camel-casing them while fixing `productId` breaks two fields that are already right —
  `tests/test_releases_upgrade.py` fails in **both** directions on purpose.
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
- **A fixture written from this SDK's own field names proves nothing.** It encodes the same
  assumption the parser makes, so it agrees with the bug and disagrees with the server.
  `tests/fixtures/releases/upgrade_response.json` exists because the inline fixture it replaced
  spelled the owning product `product_id` — the *dataclass* field's name — while the server emits
  `productId`. The test passed; `check_for_upgrade` raised `KeyError` against every real response.
  Its keys are derived mechanically from the Rust struct, and the file records that provenance.
  This is the same rule as the next bullet, on the response-shape axis rather than the crypto one.
- **Never prove a wire format with a fixture this SDK generated.** `tests/fixtures/machine_files/`
  holds certificates produced by the *server's* `encode_machine_file`, indexed by a
  `manifest.json` that `tests/test_machine_file_fixtures.py` iterates — add a fixture by dropping
  the file and its manifest entry in, not by editing tests. Machine-file verification was broken
  in all eight SDKs for two years precisely because every repo round-tripped through its own
  encoder, so CI stayed green while nothing the server emitted could be opened. Self-signed
  certificates remain fine for *post-authentication* robustness tests (see
  `tests/test_checkout_hardening.py`) — a different question from "does the wire format match".
- **The signing-key vectors are third-party on purpose.**
  `tests/fixtures/signing_keys/signing-key-ids.json` was generated by an independent SHA-256
  implementation and confirmed against `tamga-rust`'s committed vector — not by this SDK, the same
  rule as `tests/fixtures/machine_files/`. Its `negative` entry pins the wrong answer as well as
  the right one; keep both assertions, because the positive alone does not catch a decode-first
  implementation. One provenance string in the upstream copy had the generating machine's `id(1)`
  output shell-substituted into it and was repaired on the way in; no vector value was touched.
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

**Second machine-checkout pass (machine-file v2, PR #25).** Re-reviewed after the v2/`+v2`,
dot-separated-`enc` and `meta.exp` work. No CRITICAL and no bypass: verification order, `alg`
handling (never selects a primitive), expiry enforcement, AES-GCM parameters and the 1 MiB
envelope cap all held under adversarial probing, and two suspected defects carried over from
sibling SDKs were **disproven here** — `cryptography`'s `load_der_public_key` accepts the server's
PKCS#1 `RSAPublicKey` DER as well as SPKI (both encodings really are reachable: `extract_public_key`
emits PKCS#1, `key_material.rs` stores SPKI on the account), and `ec.ECDSA(hashes.SHA256())` hashes
the message itself, so this SDK must pass raw `enc` bytes and **not** `SHA-256(enc)`. Both are now
pinned by tests in `tests/test_crypto_rsa.py`/`tests/test_crypto_ecdsa.py` so a port of the sibling
fixes fails loudly here instead of breaking verification. One HIGH was fixed: `data["id"]`,
`data["type"]` and a non-object `attributes`/`relationships` leaked `KeyError`/`TypeError`/
`AttributeError` past the documented `Raises: ValueError` on both `verify()`s — the license path
had no `isinstance(data, dict)` guard at all. Two LOWs were fixed: `LicenseFile.verify_with_claims`
decrypted the file a second time behind an `assert` that `python -O` strips (now one shared
`_verify`, mirroring `MachineFile`), and the `.lic` path decoded `enc` non-strictly (now the shared
`_envelope.b64decode_strict`, so neither file type can drift back to a lax decode). One LOW was
**not** fixed on purpose: a malformed `public_key` and a forged signature both surface as
`InvalidSignature`, because the crypto wrappers deliberately return a uniform "not valid" for
untrusted input rather than handing a caller — who may be the attacker — an oracle distinguishing
"your key is wrong" from "your signature is wrong".

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
