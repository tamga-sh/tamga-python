# tamga-sdk

[![PyPI version](https://img.shields.io/pypi/v/tamga-sdk.svg)](https://pypi.org/project/tamga-sdk/)
[![CI](https://github.com/tamga-sh/tamga-python/actions/workflows/ci.yml/badge.svg)](https://github.com/tamga-sh/tamga-python/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/tamga-sh/tamga-python/branch/main/graph/badge.svg)](https://codecov.io/gh/tamga-sh/tamga-python)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Official Python SDK for Tamga. Integrate license activation, offline verification, and machine
management into your Python applications.

Pure Python — no Rust extension, no native build step. Every cryptographic primitive (Ed25519,
RSA-PKCS1/PSS, ECDSA-P256, AES-256-GCM, HKDF-SHA256) comes from the
[`cryptography`](https://cryptography.io/) package; HTTP transport is
[`httpx`](https://www.python-httpx.org/).

## Install

```bash
pip install tamga-sdk
```

Requires Python 3.9+. The distribution is named `tamga-sdk` (the bare `tamga` name on PyPI
belongs to an unrelated logging library); the **importable package is `tamga`**:

```python
import tamga
```

## Quickstart

```python
from tamga import TamgaClient, TamgaConfig
from tamga.transport import LicenseAuth

config = TamgaConfig(
    account_id="your-account-id",
    host="api.tamga.sh",
    default_auth=LicenseAuth(key="YOUR-LICENSE-KEY"),
)

with TamgaClient(config) as client:
    result = client.licenses.validate_by_key("YOUR-LICENSE-KEY")

    if result.meta.valid:
        print("License is valid:", result.meta.code.value)
    else:
        print("License is not valid:", result.meta.code.value, result.meta.detail)
```

`result.meta.code` is a `ValidationCode` enum member (`VALID`, `EXPIRED`, `SUSPENDED`,
`TOO_MANY_MACHINES`, …). An unrecognized code from a newer server deserializes to
`ValidationCode.UNKNOWN` instead of raising.

Runnable end-to-end scripts live in [`examples/`](examples/):

- [`validate_license.py`](examples/validate_license.py) — validate by key, by ID with a scope, and
  the lightweight quick-validate `GET`.
- [`checkout_and_verify.py`](examples/checkout_and_verify.py) — offline `.lic` checkout, plain and
  encrypted, through the full verify pipeline.
- [`machine_activation_flow.py`](examples/machine_activation_flow.py) — create machine → validate
  → roll back on over-limit.
- [`heartbeat_scheduler.py`](examples/heartbeat_scheduler.py) — machine (window read from the
  policy, 600s only as a fallback) vs. process (30s window) heartbeat scheduling side by side,
  including disposing of the process row afterwards.
- [`offline_proof.py`](examples/offline_proof.py) — air-gapped machine proof generation and
  verification.

## Auth transports

Four of the server's five transports are modeled (`src/tamga/transport.py::apply_auth`).
Session-cookie auth is browser/portal-only — it requires a matching `Origin` header and is
deliberately out of scope for a non-browser SDK.

```python
from tamga import TamgaConfig
from tamga.transport import BasicAuth, BearerAuth, LicenseAuth, QueryParamAuth

# 1. Bearer token
TamgaConfig(account_id="...", host="api.tamga.sh", default_auth=BearerAuth(token="tok-..."))

# 2. HTTP Basic — three sub-forms
TamgaConfig(
    account_id="...",
    host="api.tamga.sh",
    default_auth=BasicAuth(email="you@example.com", password="..."),
)
TamgaConfig(account_id="...", host="api.tamga.sh", default_auth=BasicAuth(token="tok-..."))
TamgaConfig(account_id="...", host="api.tamga.sh", default_auth=BasicAuth(license_key="..."))

# 3. License key — the primary transport for embedded/client apps
TamgaConfig(account_id="...", host="api.tamga.sh", default_auth=LicenseAuth(key="YOUR-KEY"))

# 4. Query parameter
TamgaConfig(account_id="...", host="api.tamga.sh", default_auth=QueryParamAuth(value="tok-..."))
```

Every issued token carries a `tok-` prefix regardless of its documented type — treat tokens as
opaque strings and do not build prefix-based type detection.

`licenses.validate_by_key(key)` falls back to `Authorization: License <key>` for the key being
validated when no `default_auth` is configured, since it already holds the credential
(`src/tamga/client.py::LicensesClient.validate_by_key`).

**License-key auth must be enabled on the policy.** `Authorization: License <key>` (and the
`license:<key>` Basic sub-form) is only accepted when the license's policy sets
`authentication_strategy` to `"LICENSE"` or `"MIXED"`. That column defaults to `"TOKEN"`, and
`"NONE"` behaves the same way at the auth gate — under either the server answers
`401 LICENSE_NOT_ALLOWED`, raised as `tamga.errors.LicenseNotAllowedError`. That is a
configuration precondition to fix on the policy, not a transient failure: retrying the same key
never succeeds, and it does not mean the key is wrong. Separately, a policy with
`expiration_strategy: "REVOKE_ACCESS"` stops an expired license from authenticating at all
(`401 LICENSE_EXPIRED`); the other three expiration strategies still authenticate it and report
expiry through the validation result instead.

The host may be given with an explicit `http://` scheme for a self-hosted or local deployment —
it is preserved, not silently upgraded. A bare host defaults to `https`.

## Activating a machine and keeping it alive

```python
from tamga.client import HeartbeatScheduler

with TamgaClient(config) as client:
    # Idempotent: a repeat activation of the same fingerprint returns the
    # machine that already exists instead of raising `409 FINGERPRINT_TAKEN`.
    machine = client.machines.activate_machine_idempotent(license_id, fingerprint)

    # Size the ping interval from the policy that actually sets the window.
    # 600s is only what the server falls back to when `heartbeat_duration` is
    # unset — a 120s policy needs a 40s ping, not the 200s default.
    policy = client.licenses.get_policy(license_id)
    HeartbeatScheduler.for_policy(client.machines, machine.id, policy).run_forever()
```

Read the policy through `licenses.get_policy(license_id)`, not `policies.get(policy_id)`: the
former is gated on `license.read`, which a license key holds; the latter on `policy.read`, which
it does not, so it answers `403` under license-key auth.

`machines.get(machine_id)` is the read path where `heartbeat_status` is a genuine staleness
verdict — the ping/reset/create routes each derive the status from a timestamp they just wrote, so
they can never report `DEAD`. `DEAD` still never means the row was culled; only a `404` from the
ping does.

A process is the mirror image, because nothing on the server reaps process rows:

```python
from tamga.client import ProcessHeartbeatScheduler

with TamgaClient(config) as client:
    process = client.processes.create(machine.id, pid=str(os.getpid()))
    # `dispose` on exit stops the loop *and* deletes the row, freeing its slot
    # against `policy.max_processes` — `stop()` alone would leak it.
    with ProcessHeartbeatScheduler(client.processes, process.id) as scheduler:
        scheduler.run_forever()
```

## Checking for updates

```python
with TamgaClient(config) as client:
    release = client.releases.check_for_upgrade(
        product_id=product_id,
        platform="darwin-arm64",
        filetype="dmg",
        version=__version__,
    )

if release is None:
    # NOT "you are up to date". The server answers `204 No Content` both when
    # nothing newer exists and when something newer exists that this license is
    # not entitled to, deliberately, so that a denial cannot leak the latter.
    print("No update is available to you.")
else:
    print("Update available:", release.version)
```

## Diagnosing a misconfigured deployment

```python
with TamgaClient(config) as client:
    print(client.health())
```

`GET /v1/health` is the one route outside `/v1/accounts/{account_id}`, and it is exempt both from
the auth gate and from the server's `Host`-header allowlist. So if every other call fails with
`403` and *"The Host header does not match any configured host"* while this one succeeds, the
problem is the server's `TAMGA_ALLOWED_HOSTS` configuration — not the caller's credential. If this
one fails too, the server is unreachable and no credential would have helped.

## Offline verification

`.lic` license files and machine files verify entirely offline once the account's public key is
embedded in your application — no network round-trip per check.

```python
from tamga.checkout.license_file import LicenseFile, LicenseFileExpired

# The account's raw 32-byte Ed25519 public key, embedded in your application.
ACCOUNT_PUBLIC_KEY = b"...32 bytes..."

with TamgaClient(config) as client:
    checkout = client.licenses.check_out(license_id, ttl=86_400)
    assert not isinstance(checkout, bytes)  # the POST variant returns a LicenseFileResource

    license_file = LicenseFile.parse(checkout.certificate)
    try:
        license_resource = license_file.verify(ACCOUNT_PUBLIC_KEY)
    except LicenseFileExpired as exc:
        print("license file expired at unix timestamp", exc.exp)
    else:
        print("verified:", license_resource.id)
```

Pass `as_bytes=True` to use the `GET` variant instead, which returns the raw `.lic` bytes with no
surrounding metadata. For an encrypted checkout, supply the license key so the AES key can be
derived, and use `verify_with_claims` when you want the signed `jti` (replay detection) or `kid`
(key rotation):

```python
encrypted = client.licenses.check_out(license_id, encrypt=True, ttl=86_400)
assert not isinstance(encrypted, bytes)

license_resource, claims = LicenseFile.parse(encrypted.certificate).verify_with_claims(
    ACCOUNT_PUBLIC_KEY,
    license_key="YOUR-LICENSE-KEY",
)
print(claims.iat, claims.exp, claims.jti, claims.kid)
```

> ⚠️ **Compatibility break: license files must be format v2.** `alg` must be
> `base64+ed25519+v2` or `aes-256-gcm+ed25519+v2`; every v1-issued `.lic` file is rejected with a
> `ValueError` and **there is no fallback path**
> (`src/tamga/checkout/license_file.py::LicenseFile.parse`). If you hold v1 files, re-check them
> out against a v2 server. In v1 the requested `ttl`/`expiry` lived only in the JSON:API envelope
> *around* the certificate, so a 24-hour trial file stayed cryptographically valid forever;
> accepting both formats would hand that behavior back.

Machine files use the same `{enc, sig, alg}` envelope but dispatch signature verification on the
license's own `scheme` (`ED25519_SIGN`, `RSA_2048_PKCS1_SIGN`, `RSA_2048_PKCS1_PSS_SIGN`,
`ECDSA_P256_SIGN`) via `src/tamga/checkout/machine_file.py::MachineFile.verify`.

```python
from tamga.checkout import MachineFile
from tamga.checkout.machine_file import MachineFileExpired
from tamga.models.policy import LicenseScheme

machine_file = MachineFile.parse(certificate)
try:
    machine, claims = machine_file.verify_with_claims(
        ACCOUNT_PUBLIC_KEY,
        LicenseScheme.ED25519_SIGN,  # from the license, never from the file's own `alg`
        license_key="YOUR-LICENSE-KEY",  # encrypted files only
        fingerprint=THIS_MACHINE_FINGERPRINT,  # encrypted files only
    )
except MachineFileExpired as exc:
    ...  # authentic but lapsed -> check out a fresh one; `exc.exp` says when
print(machine.heartbeat_status, claims.jti, claims.kid)
```

Machine files are format v2 as well:

- **`alg` carries the mandatory `+v2` suffix** — `base64+ed25519+v2`,
  `aes-256-gcm+rsa-pss-sha256+v2`, and the six other combinations of encoding prefix and signing
  suffix. A file without it is rejected with no fallback, for the same reason a v1 `.lic` is.
- **`meta.exp` is enforced**, sharing `CLOCK_SKEW_TOLERANCE_SECONDS` with the `.lic` path and
  raising `MachineFileExpired` — a subclass of `LicenseFileExpired`, so one `except` clause covers
  both file types. `exp` is optional by design: a checkout made without a `ttl` produces a file
  that genuinely never expires. Pass `verify(..., now=<server-supplied timestamp>)` when
  defending against a rewound clock.
- **An encrypted machine file's `enc` is `"<nonce_b64>.<cipher_b64>"`** — two *separately*
  base64-encoded halves, not the single `base64(nonce ‖ ciphertext ‖ tag)` blob a `.lic` uses.
  The signature covers the whole `enc` string, so verification happens before the split.

`src/tamga/proof.py::ProofResult.verify` covers the lighter air-gapped machine offline proof.

## Security notes

- **Both offline-file AES keys are HKDF-SHA256 derived.** License file:
  `salt = "tamga:license-file-key-v1"`, `ikm = the license key`, `info = "license-file"`
  (`src/tamga/crypto/hkdf.py::derive_license_file_key`). Machine file: `salt =
  "tamga:machine-file-key-v1"`, `ikm = the license key`, `info = the machine's fingerprint`
  (`src/tamga/crypto/hkdf.py::derive_machine_file_key`), so a machine file only decrypts on the
  machine it was issued for. The former zero-pad/truncate license-file transform was **removed,
  not deprecated** — the module that implemented it no longer exists.
- **Signed expiry is enforced, not advisory.** Format v2 moves `iat`/`exp`/`jti`/`kid` inside the
  signed bytes, and `src/tamga/checkout/license_file.py::LicenseFile.verify` rejects an expired
  file with `LicenseFileExpired` using a deliberately small 60-second clock-skew tolerance
  (`CLOCK_SKEW_TOLERANCE_SECONDS`). The client's clock is under the attacker's control, so pass
  `verify(..., now=<server-supplied timestamp>)` if you are defending against a rewound clock.
  `LicenseFile.is_expired()` reads the *unsigned* `expiry` metadata and is advisory only.
- **Signatures cover `enc`'s base64 string, not its decoded bytes.** Both file types sign
  `enc.encode("ascii")` (`src/tamga/checkout/license_file.py::LicenseFile.verify`). It is the
  easiest thing to get backwards when reimplementing verification.
- **`scheme` must come from an authenticated response.** Feed
  `MachineFile.verify(..., scheme=...)` from the license's own `scheme` field, never from the
  certificate's own `alg` string — `alg` sits in the unsigned outer envelope and is not covered
  by the signature (`src/tamga/checkout/machine_file.py`, module docstring). `RSA_2048_JWT_RS256`
  is rejected up front with `SchemeNotSupportedError`, never falling through to another verifier.
- **HTTP 429 is live and handled.** `src/tamga/client.py::_request_with_retry` retries while the
  server answers `429`. `src/tamga/client.py::_retry_delay` prefers the server's `Retry-After`
  but caps it at 60s, otherwise using jittered exponential backoff so a fleet does not reconverge
  into the spike it was backing off from. `src/tamga/client.py::_is_retryable` scopes auto-retry
  to every `GET` plus exactly seven `POST` actions — `validate`, `validate-key`, `check-in`,
  `check-out`, `ping`, `ping-heartbeat`, `reset-heartbeat` — because those are the calls a client
  makes on a timer. (`ping-heartbeat` does **not** end with `/actions/ping`; that suffix matches
  only the process route, so it needs its own entry.) Creates are
  deliberately excluded: retrying `POST /machines` risks burning a second seat. Tune with
  `TamgaConfig(max_retries=...)`; `0` disables retries and the raised
  `tamga.errors.RateLimitedError` still carries `retry_after`.
- **The license read routes are not scoped to the calling license.** `licenses.get(license_id)`
  and `licenses.get_policy(license_id)` reach `GET /licenses/{id}` and
  `GET /licenses/{id}/policy`, which authorize on the `license.read` permission and the account
  resolved from the bearer — and on nothing else. Any license key that authenticates can therefore
  read *every* license in the same account, including each one's `attributes.key` in plain text.
  Both methods are exposed because reading your own policy is how the heartbeat window is
  discovered at all, but do not mistake the surface for a scoped one: never embed a license key in
  a context where an attacker recovering it should not also be able to enumerate the account's
  other keys. This is server-side behaviour the SDK cannot fix; it has been reported upstream.
- **Verification failures stay uniform inside a step.** A wrong key, a malformed key, and a
  tampered message all collapse to one `InvalidSignature`
  (`src/tamga/crypto/ed25519.py::verify`). The steps themselves remain distinguishable on
  purpose: `InvalidSignature` (not authentic), `InvalidTag` (authentic but decryption failed),
  `LicenseFileExpired` (authentic but expired), `ValueError` (malformed input that never reached
  a cryptographic operation).
- **`except TamgaError:` catches everything raised against the server.** That includes
  `MachineOverLimitError` from `activate_machine`, which reports a licence at its machine / core /
  memory / disk limit. It also subclasses `ValueError`, deliberately and permanently, because both
  activation rejection paths used to raise a bare `ValueError` — so existing `except ValueError:`
  handlers keep working. Do not confuse it with the plain `ValueError`s above: those come from the
  *offline* parsers and mean "this input is malformed", where failing closed is correct. An
  over-limit rejection means the server said no, and carries `validation_code` plus a
  `rolled_back` flag saying whether a machine row was created and then deleted.

Report suspected vulnerabilities privately to **security@tamga.sh** — see
[`SECURITY.md`](SECURITY.md).

## Known gaps

- **Sync only.** `TamgaClient` wraps `httpx.Client`; there is no async client yet.
- **No session-cookie transport.** Browser/portal only, out of scope here.
- **No `Tamga-Environment` header.** No server code path reads it yet, so the SDK does not send
  it.
- **`204` from the upgrade check has two meanings, and no client can tell them apart.**
  `releases.check_for_upgrade` returns `None` both when nothing newer exists *and* when something
  newer exists that this license is not entitled to. That is deliberate server-side — a denial
  would leak "a newer version exists but you can't have it" — so report `None` as *no update is
  available to you*, never as "you are up to date". A suspended license is a separate `403`.
- **There is no exact fingerprint filter on `GET /machines`.** The server offers
  `filter[license|owner|group|platform]` and a free-text `filter[q]`, and `filter[q]` is a
  case-insensitive substring match across `name`, `hostname` *and* `fingerprint`, truncated to 200
  characters. `machines.find_by_fingerprint` therefore narrows with the search and then compares
  exactly client-side; both approximations run toward a superset, so it never returns a machine
  with a different fingerprint, but it costs a scan rather than a lookup.
- **A listed machine cannot be attributed to a license.** The machine resource carries no
  `license_id` and no `relationships` object, so `filter[license]` on `machines.list` is the only
  way to tie machines to a license. That matters for re-activation recovery: under
  `UNIQUE_PER_POLICY` or `UNIQUE_PER_ACCOUNT` the machine behind a `409 FINGERPRINT_TAKEN` may
  sit on a *different* license, which is why `find_by_fingerprint` searches account-wide by
  default.
- **`GET /policies/{id}` always fails under license-key auth.** It authorizes on the `policy.read`
  permission, which is not in the license-token permission set. Read the policy through
  `licenses.get_policy(license_id)` instead — same resource, but a route gated on `license.read`,
  which a license credential does hold. `policies.get` exists for callers holding a privileged
  token.
- **The license read routes are not scoped to the calling license.** `GET /licenses/{id}` and
  `GET /licenses/{id}/policy` authorize on `license.read` and the account resolved from the
  bearer, and nothing further — so any license key that authenticates can read every license in
  the same account, `attributes.key` included, in plain text. Server-side behaviour this SDK
  cannot fix and does not work around; reported upstream.
- **`policy.max_memory` and `policy.max_disk` are always `None`.** The server omits both from the
  policy response even though it enforces them, so the only way to observe either limit is a
  `TOO_MUCH_MEMORY` / `TOO_MUCH_DISK` validation code.
- **`machines.update` cannot clear a field.** Every column is applied through
  `COALESCE(new, existing)` server-side, so an omitted or `None` field means "leave alone", never
  "set to null". Its response also judges `heartbeat_status`/`next_heartbeat_at` against the 600s
  fallback rather than the policy window — that query does not join `policies`. Read the machine
  back with `machines.get` when either field matters.
- **Whether `heartbeat_status` can say `DEAD` depends on whether the server wrote or read.** The
  write-shaped routes preclude it by construction: a heartbeat ping reports the timestamp it just
  wrote (always `ALIVE` or `RESURRECTED`), a reset nulls it (`NOT_STARTED`), and a create never
  sets it (`NOT_STARTED`). The read paths do not, so `machines.get`, `machines.list` and machine
  checkout all carry a genuine staleness verdict. `PATCH` sits between the two: it writes, but
  never to `last_heartbeat_at`, so it *can* report `DEAD` — just judged against the 600s fallback,
  since that query does not join the policy. A `DEAD` reading still never means the row was
  deleted, so it is information rather than a stop condition: `HeartbeatScheduler` stops for no
  status at all — only `stop()`, cancellation, or a `404` from the ping (the row is gone —
  re-activate) ends the loop.
- **Nothing reaps process rows server-side.** The 30s process window exists but no scheduled job
  acts on it, so a process that merely stops pinging holds its slot against `policy.max_processes`
  forever. Deleting it is the application's job: call `processes.delete`, or use
  `ProcessHeartbeatScheduler.dispose` (or the scheduler as a context manager), which stops the
  loop and deletes the row together.
- **`reset_heartbeat` and `generate_offline_proof` always fail under license-key auth.** Both are
  role-gated (admin / developer / product token / environment token), so a license key gets `403`
  every time. `ping_heartbeat` is permission-only and works.
- **`X-RateLimit-*` response headers are not surfaced.** `Retry-After` on a `429` is the only
  rate-limit signal this SDK reads (`src/tamga/transport.py::parse_retry_after`), and only its
  delta-seconds form is honored — the HTTP-date form is ignored rather than risking a date being
  misread as a duration.
- **8 of the 24 `ValidationCode` members are declared but never emitted today** (`BANNED`,
  `TOO_MANY_USERS`, `HEARTBEAT_DEAD`, `HEARTBEAT_NOT_STARTED`, `COMPONENTS_SCOPE_MISMATCH`,
  `NOT_FOUND` — which comes back as a raw HTTP 404 — and the `CHECKSUM`/`VERSION` scope
  mismatches, whose scope keys are rejected outright rather than evaluated). Per-member
  reachability is documented in `src/tamga/models/validation.py`.
- **Six `LicenseScope` fields are enforced** — `product`, `policy`, `user`, `environment`,
  `entitlements`, and `fingerprint`. `version` and `checksum` are **not** ignored: sending either
  makes the server reject the entire validate call with `422 SCOPE_NOT_SUPPORTED`, so this SDK
  deprecates them and does not put them on the wire.
- **License entitlements cannot be paginated.** The server ignores `page[after]` on
  `/licenses/{id}/entitlements` (the listing unions direct and policy-inherited rows), so
  `entitlements.list` always returns `next_after=None` and `list_all` is a single request capped
  at 100 rows. A license with more than 100 effective entitlements cannot be enumerated in full,
  which makes a negative `has_entitlement` authoritative only below that ceiling.
  `components.list` is genuinely keyset-paginated and does page to completion.
- **`quick_validate` records nothing if the request carries an `Origin` header.** The server skips
  the `last_validated_at` write and returns a byte-identical response, so a proxy that injects
  `Origin` silently disables it. This SDK never sends `Origin`; use `validate_by_id` when the
  write matters.
- **No CLI.** The package ships a library only.

## Documentation

- [tamga.sh](https://tamga.sh) — product documentation and the account console.
- [`SECURITY.md`](SECURITY.md) — the crypto assumptions an integrator is trusting, and how to
  report a vulnerability.
- [`CLAUDE.md`](CLAUDE.md) — dense, gotcha-first architecture/crypto reference for anyone
  modifying this codebase.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup, test/lint/type-check commands, PR
  expectations.
- Every public symbol carries a Google-style docstring; `help(tamga.TamgaClient)` and your IDE
  are the API reference until a generated docs site lands.

## License

MIT — see [LICENSE](LICENSE).
