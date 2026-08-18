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
- [`heartbeat_scheduler.py`](examples/heartbeat_scheduler.py) — machine (600s window) vs. process
  (30s window) heartbeat scheduling side by side.
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
`ECDSA_P256_SIGN`) via `src/tamga/checkout/machine_file.py::MachineFile.verify`, and they are not
part of the `+v2` `alg` vocabulary. `src/tamga/proof.py::ProofResult.verify` covers the lighter
air-gapped machine offline proof.

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
  to every `GET` plus exactly five `POST` actions — `validate`, `validate-key`, `check-in`,
  `check-out`, `ping` — because those are the calls a client makes on a timer. Creates are
  deliberately excluded: retrying `POST /machines` risks burning a second seat. Tune with
  `TamgaConfig(max_retries=...)`; `0` disables retries and the raised
  `tamga.errors.RateLimitedError` still carries `retry_after`.
- **Verification failures stay uniform inside a step.** A wrong key, a malformed key, and a
  tampered message all collapse to one `InvalidSignature`
  (`src/tamga/crypto/ed25519.py::verify`). The steps themselves remain distinguishable on
  purpose: `InvalidSignature` (not authentic), `InvalidTag` (authentic but decryption failed),
  `LicenseFileExpired` (authentic but expired), `ValueError` (malformed input that never reached
  a cryptographic operation).

Report suspected vulnerabilities privately to **security@tamga.sh** — see
[`SECURITY.md`](SECURITY.md).

## Known gaps

- **Sync only.** `TamgaClient` wraps `httpx.Client`; there is no async client yet.
- **No session-cookie transport.** Browser/portal only, out of scope here.
- **No `Tamga-Environment` header.** No server code path reads it yet, so the SDK does not send
  it.
- **No releases/auto-update sub-client.** The upgrade-check endpoint is not usable server-side.
- **`X-RateLimit-*` response headers are not sent.** `Retry-After` on a `429` is the only
  server-side rate-limit signal available (`src/tamga/transport.py::parse_retry_after`), and only
  its delta-seconds form is honored — the HTTP-date form is ignored rather than risking a date
  being misread as a duration.
- **10 of the 24 `ValidationCode` members are declared but never emitted today** (`BANNED`,
  `ENTITLEMENTS_MISSING`, `TOO_MANY_USERS`, `HEARTBEAT_DEAD`, `HEARTBEAT_NOT_STARTED`, the
  `FINGERPRINT`/`COMPONENTS`/`CHECKSUM`/`VERSION` scope mismatches, and `NOT_FOUND`, which comes
  back as a raw HTTP 404). Per-member reachability is documented in
  `src/tamga/models/validation.py`.
- **Only four `LicenseScope` fields are enforced server-side** — `product`, `policy`, `user`,
  `environment`. `entitlements`, `fingerprint`, `version`, and `checksum` are sent and silently
  ignored.
- **Pagination cursors are inferred.** `components.list`/`entitlements.list` return
  `next_after=None` unless you pass an explicit `limit`, because the server exposes no cursor
  metadata (`src/tamga/client.py::_next_after_cursor`).
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
