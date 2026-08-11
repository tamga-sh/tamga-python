# tamga-python

[![PyPI version](https://img.shields.io/pypi/v/tamga-sdk.svg)](https://pypi.org/project/tamga-sdk/)
[![CI](https://github.com/tamga-sh/tamga-python/actions/workflows/ci.yml/badge.svg)](https://github.com/tamga-sh/tamga-python/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/tamga-sh/tamga-python/branch/main/graph/badge.svg)](https://codecov.io/gh/tamga-sh/tamga-python)

Official Python SDK for Tamga. Integrate license activation, offline verification, and machine
management into your Python applications.

Pure Python — no Rust extension, no native build step. Every cryptographic primitive (Ed25519,
RSA-PKCS1/PSS, ECDSA-P256, AES-256-GCM, HKDF) is implemented natively via the
[`cryptography`](https://cryptography.io/) package; HTTP transport is [`httpx`](https://www.python-httpx.org/).

## Install

```bash
pip install tamga-sdk
```

Published to [PyPI](https://pypi.org/project/tamga-sdk/) as `tamga-sdk` (the bare `tamga` name is
taken by an unrelated logging library); the importable package name is `tamga`.

## Quickstart

```python
from tamga import TamgaClient, TamgaConfig

client = TamgaClient(
    TamgaConfig(account_id="your-account-id", host="api.tamga.sh"),
)

result = client.licenses.validate_by_key("YOUR-LICENSE-KEY")

if result.meta.valid:
    print("License is valid:", result.meta.code)
else:
    print("License is not valid:", result.meta.code, result.meta.detail)
```

More examples in [`examples/`](examples/):

- [`validate_license.py`](examples/validate_license.py) — validate by key and by ID with a scope.
- [`checkout_and_verify.py`](examples/checkout_and_verify.py) — offline `.lic` checkout, plain and
  encrypted, full verify pipeline.
- [`machine_activation_flow.py`](examples/machine_activation_flow.py) — create machine → validate
  → handle over-limit rollback.
- [`heartbeat_scheduler.py`](examples/heartbeat_scheduler.py) — machine (600s window) vs. process
  (30s window) heartbeat scheduling side by side.
- [`offline_proof.py`](examples/offline_proof.py) — air-gapped machine proof generation +
  verification.

## Auth transports

The SDK supports 4 of the server's 5 documented auth transports (session-cookie auth is
browser/portal-only and out of scope for a non-browser SDK):

```python
from tamga.transport import BasicAuth, BearerAuth, LicenseAuth, QueryParamAuth

# 1. Bearer token (SDK default when default_auth is set to one)
TamgaConfig(account_id="...", host="...", default_auth=BearerAuth(token="tok-..."))

# 2. HTTP Basic — three sub-forms
TamgaConfig(
    account_id="...", host="...", default_auth=BasicAuth(email="you@example.com", password="...")
)
TamgaConfig(account_id="...", host="...", default_auth=BasicAuth(token="tok-..."))
TamgaConfig(account_id="...", host="...", default_auth=BasicAuth(license_key="..."))

# 3. License key — the primary transport for embedded/client apps
TamgaConfig(account_id="...", host="...", default_auth=LicenseAuth(key="YOUR-LICENSE-KEY"))

# 4. Query parameter
TamgaConfig(account_id="...", host="...", default_auth=QueryParamAuth(value="tok-..."))
```

`licenses.validate_by_key(key)` always sends `Authorization: License <key>` for the key being
validated, regardless of `default_auth`, since it already has the credential in hand.

## Offline verification

`.lic` license files and machine files can be verified fully offline once the account's public
key is embedded in your application — no network round-trip required on every check:

```python
from tamga.checkout.license_file import LicenseFile

certificate = client.licenses.check_out(license_id, as_bytes=True)
license_file = LicenseFile.parse(certificate.decode())
license_resource = license_file.verify(public_key=YOUR_ED25519_PUBLIC_KEY_BYTES)
```

See [`examples/checkout_and_verify.py`](examples/checkout_and_verify.py) for the full flow,
including encrypted checkout.

## What this SDK does not do

Per `tamga-api`'s [Known Server-Side Gaps](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md#known-server-side-gaps):
no client-side rate-limit/backoff handling (the server never returns `429`), no
`Tamga-Environment` header, no release/auto-update checking (`GET /releases/actions/upgrade` is
unusable server-side today). See [`CLAUDE.md`](CLAUDE.md) for the full gotcha list.

## Documentation

- [tamga-api `docs/sdk.md`](https://github.com/tamga-sh/tamga-api/blob/main/docs/sdk.md) — the
  authoritative wire-level protocol reference this SDK implements against, including the
  **Known Server-Side Gaps** section describing which documented features are not yet live
  server-side.
- [`CLAUDE.md`](CLAUDE.md) — dense, gotcha-first architecture/crypto reference for anyone
  modifying this codebase.
- [`SECURITY.md`](SECURITY.md) — the crypto assumptions an integrator is trusting, and how to
  report a vulnerability.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup, test/lint/type-check commands, PR
  expectations.

<!-- TODO: a generated API reference site (mkdocs) is deferred post-v1. -->

## License

MIT — see [LICENSE](LICENSE).
