# Security Policy

## Reporting a vulnerability

Please report suspected security vulnerabilities privately — do not open a public GitHub issue.
Email **security@tamga.sh** with a description of the issue, reproduction steps if available, and
the affected version. We aim to acknowledge reports within 3 business days.

## Crypto assumptions an integrator is trusting

This SDK reimplements the full offline-verification surface natively (via the
[`cryptography`](https://cryptography.io/) package), rather than binding to a shared C library.
Anyone embedding this SDK is implicitly trusting the following design decisions — read this
before relying on offline verification for anything security-sensitive:

### 1. Both offline file encryption keys are HKDF-SHA256 derived

Both derivations live in `src/tamga/crypto/hkdf.py` and are HKDF-SHA256 with a 32-byte output:

| File | Function | salt | ikm | info |
|---|---|---|---|---|
| `.lic` license file | `src/tamga/crypto/hkdf.py::derive_license_file_key` | `tamga:license-file-key-v1` | the license key | `license-file` |
| machine file | `src/tamga/crypto/hkdf.py::derive_machine_file_key` | `tamga:machine-file-key-v1` | the license key | the machine's fingerprint |

The license-file derivation used to be the license key's raw UTF-8 bytes zero-padded or
truncated to 32 — no hash, no KDF. That transform has been **removed, not deprecated**: the
module that implemented it no longer exists, so no caller can silently keep using the weaker
derivation. A stolen `.lic` under the old scheme was a dictionary attack against the license
key's own entropy rather than a 256-bit key space.

Because the machine-file `info` is the target machine's fingerprint, a machine file cannot be
decrypted anywhere but on the machine it was issued for. A license file is not bound to a
machine and uses a fixed `info`.

Both derivations still take the license key as `ikm`, so an encrypted file's confidentiality
remains bounded by that key's entropy — HKDF removes the trivial cleartext-in-the-key problem,
it does not add entropy that was never there.

### 1b. Offline license files must be format v2, and `exp` is enforced

`src/tamga/checkout/license_file.py::LicenseFile.parse` accepts exactly two `alg` values —
`base64+ed25519+v2` and `aes-256-gcm+ed25519+v2`. Anything else, including every v1-issued
file, is rejected with a `ValueError`. **There is no fallback path**, so a caller holding a
v1 `.lic` file must re-check-out against a v2 server.

The reason is not cosmetic. In v1 the requested `ttl`/`expiry` lived only in the JSON:API
envelope *around* the certificate, never inside the signed bytes, so a 24-hour trial file
stayed cryptographically valid forever — the holder simply kept (or redistributed) the raw
certificate. v2 moves `iat`/`exp`/`jti`/`kid` inside the signature
(`src/tamga/checkout/license_file.py::LicenseFileClaims`), and
`src/tamga/checkout/license_file.py::LicenseFile.verify` **enforces** `exp` via
`_enforce_expiry` with a deliberately small 60-second clock-skew tolerance
(`CLOCK_SKEW_TOLERANCE_SECONDS`). The client's clock is under the attacker's control, so a
generous allowance would just be a free extension on every expired file; pass a
server-supplied timestamp as `verify(..., now=...)` if you are defending against a user
winding their clock back.

An expired-but-authentic file raises `LicenseFileExpired`, deliberately distinct from a
signature failure — see item 5.

`LicenseFile.is_expired()` checks the *unsigned* `expiry` metadata a `POST` checkout echoes
back. It is advisory only; the signed `exp` above is the enforced one.

### 2. Offline-proof signatures depend on byte-exact JSON serialization

`src/tamga/proof.py::build_proof_payload` must reproduce the server's exact serialized bytes
(`{"account":...,"dataset":...,"machine":...}`, alphabetically key-ordered, `ensure_ascii=False`)
for signature verification to succeed. This is a correctness requirement, not a cryptographic
weakness, but it means a future change to this function's serialization (or a future change to
the server's `serde_json` configuration) could silently break verification for legitimate,
untampered proofs. See the module's docstring and `tests/test_offline_proof.py`'s golden-byte
tests, which act as a drift canary.

### 3. `RSA_2048_JWT_RS256` is explicitly rejected for machine-file verification

The server itself refuses to generate a machine file signed with this scheme
(`422 SCHEME_NOT_SUPPORTED`). This SDK's
`src/tamga/checkout/machine_file.py::MachineFile.verify` mirrors that rejection via a
dedicated `SchemeNotSupportedError`, raised *before* any parsing or cryptographic operation is
attempted — it never falls through to a different verifier. Do not attempt to bypass this by
manually constructing a verification call with a different scheme than what the license actually
declares; `scheme` must always come from an authenticated API response (the license's own
`scheme` field), never from the certificate being verified itself (which is not covered by its
own signature).

### 4. Signature coverage is `enc`'s base64 string, not its decoded bytes

Both `.lic` and machine-file signatures cover the ASCII/UTF-8 bytes of the `enc` field's base64
**string** — not the bytes obtained by decoding it. This is a wire-format detail, not a
weakening of the signature scheme itself, but it is the single easiest thing to get backwards
when modifying this code (see `src/tamga/checkout/license_file.py`'s module docstring and the
dedicated regression test guarding it).

### 5. Verification failures are uniform *within* a step, not across all of them

Inside signature verification, every failure mode collapses to one answer: a wrong key, a
malformed key or signature, and a tampered message all make
`src/tamga/crypto/ed25519.py::verify` (and its RSA/ECDSA siblings) return `False`, which the
callers turn into a single `cryptography.exceptions.InvalidSignature`. No failure-mode-specific
signal is exposed for an attacker to probe against.

The steps themselves stay distinguishable on purpose, because a caller has to react differently
to each:

- `cryptography.exceptions.InvalidSignature` — the file is not authentic.
- `cryptography.exceptions.InvalidTag` — the signature verified, but AES-256-GCM decryption
  failed (wrong license key, or corrupted ciphertext).
- `tamga.checkout.license_file.LicenseFileExpired` — authentic, decrypted, but past its signed
  `exp`. A caller that cannot tell "expired" from "forged" either warns the user about tampering
  when their trial merely ended, or treats a forgery as a renewal prompt.
- `ValueError` — malformed input that never reached a cryptographic operation (bad PEM markers,
  bad base64/JSON, an `alg` outside the accepted set, a payload missing its signed `meta`).

## Dependency posture

- `cryptography` (pyca) is the sole crypto dependency — it wraps OpenSSL/BoringSSL and covers
  every primitive this SDK needs. No alternate/backup crypto library (`pynacl`,
  `pycryptodome`, etc.) is used alongside it.
- `httpx` is the sole HTTP dependency. No `requests`/`urllib3` calls exist anywhere in
  `src/tamga/`.

## Supported versions

Security fixes are released against the latest minor version on the current major version line.
There is no long-term-support branch for older major versions at this time.
