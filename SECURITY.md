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

### 1. License-file encryption key is intentionally not a KDF

`crypto/naive_key.py` derives the AES-256-GCM key for an encrypted `.lic` file from the license
key's raw UTF-8 bytes, zero-padded or truncated to exactly 32 bytes — **not** a hash, not PBKDF2,
not HKDF. This matches the server's own deliberately naive transform byte-for-byte; it is a
correctness requirement (interop with every license file the server has ever issued), not a
security recommendation from this SDK. The confidentiality of an encrypted `.lic` file is
therefore only as strong as the entropy of the license key string itself — a short or
low-entropy license key yields a weak encryption key. Contrast with machine-file encryption
(`crypto/hkdf.py`), which uses a real HKDF-SHA256 derivation.

### 2. Offline-proof signatures depend on byte-exact JSON serialization

`proof.py`'s `build_proof_payload` must reproduce the server's exact serialized bytes
(`{"account":...,"dataset":...,"machine":...}`, alphabetically key-ordered, `ensure_ascii=False`)
for signature verification to succeed. This is a correctness requirement, not a cryptographic
weakness, but it means a future change to this function's serialization (or a future change to
the server's `serde_json` configuration) could silently break verification for legitimate,
untampered proofs. See the module's docstring and `tests/test_offline_proof.py`'s golden-byte
tests, which act as a drift canary.

### 3. `RSA_2048_JWT_RS256` is explicitly rejected for machine-file verification

The server itself refuses to generate a machine file signed with this scheme
(`422 SCHEME_NOT_SUPPORTED`). This SDK's `MachineFile.verify` mirrors that rejection via a
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
when modifying this code (see `checkout/license_file.py`'s module docstring and the dedicated
regression test guarding it).

### 5. Verification failures are intentionally uniform

Signature/tag verification failures (wrong key, tampered data, wrong algorithm) all surface as
the same exception type/class rather than a failure-mode-specific error, to avoid giving an
attacker a signal useful for iteratively probing for valid inputs.

## Dependency posture

- `cryptography` (pyca) is the sole crypto dependency — it wraps OpenSSL/BoringSSL and covers
  every primitive this SDK needs. No alternate/backup crypto library (`pynacl`,
  `pycryptodome`, etc.) is used alongside it.
- `httpx` is the sole HTTP dependency. No `requests`/`urllib3` calls exist anywhere in
  `src/tamga/`.

## Supported versions

Security fixes are released against the latest minor version on the current major version line.
There is no long-term-support branch for older major versions at this time.
