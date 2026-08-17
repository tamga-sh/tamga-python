"""Cryptographic primitives backing offline license/machine verification.

All primitives are built on the ``cryptography`` package
(``cryptography.hazmat.primitives``) — no bespoke crypto implementations.
Each module wraps exactly one primitive so a security review can be scoped
to exactly the files that changed; any change under this package requires
such a review before merge (see ``CONTRIBUTING.md``).

``hkdf`` derives the AES-256 keys for **both** offline file types — the
license-file derivation is not a special case and is not a bare/naive
transform.
"""

from __future__ import annotations

from tamga.crypto.aes_gcm import decrypt as aes_gcm_decrypt
from tamga.crypto.ecdsa import verify_p256
from tamga.crypto.ed25519 import verify as ed25519_verify
from tamga.crypto.hkdf import derive_license_file_key, derive_machine_file_key
from tamga.crypto.rsa import verify_pkcs1v15, verify_pss

__all__ = [
    "aes_gcm_decrypt",
    "derive_license_file_key",
    "derive_machine_file_key",
    "ed25519_verify",
    "verify_p256",
    "verify_pkcs1v15",
    "verify_pss",
]
