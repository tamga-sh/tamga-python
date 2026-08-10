"""Naive (non-KDF) key derivation for license checkout encryption.

⚠️ **This is intentionally not a real key derivation function.** The server
derives the AES-256-GCM key for encrypted ``.lic`` files from the license
key's raw UTF-8 bytes, zero-padded or truncated to exactly 32 bytes — not a
hash, not HKDF, not PBKDF2. Do not "fix" this into a real KDF: a verifier
must byte-for-byte replicate the server's naive transform or decryption will
fail against every license file the server has ever issued.

Contrast with ``tamga.crypto.hkdf``, which machine checkout uses instead —
that one *is* a proper KDF (HKDF-SHA256).
"""

from __future__ import annotations

AES_KEY_LENGTH: int = 32
"""Target key length in bytes for AES-256."""


def derive_license_file_key(license_key: str) -> bytes:
    """Derive the AES-256 key used to decrypt an encrypted license file.

    Takes ``license_key``'s raw UTF-8 bytes and zero-pads (if shorter than
    32 bytes) or truncates (if longer) to exactly 32 bytes. This is **not**
    a cryptographic hash or KDF — do not replace this implementation with
    one, even though that would look more "correct". It must match the
    server's exact naive transform byte-for-byte.

    Args:
        license_key: The license's raw key string.

    Returns:
        Exactly 32 bytes, derived by zero-padding or truncating the UTF-8
        encoding of ``license_key``.
    """
    key_bytes = license_key.encode("utf-8")
    padded = bytearray(AES_KEY_LENGTH)
    length = min(len(key_bytes), AES_KEY_LENGTH)
    padded[:length] = key_bytes[:length]
    return bytes(padded)
