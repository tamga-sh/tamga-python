"""AES-256-GCM decryption.

Shared by both checkout flows. Both keys come from ``tamga.crypto.hkdf``,
differing only in salt and ``info``; the decrypt operation itself is identical
either way.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes) -> bytes:
    """Decrypt an AES-256-GCM ciphertext.

    Args:
        key: 32-byte AES key.
        nonce: 12-byte nonce.
        ciphertext_and_tag: Ciphertext with the 16-byte GCM tag appended, as
            produced by the server (``ciphertext ‖ tag``).

    Returns:
        The decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If the tag doesn't verify (wrong
            key, corrupted/tampered data, or wrong nonce).
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
