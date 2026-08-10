"""HKDF-SHA256 key derivation for machine checkout encryption.

Unlike license checkout's naive key derivation (``tamga.crypto.naive_key``),
machine checkout uses a proper KDF: HKDF-SHA256 with a fixed salt and the
machine's fingerprint as the ``info`` parameter, meaning decryption requires
**both** the license key and the target machine's fingerprint.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes  # noqa: F401
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: F401

MACHINE_FILE_KEY_SALT: bytes = b"tamga:machine-file-key-v1"
"""Fixed HKDF salt used by the server for machine-file encryption keys."""


def derive_machine_file_key(license_key: str, fingerprint: str) -> bytes:
    """Derive the AES-256 key used to decrypt an encrypted machine file.

    ``HKDF-SHA256(salt=MACHINE_FILE_KEY_SALT, ikm=license_key, info=fingerprint)``
    -> 32 bytes.

    Args:
        license_key: The license's raw key string (used as HKDF's ``ikm``).
        fingerprint: The target machine's fingerprint (used as HKDF's ``info``).

    Returns:
        A 32-byte AES key.
    """
    raise NotImplementedError
