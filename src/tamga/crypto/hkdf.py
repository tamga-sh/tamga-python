"""HKDF-SHA256 key derivation for both offline file types.

Machine checkout always used a proper KDF. License checkout did not: before
file format v2, the AES key was the license key's raw UTF-8 bytes zero-padded
to 32. That meant an attacker holding a stolen ``.lic`` was not attacking a
256-bit key space but the license key's own entropy — a dictionary attack
against the AEAD tag on a ``XXXX-XXXX-XXXX-XXXX``-shaped string.

The ``tamga.crypto.naive_key`` module that implemented it has been **removed**
rather than deprecated: leaving it importable would let a caller silently keep
using the weaker derivation.

The two derivations differ in salt and ``info``. Machine files additionally
require the target machine's fingerprint, so a machine file cannot be decrypted
anywhere but on the machine it was issued for; license files are not bound to a
machine and use a fixed ``info``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MACHINE_FILE_KEY_SALT: bytes = b"tamga:machine-file-key-v1"
"""Fixed HKDF salt used by the server for machine-file encryption keys."""

LICENSE_FILE_KEY_SALT: bytes = b"tamga:license-file-key-v1"
"""Fixed HKDF salt used by the server for license-file encryption keys."""

LICENSE_FILE_KEY_INFO: bytes = b"license-file"
"""Fixed HKDF ``info`` for license-file encryption keys."""

_AES_KEY_LENGTH = 32


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
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_LENGTH,
        salt=MACHINE_FILE_KEY_SALT,
        info=fingerprint.encode("utf-8"),
    )
    return hkdf.derive(license_key.encode("utf-8"))


def derive_license_file_key(license_key: str) -> bytes:
    """Derive the AES-256 key used to decrypt an encrypted license file.

    ``HKDF-SHA256(salt=LICENSE_FILE_KEY_SALT, ikm=license_key,
    info=LICENSE_FILE_KEY_INFO)`` -> 32 bytes.

    Unlike the machine-file derivation there is no fingerprint: a license file
    is not bound to a machine.

    Args:
        license_key: The license's raw key string (used as HKDF's ``ikm``).

    Returns:
        A 32-byte AES key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_LENGTH,
        salt=LICENSE_FILE_KEY_SALT,
        info=LICENSE_FILE_KEY_INFO,
    )
    return hkdf.derive(license_key.encode("utf-8"))
