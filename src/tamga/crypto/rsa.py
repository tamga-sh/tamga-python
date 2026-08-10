"""RSA-PKCS1v15 and RSA-PSS signature verification.

Used for: machine checkout (``RSA_2048_PKCS1_SIGN`` / ``RSA_2048_PKCS1_PSS_SIGN``
schemes) and machine offline proof (always RSA-2048 PKCS#1 v1.5 / SHA-256,
regardless of the license's ``scheme``).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: F401


def verify_pkcs1v15(public_key_pem_or_der: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 / SHA-256 signature.

    Args:
        public_key_pem_or_der: RSA public key, PEM or DER encoded.
        message: The exact bytes that were signed.
        signature: The raw signature bytes.

    Returns:
        ``True`` if valid, ``False`` otherwise. Does not raise on an invalid
        signature.
    """
    raise NotImplementedError


def verify_pss(public_key_pem_or_der: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an RSASSA-PSS / SHA-256 signature.

    Args:
        public_key_pem_or_der: RSA public key, PEM or DER encoded.
        message: The exact bytes that were signed.
        signature: The raw signature bytes.

    Returns:
        ``True`` if valid, ``False`` otherwise. Does not raise on an invalid
        signature.
    """
    raise NotImplementedError
