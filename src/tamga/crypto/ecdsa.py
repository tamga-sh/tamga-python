"""ECDSA P-256 signature verification.

Used for the ``ECDSA_P256_SIGN`` machine checkout scheme.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: F401


def verify_p256(public_key_pem_or_der: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ECDSA / SECP256R1 (P-256) / SHA-256 signature.

    Args:
        public_key_pem_or_der: EC public key on the P-256 curve, PEM or DER encoded.
        message: The exact bytes that were signed.
        signature: The raw DER-encoded ECDSA signature bytes.

    Returns:
        ``True`` if valid, ``False`` otherwise. Does not raise on an invalid
        signature.
    """
    raise NotImplementedError
