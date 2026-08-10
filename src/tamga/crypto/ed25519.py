"""Ed25519 signature verification.

Used for: the license checkout signature (always Ed25519, independent of the
license's own ``scheme``), and as one of the four machine checkout
verification schemes (``LicenseScheme.ED25519_SIGN``).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401


def verify(public_key_bytes: bytes, message_bytes: bytes, signature_bytes: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key.
        message_bytes: The exact bytes that were signed. Callers in this SDK
            must be careful about *which* bytes that is — see the
            signing-message gotcha documented in
            ``tamga.checkout.license_file``.
        signature_bytes: The raw signature bytes (already base64-decoded by
            the caller).

    Returns:
        ``True`` if the signature is valid for the given key and message,
        ``False`` otherwise. Does not raise on an invalid signature.
    """
    raise NotImplementedError
