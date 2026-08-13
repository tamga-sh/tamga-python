"""RSA-PKCS1v15 and RSA-PSS signature verification.

Used for: machine checkout (``RSA_2048_PKCS1_SIGN`` / ``RSA_2048_PKCS1_PSS_SIGN``
schemes) and machine offline proof (always RSA-2048 PKCS#1 v1.5 / SHA-256,
regardless of the license's ``scheme``).

Public keys are accepted as PEM, DER (including bare SubjectPublicKeyInfo DER
— the format the server's own ``aws-lc-rs``-based signer exports via
``RsaKeyPair::public_key()``), matching ``tamga-rust``'s ``crypto/rsa.rs``
(which documents its ``pubkey_spki_der`` parameter identically).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

#: Matches tamga-rust's reference implementation (aws-lc-rs's
#: RSA_PKCS1_2048_8192_SHA256 / RSA_PSS_2048_8192_SHA256 algorithm objects,
#: crypto/rsa.rs) -- the accepted range is 2048-8192 bits, not exactly 2048,
#: even though the wire scheme names are RSA_2048_*.
_MIN_KEY_SIZE_BITS = 2048
_MAX_KEY_SIZE_BITS = 8192


def _load_rsa_public_key(public_key_pem_or_der: bytes) -> rsa.RSAPublicKey:
    """Load an RSA public key from PEM or DER (SubjectPublicKeyInfo) bytes."""
    try:
        key = serialization.load_pem_public_key(public_key_pem_or_der)
    except ValueError:
        key = serialization.load_der_public_key(public_key_pem_or_der)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("key is not an RSA public key")
    # SECURITY: neither load_pem_public_key nor load_der_public_key checks
    # key size -- a caller-influenced downgrade to a weaker RSA key (e.g.
    # 1024-bit) would otherwise verify successfully. Found via audit; see
    # tests/test_crypto_rsa.py for the regression coverage.
    if not (_MIN_KEY_SIZE_BITS <= key.key_size <= _MAX_KEY_SIZE_BITS):
        raise ValueError(
            f"RSA key size {key.key_size} bits outside the accepted "
            f"{_MIN_KEY_SIZE_BITS}-{_MAX_KEY_SIZE_BITS}-bit range"
        )
    return key


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
    try:
        public_key = _load_rsa_public_key(public_key_pem_or_der)
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_pss(public_key_pem_or_der: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an RSASSA-PSS / SHA-256 signature.

    Uses MGF1-SHA256 with a salt length equal to the digest length (32
    bytes) — the standard PSS parameterization, matching the server's
    ``aws-lc-rs`` ``RSA_PSS_2048_8192_SHA256`` verifier.

    Args:
        public_key_pem_or_der: RSA public key, PEM or DER encoded.
        message: The exact bytes that were signed.
        signature: The raw signature bytes.

    Returns:
        ``True`` if valid, ``False`` otherwise. Does not raise on an invalid
        signature.
    """
    try:
        public_key = _load_rsa_public_key(public_key_pem_or_der)
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False
