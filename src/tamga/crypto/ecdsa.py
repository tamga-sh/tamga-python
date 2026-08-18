"""ECDSA P-256 signature verification.

Used for the ``ECDSA_P256_SIGN`` machine checkout scheme.

⚠️ **Public key format**: the server exports and verifies P-256 public keys
as a **raw 65-byte uncompressed point** (``0x04 || X(32B) || Y(32B)``), not
PEM/DER SubjectPublicKeyInfo. This module therefore accepts **both**: the
raw uncompressed point (the actual wire format, tried first) and PEM/DER
SPKI, for callers who re-wrap the raw point themselves.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

#: Length of a raw uncompressed SECP256R1 point: 0x04 prefix + 32-byte X + 32-byte Y.
_UNCOMPRESSED_POINT_LENGTH = 65


def _load_ec_public_key(public_key_pem_or_der: bytes) -> ec.EllipticCurvePublicKey:
    """Load a P-256 public key from a raw uncompressed point, PEM, or DER SPKI."""
    if (
        len(public_key_pem_or_der) == _UNCOMPRESSED_POINT_LENGTH
        and public_key_pem_or_der[0] == 0x04
    ):
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_pem_or_der)
    try:
        key = serialization.load_pem_public_key(public_key_pem_or_der)
    except ValueError:
        key = serialization.load_der_public_key(public_key_pem_or_der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("key is not an EC public key")
    # SECURITY: the PEM/DER SubjectPublicKeyInfo format embeds its own curve
    # OID, so loading alone does not guarantee P-256 -- unlike the raw-point
    # branch above, which hardcodes ec.SECP256R1() regardless of input. A
    # validly-signed message from any other curve (e.g. P-384) would
    # otherwise verify successfully here, since SHA-256 is just the digest
    # algorithm and is independent of curve choice. Found via audit; see
    # tests/test_crypto_ecdsa.py for the regression coverage.
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(
            f"expected an EC public key on curve secp256r1 (P-256), got {key.curve.name}"
        )
    return key


def verify_p256(public_key_pem_or_der: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ECDSA / SECP256R1 (P-256) / SHA-256 signature.

    Args:
        public_key_pem_or_der: EC public key on the P-256 curve — a raw
            65-byte uncompressed point (the server's actual wire format),
            or PEM/DER SubjectPublicKeyInfo.
        message: The exact bytes that were signed.
        signature: The raw DER-encoded ECDSA signature bytes.

    Returns:
        ``True`` if valid, ``False`` otherwise. Does not raise on an invalid
        signature.
    """
    try:
        public_key = _load_ec_public_key(public_key_pem_or_der)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
