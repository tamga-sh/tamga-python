"""Regression tests for tamga.crypto.ecdsa.verify_p256's curve enforcement.

Found during a cross-repo security audit: the PEM/DER key-loading branch of
`_load_ec_public_key` checked only `isinstance(key, ec.EllipticCurvePublicKey)`,
never the key's actual curve -- so `verify_p256` (named and documented as
P-256-only) would accept a validly-signed message from *any* EC curve, as
long as the caller supplied that curve's key as PEM/DER SubjectPublicKeyInfo.
The raw-65-byte-point branch was already safe (it hardcodes `ec.SECP256R1()`
regardless of input), so this was a real inconsistency within the same
function, not a symmetric gap.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tamga.crypto.ecdsa import verify_p256


def test_rejects_a_validly_signed_message_from_a_non_p256_curve() -> None:
    """A real P-384 keypair, signing a real message, must NOT verify as P-256.

    This is the exact reproduction used during the audit: generate a P-384
    key, sign with it, hand its PEM SubjectPublicKeyInfo (not the raw-point
    format) to verify_p256. Before the fix this returned True.
    """
    private_key = ec.generate_private_key(ec.SECP384R1())
    message = b"tamga-python ecdsa curve-confusion regression test"
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert verify_p256(public_key_pem, message, signature) is False


def test_rejects_a_validly_signed_message_from_secp256k1_via_der() -> None:
    """Same gap, different non-P-256 curve, DER encoding instead of PEM."""
    private_key = ec.generate_private_key(ec.SECP256K1())
    message = b"tamga-python ecdsa curve-confusion regression test (der)"
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert verify_p256(public_key_der, message, signature) is False


def test_still_accepts_a_valid_p256_signature_via_pem(ecdsa_keypair) -> None:  # type: ignore[no-untyped-def]
    """Guard against an overcorrection: real P-256 keys via PEM must still verify."""
    private_key, public_key = ecdsa_keypair
    message = b"tamga-python ecdsa p256 still works"
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert verify_p256(public_key_pem, message, signature) is True


def test_still_accepts_a_valid_p256_signature_via_raw_point(ecdsa_keypair) -> None:  # type: ignore[no-untyped-def]
    """Guard against a regression on the already-safe raw-point path."""
    private_key, public_key = ecdsa_keypair
    message = b"tamga-python ecdsa p256 raw point still works"
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    raw_point = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    assert verify_p256(raw_point, message, signature) is True
