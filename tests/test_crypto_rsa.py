"""Regression tests for tamga.crypto.rsa's key-size enforcement.

Found during a cross-repo security audit: `_load_rsa_public_key` checked
only `isinstance(key, rsa.RSAPublicKey)`, never `key.key_size` -- so
`verify_pkcs1v15`/`verify_pss` would accept a validly-signed message from an
RSA key well below the documented `RSA_2048_*` scheme family (reproduced
directly with a 1024-bit key). The accepted range (2048-8192 bits, not
exactly 2048) matches tamga-rust's reference implementation, which uses
aws-lc-rs's `RSA_PKCS1_2048_8192_SHA256`/`RSA_PSS_2048_8192_SHA256`
algorithm objects -- enforcing exactly 2048 would be stricter than the
actual protocol and could reject a legitimate larger key.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tamga.crypto.rsa import verify_pkcs1v15, verify_pss


def _spki_pem(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_pkcs1v15_rejects_a_validly_signed_message_from_a_1024_bit_key() -> None:
    """The exact reproduction used during the audit."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    message = b"tamga-python rsa key-size regression test"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    assert verify_pkcs1v15(_spki_pem(private_key.public_key()), message, signature) is False


def test_pss_rejects_a_validly_signed_message_from_a_1024_bit_key() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    message = b"tamga-python rsa pss key-size regression test"
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )

    assert verify_pss(_spki_pem(private_key.public_key()), message, signature) is False


def test_pkcs1v15_still_accepts_a_valid_2048_bit_signature(rsa_keypair) -> None:  # type: ignore[no-untyped-def]
    """Guard against an overcorrection: the documented 2048-bit case must still work."""
    private_key, public_key = rsa_keypair
    message = b"tamga-python rsa 2048 still works"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    assert verify_pkcs1v15(_spki_pem(public_key), message, signature) is True


def test_pkcs1v15_still_accepts_a_valid_4096_bit_signature() -> None:
    """A larger-than-2048 key must still verify -- the range is 2048-8192, not exactly 2048."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    message = b"tamga-python rsa 4096 still works"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    assert verify_pkcs1v15(_spki_pem(private_key.public_key()), message, signature) is True
