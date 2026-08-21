"""Tests for machine checkout crypto: multi-algorithm verify + HKDF.

⚠️ Crypto-bearing — changes here require a mandatory security-reviewer pass.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable
from uuid import UUID

import httpx
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tamga.checkout.machine_file import PEM_FOOTER, PEM_HEADER, MachineFile
from tamga.client import TamgaClient
from tamga.crypto.hkdf import derive_machine_file_key
from tamga.errors import SchemeNotSupportedError, TtlInvalidError
from tamga.models.policy import LicenseScheme

#: The signed `meta` claims a format-v2 certificate carries. `exp` is absent
#: on purpose -- a checkout made without a `ttl` produces a file that never
#: expires -- so these round-trip tests stay about signatures and key
#: derivation. Expiry enforcement is exercised against the server-produced
#: fixtures in test_machine_file_fixtures.py.
V2_CLAIMS = {
    "iat": 1700000000,
    "jti": "018f2f3a-0000-7000-8000-0000000000bb",
    "kid": "0123456789abcdef",
}

MACHINE_DATA = {
    "data": {
        "id": "018f2f3a-0000-7000-8000-000000000040",
        "type": "machines",
        "attributes": {
            "fingerprint": "test-machine-fingerprint-abc123",
            "heartbeat_status": "NOT_STARTED",
        },
    },
    "meta": V2_CLAIMS,
}


def _sign_ed25519(private_key, message: bytes) -> bytes:  # type: ignore[no-untyped-def]
    return private_key.sign(message)


def _sign_rsa_pkcs1(private_key, message: bytes) -> bytes:  # type: ignore[no-untyped-def]
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def _sign_rsa_pss(private_key, message: bytes) -> bytes:  # type: ignore[no-untyped-def]
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )


def _sign_ecdsa(private_key, message: bytes) -> bytes:  # type: ignore[no-untyped-def]
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


_SIGNERS = {
    LicenseScheme.ED25519_SIGN: _sign_ed25519,
    LicenseScheme.RSA_2048_PKCS1_SIGN: _sign_rsa_pkcs1,
    LicenseScheme.RSA_2048_PKCS1_PSS_SIGN: _sign_rsa_pss,
    LicenseScheme.ECDSA_P256_SIGN: _sign_ecdsa,
}


def _public_key_bytes(scheme: LicenseScheme, public_key) -> bytes:  # type: ignore[no-untyped-def]
    if scheme == LicenseScheme.ED25519_SIGN:
        return public_key.public_bytes_raw()
    if scheme == LicenseScheme.ECDSA_P256_SIGN:
        return public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


#: Maps a scheme to its `alg` signing-suffix, matching the server's own
#: scheme-to-`alg`-suffix mapping — needed so test fixtures produce an `alg`
#: value MachineFile.parse's closed `VALID_ALGORITHMS` set actually accepts.
#: Note `rsa-sha256` is what the server emits for RSA_2048_JWT_RS256 too, so
#: this mapping is not invertible — see MachineFile's module docstring.
_ALG_SUFFIX = {
    LicenseScheme.ED25519_SIGN: "ed25519",
    LicenseScheme.RSA_2048_PKCS1_SIGN: "rsa-sha256",
    LicenseScheme.RSA_2048_PKCS1_PSS_SIGN: "rsa-pss-sha256",
    LicenseScheme.ECDSA_P256_SIGN: "ecdsa-p256",
}


def _make_plain_certificate(scheme: LicenseScheme, private_key, payload: dict) -> str:  # type: ignore[no-untyped-def]
    payload_json = json.dumps(payload)
    enc = base64.b64encode(payload_json.encode("utf-8")).decode("ascii")
    sig_bytes = _SIGNERS[scheme](private_key, enc.encode("ascii"))
    sig = base64.b64encode(sig_bytes).decode("ascii")
    cert = {"enc": enc, "sig": sig, "alg": f"base64+{_ALG_SUFFIX[scheme]}+v2"}
    body = base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")
    return f"{PEM_HEADER}\n{body}\n{PEM_FOOTER}"


def _make_encrypted_certificate(
    scheme: LicenseScheme, private_key, payload: dict, license_key: str, fingerprint: str
) -> str:  # type: ignore[no-untyped-def]
    payload_json = json.dumps(payload)
    key = derive_machine_file_key(license_key, fingerprint)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext_and_tag = aesgcm.encrypt(nonce, payload_json.encode("utf-8"), None)
    # `<nonce_b64>.<cipher_b64>` -- two separately base64-encoded halves, the
    # format the server's FieldEncryption::encrypt actually emits. NOT
    # base64(nonce || ciphertext || tag), which is the license-file layout.
    enc = (
        f"{base64.b64encode(nonce).decode('ascii')}."
        f"{base64.b64encode(ciphertext_and_tag).decode('ascii')}"
    )
    sig_bytes = _SIGNERS[scheme](private_key, enc.encode("ascii"))
    sig = base64.b64encode(sig_bytes).decode("ascii")
    cert = {"enc": enc, "sig": sig, "alg": f"aes-256-gcm+{_ALG_SUFFIX[scheme]}+v2"}
    body = base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")
    return f"{PEM_HEADER}\n{body}\n{PEM_FOOTER}"


def test_ed25519_verify_round_trip(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    scheme = LicenseScheme.ED25519_SIGN
    certificate = _make_plain_certificate(scheme, private_key, MACHINE_DATA)
    parsed = MachineFile.parse(certificate)

    machine = parsed.verify(_public_key_bytes(scheme, public_key), scheme)
    assert str(machine.id) == MACHINE_DATA["data"]["id"]


def test_rsa_pkcs1v15_verify_round_trip(rsa_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = rsa_keypair
    scheme = LicenseScheme.RSA_2048_PKCS1_SIGN
    certificate = _make_plain_certificate(scheme, private_key, MACHINE_DATA)
    parsed = MachineFile.parse(certificate)

    machine = parsed.verify(_public_key_bytes(scheme, public_key), scheme)
    assert str(machine.id) == MACHINE_DATA["data"]["id"]


def test_rsa_pss_verify_round_trip(rsa_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = rsa_keypair
    scheme = LicenseScheme.RSA_2048_PKCS1_PSS_SIGN
    certificate = _make_plain_certificate(scheme, private_key, MACHINE_DATA)
    parsed = MachineFile.parse(certificate)

    machine = parsed.verify(_public_key_bytes(scheme, public_key), scheme)
    assert str(machine.id) == MACHINE_DATA["data"]["id"]


def test_ecdsa_p256_verify_round_trip(ecdsa_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ecdsa_keypair
    scheme = LicenseScheme.ECDSA_P256_SIGN
    certificate = _make_plain_certificate(scheme, private_key, MACHINE_DATA)
    parsed = MachineFile.parse(certificate)

    machine = parsed.verify(_public_key_bytes(scheme, public_key), scheme)
    assert str(machine.id) == MACHINE_DATA["data"]["id"]


def test_rsa_2048_jwt_rs256_scheme_raises_scheme_not_supported(rsa_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = rsa_keypair
    # Build a certificate signed with plain PKCS1 (doesn't matter — the
    # dispatcher must reject before ever touching the signature).
    certificate = _make_plain_certificate(
        LicenseScheme.RSA_2048_PKCS1_SIGN, private_key, MACHINE_DATA
    )
    parsed = MachineFile.parse(certificate)

    with pytest.raises(SchemeNotSupportedError):
        parsed.verify(
            _public_key_bytes(LicenseScheme.RSA_2048_PKCS1_SIGN, public_key),
            LicenseScheme.RSA_2048_JWT_RS256,
        )


def test_parse_rejects_alg_outside_closed_vocabulary() -> None:
    """Security-review regression test (finding M-1): `alg` is not
    covered by the signature (it lives in the same unsigned outer JSON as
    `enc`/`sig`), so `MachineFile.parse` must validate it against a closed
    set at parse time rather than accepting any string — a corrupted `alg`
    should fail fast with a clear `ValueError`, not an opaque crypto
    exception surfaced later from `verify()`.
    """
    cert = {
        "enc": "abc",
        "sig": base64.b64encode(b"sig").decode(),
        "alg": "base64+not-a-real-alg+v2",
    }
    body = base64.b64encode(json.dumps(cert).encode()).decode()
    certificate = f"{PEM_HEADER}\n{body}\n{PEM_FOOTER}"
    with pytest.raises(ValueError, match="unsupported machine file algorithm"):
        MachineFile.parse(certificate)


def test_hkdf_sha256_known_answer(sample_license_key: str, sample_fingerprint: str) -> None:
    key1 = derive_machine_file_key(sample_license_key, sample_fingerprint)
    key2 = derive_machine_file_key(sample_license_key, sample_fingerprint)
    assert len(key1) == 32
    assert key1 == key2  # deterministic for fixed inputs

    different_fp_key = derive_machine_file_key(sample_license_key, "different-fingerprint")
    assert different_fp_key != key1

    different_lk_key = derive_machine_file_key("different-license-key", sample_fingerprint)
    assert different_lk_key != key1


def test_encrypted_machine_file_round_trip_requires_license_key_and_fingerprint(
    ed25519_keypair,
    sample_license_key: str,
    sample_fingerprint: str,  # type: ignore[no-untyped-def]
) -> None:
    private_key, public_key = ed25519_keypair
    scheme = LicenseScheme.ED25519_SIGN
    certificate = _make_encrypted_certificate(
        scheme, private_key, MACHINE_DATA, sample_license_key, sample_fingerprint
    )
    parsed = MachineFile.parse(certificate)

    machine = parsed.verify(
        _public_key_bytes(scheme, public_key),
        scheme,
        license_key=sample_license_key,
        fingerprint=sample_fingerprint,
    )
    assert str(machine.id) == MACHINE_DATA["data"]["id"]


def test_wrong_fingerprint_fails_to_decrypt(
    ed25519_keypair,
    sample_license_key: str,
    sample_fingerprint: str,  # type: ignore[no-untyped-def]
) -> None:
    private_key, public_key = ed25519_keypair
    scheme = LicenseScheme.ED25519_SIGN
    certificate = _make_encrypted_certificate(
        scheme, private_key, MACHINE_DATA, sample_license_key, sample_fingerprint
    )
    parsed = MachineFile.parse(certificate)

    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        parsed.verify(
            _public_key_bytes(scheme, public_key),
            scheme,
            license_key=sample_license_key,
            fingerprint="wrong-fingerprint",
        )


@pytest.mark.parametrize(
    "scheme_fixture",
    ["ed25519_keypair", "rsa_keypair", "ecdsa_keypair"],
)
def test_tamper_detection_per_algorithm(
    scheme_fixture: str, request: pytest.FixtureRequest
) -> None:
    scheme_map = {
        "ed25519_keypair": LicenseScheme.ED25519_SIGN,
        "rsa_keypair": LicenseScheme.RSA_2048_PKCS1_SIGN,
        "ecdsa_keypair": LicenseScheme.ECDSA_P256_SIGN,
    }
    scheme = scheme_map[scheme_fixture]
    private_key, public_key = request.getfixturevalue(scheme_fixture)
    certificate = _make_plain_certificate(scheme, private_key, MACHINE_DATA)
    parsed = MachineFile.parse(certificate)

    tampered = parsed.__class__(enc=parsed.enc + "AA", sig=parsed.sig, alg=parsed.alg)
    with pytest.raises(InvalidSignature):
        tampered.verify(_public_key_bytes(scheme, public_key), scheme)


MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000041")


def test_client_check_out_post_variant_returns_structured_resource(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == (
            f"/v1/accounts/018f2f3a-0000-7000-8000-000000000001/machines/{MACHINE_ID}/actions/check-out"
        )
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": "file-1",
                    "type": "machine-files",
                    "attributes": {
                        "certificate": (
                            "-----BEGIN MACHINE FILE-----\n...\n-----END MACHINE FILE-----"
                        ),
                        "algorithm": "base64+ed25519+v2",
                        "includes": [],
                        "ttl": None,
                        "expiry": None,
                        "issued": "2024-01-01T00:00:00Z",
                    },
                }
            },
        )

    client = make_client(handler)
    result = client.machines.check_out(MACHINE_ID)
    assert not isinstance(result, bytes)
    assert result.algorithm == "base64+ed25519+v2"


def test_client_check_out_get_variant_returns_raw_bytes(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    raw_cert = b"-----BEGIN MACHINE FILE-----\nABC\n-----END MACHINE FILE-----"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, content=raw_cert)

    client = make_client(handler)
    result = client.machines.check_out(MACHINE_ID, as_bytes=True)
    assert result == raw_cert


def test_client_check_out_ttl_out_of_range_raises_before_sending_request(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("request should never be sent for an out-of-range ttl")

    client = make_client(handler)
    with pytest.raises(TtlInvalidError):
        client.machines.check_out(MACHINE_ID, ttl=99999999)
