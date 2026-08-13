"""Tests for ``.lic`` license checkout crypto (plan Section E).

⚠️ Crypto-bearing — this section requires a mandatory security-reviewer pass
per docs/plans/tamga-python.plan.md Section 4.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from uuid import UUID

import httpx
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tamga.checkout.license_file import (
    ALG_ENCRYPTED,
    ALG_PLAIN,
    PEM_FOOTER,
    PEM_HEADER,
    LicenseFile,
    LicenseFileExpired,
)
from tamga.client import TamgaClient
from tamga.crypto.hkdf import derive_license_file_key

LICENSE_DATA = {
    "data": {
        "id": "018f2f3a-0000-7000-8000-000000000030",
        "type": "licenses",
        "attributes": {"key": "TEST-LICENSE-KEY-0000-1111-2222-3333", "status": "ACTIVE"},
    },
    # Format v2 puts the claims inside the signed bytes. A payload without
    # them is a v1 file and no longer verifies.
    "meta": {"iat": 1767225600, "jti": "test-jti", "kid": "test-kid"},
}


def _license_data_expiring_at(exp: int) -> dict:
    """LICENSE_DATA with an ``exp`` claim, for the expiry tests."""
    data = json.loads(json.dumps(LICENSE_DATA))
    data["meta"]["exp"] = exp
    return data


def _make_plain_certificate(private_key, payload: dict) -> str:  # type: ignore[no-untyped-def]
    payload_json = json.dumps(payload)
    enc = base64.b64encode(payload_json.encode("utf-8")).decode("ascii")
    # ⚠️ sign the base64 STRING bytes, never the decoded bytes.
    sig = base64.b64encode(private_key.sign(enc.encode("ascii"))).decode("ascii")
    cert = {"enc": enc, "sig": sig, "alg": ALG_PLAIN}
    cert_json = json.dumps(cert)
    body = base64.b64encode(cert_json.encode("utf-8")).decode("ascii")
    return f"{PEM_HEADER}\n{body}\n{PEM_FOOTER}"


def _make_encrypted_certificate(private_key, payload: dict, license_key: str) -> str:  # type: ignore[no-untyped-def]
    payload_json = json.dumps(payload)
    key = derive_license_file_key(license_key)
    aesgcm = AESGCM(key)
    import os

    nonce = os.urandom(12)
    ciphertext_and_tag = aesgcm.encrypt(nonce, payload_json.encode("utf-8"), None)
    enc = base64.b64encode(nonce + ciphertext_and_tag).decode("ascii")
    sig = base64.b64encode(private_key.sign(enc.encode("ascii"))).decode("ascii")
    cert = {"enc": enc, "sig": sig, "alg": ALG_ENCRYPTED}
    cert_json = json.dumps(cert)
    body = base64.b64encode(cert_json.encode("utf-8")).decode("ascii")
    return f"{PEM_HEADER}\n{body}\n{PEM_FOOTER}"


def test_round_trip_plain_lic_parse_and_verify(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    certificate = _make_plain_certificate(private_key, LICENSE_DATA)

    parsed = LicenseFile.parse(certificate)
    assert parsed.alg == ALG_PLAIN

    public_bytes = public_key.public_bytes_raw()
    license_resource = parsed.verify(public_bytes)
    assert str(license_resource.id) == LICENSE_DATA["data"]["id"]
    assert license_resource.attributes["status"] == "ACTIVE"


def test_round_trip_encrypted_lic_parse_verify_and_decrypt(
    ed25519_keypair,
    sample_license_key: str,  # type: ignore[no-untyped-def]
) -> None:
    private_key, public_key = ed25519_keypair
    certificate = _make_encrypted_certificate(private_key, LICENSE_DATA, sample_license_key)

    parsed = LicenseFile.parse(certificate)
    assert parsed.alg == ALG_ENCRYPTED

    public_bytes = public_key.public_bytes_raw()
    license_resource = parsed.verify(public_bytes, license_key=sample_license_key)
    assert str(license_resource.id) == LICENSE_DATA["data"]["id"]


def test_license_file_key_is_hkdf_derived_not_zero_padded(sample_license_key: str) -> None:
    # v1 zero-padded the license key, so the derived key literally contained it
    # in cleartext and everything past its length was zero — a stolen `.lic`
    # was a dictionary attack against the key string, not a 256-bit one.
    key = derive_license_file_key(sample_license_key)
    assert len(key) == 32

    naive = sample_license_key.encode("utf-8")[:32].ljust(32, b"\x00")
    assert key != naive

    # Deterministic, so a client can re-derive it offline.
    assert key == derive_license_file_key(sample_license_key)
    assert key != derive_license_file_key(sample_license_key + "x")


def test_an_expired_file_is_refused_even_though_its_signature_is_valid(
    ed25519_keypair,  # type: ignore[no-untyped-def]
) -> None:
    # The whole point of v2: in v1 the requested TTL lived only in the JSON:API
    # envelope around the certificate, so a 24-hour trial file stayed
    # cryptographically valid forever and the client simply kept the PEM.
    private_key, public_key = ed25519_keypair
    exp = 1767229200
    certificate = _make_plain_certificate(private_key, _license_data_expiring_at(exp))
    parsed = LicenseFile.parse(certificate)

    with pytest.raises(LicenseFileExpired):
        parsed.verify(public_key.public_bytes_raw(), now=exp + 3600)


def test_a_file_within_its_ttl_verifies(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    exp = 1767229200
    certificate = _make_plain_certificate(private_key, _license_data_expiring_at(exp))
    parsed = LicenseFile.parse(certificate)

    license_resource, claims = parsed.verify_with_claims(
        public_key.public_bytes_raw(), now=exp - 3600
    )
    assert claims.exp == exp
    assert claims.jti == "test-jti"
    assert claims.kid == "test-kid"
    assert str(license_resource.id) == LICENSE_DATA["data"]["id"]


def test_a_file_without_an_exp_claim_never_expires(
    ed25519_keypair,  # type: ignore[no-untyped-def]
) -> None:
    # Checkout without a `ttl` produces no `exp`. That must read as perpetual,
    # not as "expired at the epoch".
    private_key, public_key = ed25519_keypair
    certificate = _make_plain_certificate(private_key, LICENSE_DATA)
    parsed = LicenseFile.parse(certificate)

    _license, claims = parsed.verify_with_claims(public_key.public_bytes_raw(), now=2**31 - 1)
    assert claims.exp is None


def test_a_v1_payload_without_meta_is_refused(
    ed25519_keypair,  # type: ignore[no-untyped-def]
) -> None:
    # Second line of defence behind the `alg` gate: a file must not reach the
    # expiry check with nothing to check.
    private_key, public_key = ed25519_keypair
    v1_payload = {"data": LICENSE_DATA["data"]}
    certificate = _make_plain_certificate(private_key, v1_payload)
    parsed = LicenseFile.parse(certificate)

    with pytest.raises(ValueError, match="pre-v2"):
        parsed.verify(public_key.public_bytes_raw())


def test_a_v1_alg_string_is_refused(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    # Accepting both formats would hand back the permanent-file problem.
    private_key, _public_key = ed25519_keypair
    certificate = _make_plain_certificate(private_key, LICENSE_DATA)

    body = "".join(line for line in certificate.splitlines() if not line.startswith("-----"))
    cert = json.loads(base64.b64decode(body))
    cert["alg"] = "base64+ed25519"
    repacked = base64.b64encode(json.dumps(cert).encode()).decode("ascii")

    with pytest.raises(ValueError, match="unsupported license file algorithm"):
        LicenseFile.parse(f"{PEM_HEADER}\n{repacked}\n{PEM_FOOTER}")


def test_tamper_detection_mutated_enc_fails_verification(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    certificate = _make_plain_certificate(private_key, LICENSE_DATA)
    parsed = LicenseFile.parse(certificate)

    tampered = parsed.__class__(enc=parsed.enc + "AA", sig=parsed.sig, alg=parsed.alg)
    public_bytes = public_key.public_bytes_raw()
    with pytest.raises(InvalidSignature):
        tampered.verify(public_bytes)


def test_wrong_public_key_rejected(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, _ = ed25519_keypair
    certificate = _make_plain_certificate(private_key, LICENSE_DATA)
    parsed = LicenseFile.parse(certificate)

    from cryptography.hazmat.primitives.asymmetric import ed25519

    wrong_public_key = ed25519.Ed25519PrivateKey.generate().public_key()
    with pytest.raises(InvalidSignature):
        parsed.verify(wrong_public_key.public_bytes_raw())


def test_malformed_pem_markers_raise_clear_parse_error() -> None:
    with pytest.raises(ValueError, match="malformed certificate"):
        LicenseFile.parse("not a certificate at all")


def test_non_base64_body_raises_clear_parse_error() -> None:
    bad = f"{PEM_HEADER}\nnot-valid-base64!!!\n{PEM_FOOTER}"
    with pytest.raises(ValueError, match="malformed certificate"):
        LicenseFile.parse(bad)


def test_unsupported_algorithm_raises_clear_error() -> None:
    cert = {"enc": "abc", "sig": base64.b64encode(b"sig").decode(), "alg": "some-other-alg"}
    body = base64.b64encode(json.dumps(cert).encode()).decode()
    certificate = f"{PEM_HEADER}\n{body}\n{PEM_FOOTER}"
    with pytest.raises(ValueError, match="unsupported license file algorithm"):
        LicenseFile.parse(certificate)


def test_signing_message_is_base64_string_bytes_not_decoded_bytes(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    """Regression test: a future refactor must not silently "fix" this into
    signing/verifying over ``base64.b64decode(enc)`` instead of ``enc``'s
    ASCII string bytes — that would be the "more correct-looking" but wrong
    behavior, breaking interop with every real server-produced .lic file.
    """
    private_key, public_key = ed25519_keypair
    certificate = _make_plain_certificate(private_key, LICENSE_DATA)
    parsed = LicenseFile.parse(certificate)
    public_bytes = public_key.public_bytes_raw()

    # The real (correct) verification path succeeds:
    parsed.verify(public_bytes)

    # But verifying over base64.b64decode(enc) instead of enc's ASCII bytes
    # must NOT be what LicenseFile.verify does internally — prove this by
    # checking that a signature computed over the decoded bytes does not
    # match one computed over the string bytes (i.e. they're genuinely
    # different messages, so getting this backwards would break everything).
    decoded_bytes = base64.b64decode(parsed.enc)
    assert decoded_bytes != parsed.enc.encode("ascii")
    sig_over_decoded = private_key.sign(decoded_bytes)
    assert sig_over_decoded != parsed.sig


LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000031")


def test_client_check_out_post_variant_returns_structured_resource(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == (
            f"/v1/accounts/018f2f3a-0000-7000-8000-000000000001/licenses/{LICENSE_ID}/actions/check-out"
        )
        body = json.loads(request.content)
        assert body["meta"]["encrypt"] is True
        assert body["meta"]["ttl"] == 3600
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": "file-1",
                    "type": "license-files",
                    "attributes": {
                        "certificate": (
                            "-----BEGIN LICENSE FILE-----\n...\n-----END LICENSE FILE-----"
                        ),
                        "algorithm": "aes-256-gcm+ed25519+v2",
                        "includes": [],
                        "ttl": 3600,
                        "expiry": "2024-01-01T01:00:00Z",
                        "issued": "2024-01-01T00:00:00Z",
                    },
                }
            },
        )

    client = make_client(handler)
    result = client.licenses.check_out(LICENSE_ID, encrypt=True, ttl=3600)
    assert not isinstance(result, bytes)
    assert result.algorithm == "aes-256-gcm+ed25519+v2"
    assert result.ttl == 3600


def test_client_check_out_get_variant_returns_raw_bytes(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    raw_cert = b"-----BEGIN LICENSE FILE-----\nABC\n-----END LICENSE FILE-----"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, content=raw_cert)

    client = make_client(handler)
    result = client.licenses.check_out(LICENSE_ID, as_bytes=True)
    assert result == raw_cert


def test_client_check_out_license_not_encrypted_raises_typed_error(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    from tamga.errors import LicenseNotEncryptedError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={
                "errors": [
                    {
                        "id": "e1",
                        "status": "422",
                        "code": "LICENSE_NOT_ENCRYPTED",
                        "title": "Unprocessable Entity",
                        "detail": "license has no key set",
                        "source": None,
                    }
                ]
            },
        )

    client = make_client(handler)
    with pytest.raises(LicenseNotEncryptedError):
        client.licenses.check_out(LICENSE_ID, encrypt=True)
