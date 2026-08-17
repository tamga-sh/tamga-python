"""Regression tests for input-hardening findings from a cross-repo security audit.

Each covers a real defect found in offline checkout parsing/verification --
not the base64-string-vs-decoded-bytes/key-derivation/field-order gotchas
already covered elsewhere, but robustness gaps around malformed-but-not-forged input
reaching these code paths after signature verification has already passed
(or, for the envelope-length guards, before it).
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tamga.checkout._envelope import parse_certificate_envelope
from tamga.checkout.license_file import ALG_PLAIN, PEM_FOOTER, PEM_HEADER, LicenseFile
from tamga.checkout.machine_file import PEM_FOOTER as MACHINE_PEM_FOOTER
from tamga.checkout.machine_file import PEM_HEADER as MACHINE_PEM_HEADER
from tamga.checkout.machine_file import MachineFile
from tamga.crypto.hkdf import derive_machine_file_key
from tamga.models.machine import HeartbeatStatus
from tamga.models.policy import LicenseScheme


def _cert_with_raw_enc_bytes(
    private_key, enc_payload: bytes, alg: str, header: str, footer: str
) -> str:
    """Build a {enc, sig, alg} PEM certificate from already-encoded enc bytes.

    Unlike the round-trip helpers in test_license_checkout.py/
    test_machine_checkout.py (which JSON-encode a dict payload before
    base64ing it), this accepts arbitrary bytes as the plaintext payload so
    tests can construct a validly-signed certificate whose decrypted/decoded
    content is deliberately not valid JSON, or valid JSON missing "data".
    """
    enc = base64.b64encode(enc_payload).decode("ascii")
    sig = base64.b64encode(private_key.sign(enc.encode("ascii"))).decode("ascii")
    cert = {"enc": enc, "sig": sig, "alg": alg}
    body = base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")
    return f"{header}\n{body}\n{footer}"


# ---------------------------------------------------------------------------
# HeartbeatStatus: unrecognized value must fall back, not crash
# ---------------------------------------------------------------------------


def test_unrecognized_heartbeat_status_falls_back_to_not_started(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    """A correctly-signed, correctly-decrypted machine file with a future/
    unmodeled heartbeat_status must not crash verify() after the signature
    already passed -- must fall back the same way models/policy.py's
    OverageStrategy/HeartbeatResurrectionStrategy already do for
    DENY_ACCESS/NO_RESURRECTION.
    """
    private_key, public_key = ed25519_keypair
    payload = {
        "data": {
            "id": "018f2f3a-0000-7000-8000-000000000041",
            "type": "machines",
            "attributes": {
                "fingerprint": "fp",
                "heartbeat_status": "SOME_FUTURE_STATUS_NOT_YET_MODELED",
            },
        }
    }
    enc_payload = json.dumps(payload).encode("utf-8")
    cert = _cert_with_raw_enc_bytes(
        private_key, enc_payload, "base64+ed25519", MACHINE_PEM_HEADER, MACHINE_PEM_FOOTER
    )

    machine_file = MachineFile.parse(cert)
    resource = machine_file.verify(
        public_key.public_bytes_raw(),
        LicenseScheme.ED25519_SIGN,
    )

    assert resource.heartbeat_status == HeartbeatStatus.NOT_STARTED


# ---------------------------------------------------------------------------
# Post-decrypt JSON parsing: must raise a clean ValueError, not a raw
# json.JSONDecodeError/KeyError leaking from deep inside verify()
# ---------------------------------------------------------------------------


def test_license_file_non_json_plaintext_raises_clear_value_error(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    cert = _cert_with_raw_enc_bytes(
        private_key, b"not json at all", ALG_PLAIN, PEM_HEADER, PEM_FOOTER
    )
    license_file = LicenseFile.parse(cert)

    with pytest.raises(ValueError, match="not valid JSON"):
        license_file.verify(public_key.public_bytes_raw())


def test_license_file_json_missing_data_key_raises_clear_value_error(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    cert = _cert_with_raw_enc_bytes(
        private_key, json.dumps({"not_data": {}}).encode("utf-8"), ALG_PLAIN, PEM_HEADER, PEM_FOOTER
    )
    license_file = LicenseFile.parse(cert)

    with pytest.raises(ValueError, match="'data'"):
        license_file.verify(public_key.public_bytes_raw())


def test_machine_file_non_json_plaintext_raises_clear_value_error(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    cert = _cert_with_raw_enc_bytes(
        private_key, b"not json at all", "base64+ed25519", MACHINE_PEM_HEADER, MACHINE_PEM_FOOTER
    )
    machine_file = MachineFile.parse(cert)

    with pytest.raises(ValueError, match="not valid JSON"):
        machine_file.verify(public_key.public_bytes_raw(), LicenseScheme.ED25519_SIGN)


def test_machine_file_json_missing_data_key_raises_clear_value_error(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    cert = _cert_with_raw_enc_bytes(
        private_key,
        json.dumps({"not_data": {}}).encode("utf-8"),
        "base64+ed25519",
        MACHINE_PEM_HEADER,
        MACHINE_PEM_FOOTER,
    )
    machine_file = MachineFile.parse(cert)

    with pytest.raises(ValueError, match="'data'"):
        machine_file.verify(public_key.public_bytes_raw(), LicenseScheme.ED25519_SIGN)


def test_encrypted_machine_file_decrypted_non_json_raises_clear_value_error(
    ed25519_keypair, sample_license_key: str
) -> None:  # type: ignore[no-untyped-def]
    """Same class of gap, reached via the AES-256-GCM-decrypted branch instead
    of the plain base64 branch -- a different code path in verify()."""
    private_key, public_key = ed25519_keypair
    fingerprint = "fp-for-decrypted-non-json-test"
    key = derive_machine_file_key(sample_license_key, fingerprint)
    aesgcm = AESGCM(key)
    import os

    nonce = os.urandom(12)
    ciphertext_and_tag = aesgcm.encrypt(nonce, b"not json at all", None)
    cert = _cert_with_raw_enc_bytes(
        private_key,
        nonce + ciphertext_and_tag,
        "aes-256-gcm+ed25519",
        MACHINE_PEM_HEADER,
        MACHINE_PEM_FOOTER,
    )
    machine_file = MachineFile.parse(cert)

    with pytest.raises(ValueError, match="not valid JSON"):
        machine_file.verify(
            public_key.public_bytes_raw(),
            LicenseScheme.ED25519_SIGN,
            license_key=sample_license_key,
            fingerprint=fingerprint,
        )


# ---------------------------------------------------------------------------
# LicenseFile.is_expired: a timezone-naive as_of must not crash
# ---------------------------------------------------------------------------


def test_is_expired_accepts_naive_as_of_treating_it_as_utc() -> None:
    """datetime.now() with no tz argument is the natural, easy-to-reach-for
    call -- the docstring says "defaults to now (UTC)" without stating a
    caller-supplied as_of must also be tz-aware. Must not raise TypeError.
    """
    license_file = LicenseFile(enc="", sig=b"", alg=ALG_PLAIN, expiry="2020-01-01T00:00:00Z")

    naive_now = datetime(2024, 1, 1, 12, 0, 0)  # deliberately no tzinfo
    assert license_file.is_expired(as_of=naive_now) is True

    naive_before_expiry = datetime(2019, 1, 1, 12, 0, 0)
    assert license_file.is_expired(as_of=naive_before_expiry) is False

    # A tz-aware as_of must still behave exactly as before (no regression).
    aware_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert license_file.is_expired(as_of=aware_now) is True


# ---------------------------------------------------------------------------
# Envelope length guards
# ---------------------------------------------------------------------------


def test_envelope_rejects_crafted_overlapping_markers_with_an_accurate_message() -> None:
    """A string that satisfies startswith(header) and endswith(footer) only
    because the two literal marker strings overlap -- shorter than
    len(header) + len(footer) -- must raise a clear "too short" error, not
    the misleading "not valid JSON" message the negative-length slice
    previously produced (it silently sliced to an empty body, which then
    "successfully" decoded as empty base64 and only failed several steps
    later at the JSON-parse stage with an unrelated-sounding message).

    Same underlying edge-case shape as the crafted-overlapping-PEM-markers
    regression already fixed in tamga-dotnet (commit 8fa11a5).
    """
    crafted = PEM_HEADER + PEM_FOOTER[1:]
    assert crafted.startswith(PEM_HEADER)
    assert crafted.endswith(PEM_FOOTER)
    assert len(crafted) < len(PEM_HEADER) + len(PEM_FOOTER)

    with pytest.raises(ValueError, match="too short"):
        parse_certificate_envelope(crafted, PEM_HEADER, PEM_FOOTER)


def test_envelope_rejects_an_oversized_certificate_body() -> None:
    """A certificate body far larger than any legitimate license/machine
    file must be rejected before attempting to base64-decode/JSON-parse it.
    """
    oversized_body = "A" * (2 * 1024 * 1024)  # 2 MiB of base64 alphabet chars
    certificate = f"{PEM_HEADER}\n{oversized_body}\n{PEM_FOOTER}"

    with pytest.raises(ValueError, match="too large"):
        parse_certificate_envelope(certificate, PEM_HEADER, PEM_FOOTER)


def test_envelope_still_accepts_a_normal_sized_certificate(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    """Guard against an overcorrection: a normal, real-world-sized
    certificate must still parse successfully after both length guards."""
    private_key, public_key = ed25519_keypair
    cert = _cert_with_raw_enc_bytes(
        private_key,
        json.dumps({"data": {"id": "x"}}).encode("utf-8"),
        ALG_PLAIN,
        PEM_HEADER,
        PEM_FOOTER,
    )
    enc, sig_bytes, alg = parse_certificate_envelope(cert, PEM_HEADER, PEM_FOOTER)
    assert alg == ALG_PLAIN
    assert isinstance(sig_bytes, bytes)
