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
import os
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tamga.checkout import license_file as license_file_module
from tamga.checkout._envelope import parse_certificate_envelope
from tamga.checkout.license_file import (
    ALG_ENCRYPTED,
    ALG_PLAIN,
    PEM_FOOTER,
    PEM_HEADER,
    LicenseFile,
)
from tamga.checkout.machine_file import PEM_FOOTER as MACHINE_PEM_FOOTER
from tamga.checkout.machine_file import PEM_HEADER as MACHINE_PEM_HEADER
from tamga.checkout.machine_file import MachineFile
from tamga.crypto.hkdf import derive_license_file_key, derive_machine_file_key
from tamga.models.machine import HeartbeatStatus
from tamga.models.policy import LicenseScheme

#: The signed `meta` claims every format-v2 certificate carries. `exp` is
#: deliberately absent: a checkout made without a `ttl` produces a file that
#: never expires, which keeps these hardening tests about malformed payloads
#: rather than about the clock.
V2_CLAIMS = {
    "iat": 1700000000,
    "jti": "018f2f3a-0000-7000-8000-0000000000aa",
    "kid": "0123456789abcdef",
}


def _cert_from_enc_string(private_key, enc: str, alg: str, header: str, footer: str) -> str:
    """Build a {enc, sig, alg} PEM certificate around an already-built `enc` string.

    The signature covers `enc`'s ASCII bytes, so this is the lowest-level
    builder: it makes no assumption about whether `enc` is a single base64
    blob (plain, and encrypted `.lic`) or the `"<nonce_b64>.<cipher_b64>"`
    pair an encrypted *machine* file uses.
    """
    sig = base64.b64encode(private_key.sign(enc.encode("ascii"))).decode("ascii")
    cert = {"enc": enc, "sig": sig, "alg": alg}
    body = base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")
    return f"{header}\n{body}\n{footer}"


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
    return _cert_from_enc_string(private_key, enc, alg, header, footer)


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
        },
        "meta": V2_CLAIMS,
    }
    enc_payload = json.dumps(payload).encode("utf-8")
    cert = _cert_with_raw_enc_bytes(
        private_key, enc_payload, "base64+ed25519+v2", MACHINE_PEM_HEADER, MACHINE_PEM_FOOTER
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
        private_key, b"not json at all", "base64+ed25519+v2", MACHINE_PEM_HEADER, MACHINE_PEM_FOOTER
    )
    machine_file = MachineFile.parse(cert)

    with pytest.raises(ValueError, match="not valid JSON"):
        machine_file.verify(public_key.public_bytes_raw(), LicenseScheme.ED25519_SIGN)


def test_machine_file_json_missing_data_key_raises_clear_value_error(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    cert = _cert_with_raw_enc_bytes(
        private_key,
        json.dumps({"not_data": {}}).encode("utf-8"),
        "base64+ed25519+v2",
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
    # An encrypted machine file's `enc` is two separately-base64'd halves
    # joined by a dot -- NOT base64(nonce || ciphertext || tag), which is the
    # license-file layout.
    enc = (
        f"{base64.b64encode(nonce).decode('ascii')}."
        f"{base64.b64encode(ciphertext_and_tag).decode('ascii')}"
    )
    cert = _cert_from_enc_string(
        private_key,
        enc,
        "aes-256-gcm+ed25519+v2",
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
# Encrypted machine-file `enc` is "<nonce_b64>.<cipher_b64>" -- two separately
# base64'd halves, not one blob. Python hid this: base64.b64decode() silently
# drops characters outside the alphabet (the "." included), and nonce_b64 is
# always exactly 16 chars, a whole number of 4-char blocks -- so decoding the
# whole string in one pass and slicing 12 bytes off the front happens to
# reconstruct nonce||ciphertext byte-for-byte. It only works by that
# coincidence, and it silently accepts input it should refuse.
# ---------------------------------------------------------------------------


def _encrypted_machine_cert(private_key, enc: str) -> str:
    """Sign an arbitrary `enc` string as an encrypted machine-file certificate."""
    return _cert_from_enc_string(
        private_key, enc, "aes-256-gcm+ed25519+v2", MACHINE_PEM_HEADER, MACHINE_PEM_FOOTER
    )


def _encrypt_machine_payload(license_key: str, fingerprint: str) -> tuple[bytes, bytes]:
    """AES-256-GCM-encrypt a minimal valid v2 payload, returning (nonce, ciphertext+tag)."""
    import os

    payload = {
        "data": {
            "id": "018f2f3a-0000-7000-8000-000000000042",
            "type": "machines",
            "attributes": {"fingerprint": fingerprint},
        },
        "meta": V2_CLAIMS,
    }
    aesgcm = AESGCM(derive_machine_file_key(license_key, fingerprint))
    nonce = os.urandom(12)
    return nonce, aesgcm.encrypt(nonce, json.dumps(payload).encode("utf-8"), None)


def test_encrypted_machine_file_enc_with_junk_characters_is_rejected(
    ed25519_keypair, sample_license_key: str
) -> None:  # type: ignore[no-untyped-def]
    """The strongest symptom of the single-blob misreading.

    A non-validating `base64.b64decode` drops every character outside the alphabet, so
    an `enc` peppered with junk decodes to exactly the same bytes and the file opens as
    if nothing were wrong. Decoding each half strictly refuses it instead.
    """
    private_key, public_key = ed25519_keypair
    fingerprint = "fp-junk-characters"
    nonce, ciphertext_and_tag = _encrypt_machine_payload(sample_license_key, fingerprint)
    cipher_b64 = base64.b64encode(ciphertext_and_tag).decode("ascii")
    enc = f"{base64.b64encode(nonce).decode('ascii')}.{cipher_b64[:8]}*! \n{cipher_b64[8:]}"
    machine_file = MachineFile.parse(_encrypted_machine_cert(private_key, enc))

    with pytest.raises(ValueError, match="not valid base64"):
        machine_file.verify(
            public_key.public_bytes_raw(),
            LicenseScheme.ED25519_SIGN,
            license_key=sample_license_key,
            fingerprint=fingerprint,
        )


def test_encrypted_machine_file_enc_with_two_separators_is_rejected(
    ed25519_keypair, sample_license_key: str
) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    fingerprint = "fp-two-separators"
    nonce, ciphertext_and_tag = _encrypt_machine_payload(sample_license_key, fingerprint)
    cipher_b64 = base64.b64encode(ciphertext_and_tag).decode("ascii")
    enc = f"{base64.b64encode(nonce).decode('ascii')}.{cipher_b64[:8]}.{cipher_b64[8:]}"
    machine_file = MachineFile.parse(_encrypted_machine_cert(private_key, enc))

    with pytest.raises(ValueError, match="exactly one"):
        machine_file.verify(
            public_key.public_bytes_raw(),
            LicenseScheme.ED25519_SIGN,
            license_key=sample_license_key,
            fingerprint=fingerprint,
        )


def test_encrypted_machine_file_enc_with_wrong_length_nonce_is_rejected(
    ed25519_keypair, sample_license_key: str
) -> None:  # type: ignore[no-untyped-def]
    """A short nonce half must be named as such, not silently re-sliced off the payload."""
    private_key, public_key = ed25519_keypair
    fingerprint = "fp-short-nonce"
    nonce, ciphertext_and_tag = _encrypt_machine_payload(sample_license_key, fingerprint)
    enc = (
        f"{base64.b64encode(nonce[:6]).decode('ascii')}."
        f"{base64.b64encode(ciphertext_and_tag).decode('ascii')}"
    )
    machine_file = MachineFile.parse(_encrypted_machine_cert(private_key, enc))

    with pytest.raises(ValueError, match="nonce is 6 bytes"):
        machine_file.verify(
            public_key.public_bytes_raw(),
            LicenseScheme.ED25519_SIGN,
            license_key=sample_license_key,
            fingerprint=fingerprint,
        )


def test_encrypted_machine_file_ciphertext_too_short_for_a_tag_is_rejected(
    ed25519_keypair, sample_license_key: str
) -> None:  # type: ignore[no-untyped-def]
    """A ciphertext half shorter than the GCM tag cannot be authenticated at all."""
    private_key, public_key = ed25519_keypair
    fingerprint = "fp-short-ciphertext"
    nonce, _ = _encrypt_machine_payload(sample_license_key, fingerprint)
    enc = f"{base64.b64encode(nonce).decode('ascii')}.{base64.b64encode(b'tiny').decode('ascii')}"
    machine_file = MachineFile.parse(_encrypted_machine_cert(private_key, enc))

    with pytest.raises(ValueError, match="ciphertext is too short"):
        machine_file.verify(
            public_key.public_bytes_raw(),
            LicenseScheme.ED25519_SIGN,
            license_key=sample_license_key,
            fingerprint=fingerprint,
        )


def test_encrypted_license_file_payload_too_short_for_a_nonce_and_tag_is_rejected(
    ed25519_keypair, sample_license_key: str
) -> None:  # type: ignore[no-untyped-def]
    """A `.lic` blob shorter than a 12-byte nonce plus a 16-byte GCM tag.

    The single-blob layout's counterpart to the machine file's separate
    nonce/ciphertext length checks above: slicing 12 bytes off a shorter blob
    would hand AES-GCM a truncated nonce and an empty ciphertext rather than
    saying what is actually wrong.
    """
    private_key, public_key = ed25519_keypair
    enc = base64.b64encode(b"tooshort").decode("ascii")
    certificate = _cert_from_enc_string(private_key, enc, ALG_ENCRYPTED, PEM_HEADER, PEM_FOOTER)

    with pytest.raises(ValueError, match="too short to contain"):
        LicenseFile.parse(certificate).verify(
            public_key.public_bytes_raw(), license_key=sample_license_key
        )


def test_encrypted_machine_file_missing_separator_is_rejected(
    ed25519_keypair, sample_license_key: str
) -> None:  # type: ignore[no-untyped-def]
    """The single-blob layout itself -- the shape every SDK wrongly assumed."""
    private_key, public_key = ed25519_keypair
    fingerprint = "fp-single-blob"
    nonce, ciphertext_and_tag = _encrypt_machine_payload(sample_license_key, fingerprint)
    enc = base64.b64encode(nonce + ciphertext_and_tag).decode("ascii")
    machine_file = MachineFile.parse(_encrypted_machine_cert(private_key, enc))

    with pytest.raises(ValueError, match="exactly one"):
        machine_file.verify(
            public_key.public_bytes_raw(),
            LicenseScheme.ED25519_SIGN,
            license_key=sample_license_key,
            fingerprint=fingerprint,
        )


# ---------------------------------------------------------------------------
# Signed-claims edge cases surfaced by the security-reviewer pass. Both are
# only reachable behind a valid signature (and, for encrypted files, a valid
# GCM tag), so neither is an auth bypass -- but both escaped the documented
# `Raises: ValueError` contract, which a caller written as
# `except (ValueError, LicenseFileExpired):` would not catch.
# ---------------------------------------------------------------------------


def test_machine_file_infinite_exp_claim_raises_clear_value_error(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    """`json.loads` accepts the non-standard `Infinity` token; `int(inf)` is an OverflowError."""
    private_key, public_key = ed25519_keypair
    payload = {
        "data": {"id": "018f2f3a-0000-7000-8000-000000000043", "type": "machines"},
        "meta": {**V2_CLAIMS, "exp": float("inf")},
    }
    cert = _cert_with_raw_enc_bytes(
        private_key,
        json.dumps(payload).encode("utf-8"),
        "base64+ed25519+v2",
        MACHINE_PEM_HEADER,
        MACHINE_PEM_FOOTER,
    )
    machine_file = MachineFile.parse(cert)

    with pytest.raises(ValueError, match="bad 'meta' claims"):
        machine_file.verify(public_key.public_bytes_raw(), LicenseScheme.ED25519_SIGN)


def test_license_file_infinite_exp_claim_raises_clear_value_error(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    """Same claim parser, same guarantee, on the `.lic` path."""
    private_key, public_key = ed25519_keypair
    payload = {
        "data": {"id": "018f2f3a-0000-7000-8000-000000000044", "type": "licenses"},
        "meta": {**V2_CLAIMS, "exp": float("-inf")},
    }
    cert = _cert_with_raw_enc_bytes(
        private_key, json.dumps(payload).encode("utf-8"), ALG_PLAIN, PEM_HEADER, PEM_FOOTER
    )
    license_file = LicenseFile.parse(cert)

    with pytest.raises(ValueError, match="bad 'meta' claims"):
        license_file.verify(public_key.public_bytes_raw())


def test_machine_file_non_object_data_raises_clear_value_error(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    """A `data` that is present but not an object must not leak an AttributeError."""
    private_key, public_key = ed25519_keypair
    payload = {"data": ["not", "an", "object"], "meta": V2_CLAIMS}
    cert = _cert_with_raw_enc_bytes(
        private_key,
        json.dumps(payload).encode("utf-8"),
        "base64+ed25519+v2",
        MACHINE_PEM_HEADER,
        MACHINE_PEM_FOOTER,
    )
    machine_file = MachineFile.parse(cert)

    with pytest.raises(ValueError, match="'data' is not a JSON object"):
        machine_file.verify(public_key.public_bytes_raw(), LicenseScheme.ED25519_SIGN)


# ---------------------------------------------------------------------------
# The rest of the `data` shape. The `isinstance(data, dict)` guard above only
# closed half the gap: `data["id"]`/`data["type"]` are bare subscripts and
# `attributes`/`relationships` were read without a type check, so a KeyError,
# a TypeError or an AttributeError still escaped the documented
# `Raises: ValueError` on both verify()s. All are behind a valid signature --
# a contract gap, not a bypass. Found by the mandatory security-reviewer pass
# on the machine-file v2 work.
# ---------------------------------------------------------------------------


def _machine_cert(private_key, payload: dict) -> str:
    return _cert_with_raw_enc_bytes(
        private_key,
        json.dumps(payload).encode("utf-8"),
        "base64+ed25519+v2",
        MACHINE_PEM_HEADER,
        MACHINE_PEM_FOOTER,
    )


def _license_cert(private_key, payload: dict) -> str:
    return _cert_with_raw_enc_bytes(
        private_key, json.dumps(payload).encode("utf-8"), ALG_PLAIN, PEM_HEADER, PEM_FOOTER
    )


def test_machine_file_data_without_id_raises_clear_value_error(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    """`data["id"]` is a bare subscript -- a missing key must not leak a KeyError."""
    private_key, public_key = ed25519_keypair
    cert = _machine_cert(private_key, {"data": {"type": "machines"}, "meta": V2_CLAIMS})

    with pytest.raises(ValueError, match="'data' is missing 'id'"):
        MachineFile.parse(cert).verify(public_key.public_bytes_raw(), LicenseScheme.ED25519_SIGN)


@pytest.mark.parametrize("attributes", [["a"], "s", 7, True])
def test_machine_file_non_object_attributes_raises_clear_value_error(  # type: ignore[no-untyped-def]
    ed25519_keypair, attributes: object
) -> None:
    """A non-object `attributes` reaches `.get` and would raise AttributeError."""
    private_key, public_key = ed25519_keypair
    payload = {"data": {"id": "x", "attributes": attributes}, "meta": V2_CLAIMS}
    cert = _machine_cert(private_key, payload)

    with pytest.raises(ValueError, match="'data.attributes' is not a JSON object"):
        MachineFile.parse(cert).verify(public_key.public_bytes_raw(), LicenseScheme.ED25519_SIGN)


def test_machine_file_null_attributes_is_treated_as_absent(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    """Guard against an overcorrection: an explicit null is 'no attributes', not an error.

    Matches the leniency `metadata=attributes.get("metadata", {}) or {}` already applies
    one line down, and the absent-`attributes` case that has always worked.
    """
    private_key, public_key = ed25519_keypair
    cert = _machine_cert(private_key, {"data": {"id": "x", "attributes": None}, "meta": V2_CLAIMS})

    machine = MachineFile.parse(cert).verify(
        public_key.public_bytes_raw(), LicenseScheme.ED25519_SIGN
    )
    assert machine.fingerprint == ""
    assert machine.heartbeat_status is HeartbeatStatus.NOT_STARTED


@pytest.mark.parametrize("data", [["not", "an", "object"], "a string", 7])
def test_license_file_non_object_data_raises_clear_value_error(  # type: ignore[no-untyped-def]
    ed25519_keypair, data: object
) -> None:
    """The `.lic` path never got the machine path's `isinstance(data, dict)` guard.

    Without it `data["id"]` raises TypeError -- not even in the same family as the
    documented ValueError.
    """
    private_key, public_key = ed25519_keypair
    cert = _license_cert(private_key, {"data": data, "meta": V2_CLAIMS})

    with pytest.raises(ValueError, match="'data' is not a JSON object"):
        LicenseFile.parse(cert).verify(public_key.public_bytes_raw())


@pytest.mark.parametrize(
    ("data", "missing"),
    [({"type": "licenses"}, "id"), ({"id": "x"}, "type")],
)
def test_license_file_data_missing_id_or_type_raises_clear_value_error(  # type: ignore[no-untyped-def]
    ed25519_keypair, data: dict, missing: str
) -> None:
    private_key, public_key = ed25519_keypair
    cert = _license_cert(private_key, {"data": data, "meta": V2_CLAIMS})

    with pytest.raises(ValueError, match=f"'data' is missing '{missing}'"):
        LicenseFile.parse(cert).verify(public_key.public_bytes_raw())


@pytest.mark.parametrize("key", ["attributes", "relationships"])
def test_license_file_non_object_attributes_or_relationships_is_refused(  # type: ignore[no-untyped-def]
    ed25519_keypair, key: str
) -> None:
    """Both are declared `dict[str, Any]`; storing a list defers the crash to the caller."""
    private_key, public_key = ed25519_keypair
    data = {"id": "x", "type": "licenses", key: ["not", "an", "object"]}
    cert = _license_cert(private_key, {"data": data, "meta": V2_CLAIMS})

    with pytest.raises(ValueError, match=f"'data.{key}' is not a JSON object"):
        LicenseFile.parse(cert).verify(public_key.public_bytes_raw())


@pytest.mark.parametrize("key", ["attributes", "relationships"])
def test_license_file_null_attributes_or_relationships_is_treated_as_absent(  # type: ignore[no-untyped-def]
    ed25519_keypair, key: str
) -> None:
    """Overcorrection guard, mirroring the machine-file null case."""
    private_key, public_key = ed25519_keypair
    data = {"id": "x", "type": "licenses", key: None}
    cert = _license_cert(private_key, {"data": data, "meta": V2_CLAIMS})

    license_resource = LicenseFile.parse(cert).verify(public_key.public_bytes_raw())
    assert license_resource.attributes == {}
    assert license_resource.relationships == {}


# ---------------------------------------------------------------------------
# The `.lic` path decodes strictly too. The machine-file path was made strict
# in this PR; leaving `LicenseFile` on a non-validating `base64.b64decode` kept
# exactly the laxity that hid the `<nonce_b64>.<cipher_b64>` misreading for two
# years -- silently discarding whatever it does not recognize. Reaching it
# needs a certificate signed *over* the junk, which is why it takes the
# keypair fixture: the signature covers `enc`'s exact bytes, so no
# third party can steer a genuine file down here. LOW finding from the
# mandatory security-reviewer pass.
# ---------------------------------------------------------------------------


def test_license_file_enc_with_junk_characters_is_rejected(ed25519_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = ed25519_keypair
    payload = {"data": {"id": "x", "type": "licenses"}, "meta": V2_CLAIMS}
    clean = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    enc = f"{clean[:8]}*! \n{clean[8:]}"
    cert = _cert_from_enc_string(private_key, enc, ALG_PLAIN, PEM_HEADER, PEM_FOOTER)

    with pytest.raises(ValueError, match="not valid base64"):
        LicenseFile.parse(cert).verify(public_key.public_bytes_raw())


def test_license_file_verify_with_claims_decrypts_exactly_once(  # type: ignore[no-untyped-def]
    ed25519_keypair, sample_license_key: str, monkeypatch
) -> None:
    """It used to call verify() and then redo the whole decode/HKDF/AES-GCM pass.

    Two decrypts per file, plus an `assert license_key is not None` that `python -O`
    strips out. Both go away by running the shared pipeline once.
    """
    private_key, public_key = ed25519_keypair
    payload = {"data": {"id": "x", "type": "licenses"}, "meta": V2_CLAIMS}
    key = derive_license_file_key(sample_license_key)
    nonce = os.urandom(12)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, json.dumps(payload).encode("utf-8"), None)
    enc = base64.b64encode(nonce + ciphertext_and_tag).decode("ascii")
    cert = _cert_from_enc_string(private_key, enc, ALG_ENCRYPTED, PEM_HEADER, PEM_FOOTER)

    calls = []
    real_decrypt = license_file_module.aes_gcm_decrypt

    def counting_decrypt(*args: object, **kwargs: object) -> bytes:
        calls.append(1)
        return real_decrypt(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(license_file_module, "aes_gcm_decrypt", counting_decrypt)

    license_resource, claims = LicenseFile.parse(cert).verify_with_claims(
        public_key.public_bytes_raw(), license_key=sample_license_key
    )

    assert len(calls) == 1
    assert str(license_resource.id) == "x"
    assert claims.jti == V2_CLAIMS["jti"]


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
