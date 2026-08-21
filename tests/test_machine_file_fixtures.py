"""Machine-file verification against certificates the *server* produced.

⚠️ Crypto-bearing — changes here require a mandatory security-reviewer pass.

Every certificate under ``tests/fixtures/machine_files/`` came out of the server's own
``encode_machine_file``; none was produced by this SDK. See that directory's README for
why that distinction is the entire point of this module: offline machine-file
verification was broken here for two years while a green suite of round-trip tests
encoded certificates using the same wrong assumptions it then decoded them with.

The tests iterate ``manifest.json`` rather than naming fixtures, so a new scheme or
variant is picked up by dropping the file and its manifest entry in place.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from tamga.checkout.license_file import LicenseFileExpired
from tamga.checkout.machine_file import (
    PEM_FOOTER,
    PEM_HEADER,
    VALID_ALGORITHMS,
    MachineFile,
    MachineFileExpired,
)
from tamga.errors import SchemeNotSupportedError
from tamga.models.machine import HeartbeatStatus
from tamga.models.policy import LicenseScheme

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "machine_files"
MANIFEST: dict[str, dict[str, Any]] = json.loads(
    (FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8")
)

ALL_FIXTURES = sorted(MANIFEST)
ENCRYPTED_FIXTURES = [n for n in ALL_FIXTURES if MANIFEST[n]["encrypted"]]
EXPIRED_FIXTURES = [n for n in ALL_FIXTURES if MANIFEST[n]["expired"]]
UNEXPIRED_FIXTURES = [n for n in ALL_FIXTURES if not MANIFEST[n]["expired"]]

#: The manifest names schemes by their server-side (Rust) variant, which is the
#: authoritative spelling; this SDK's enum uses the wire strings.
SERVER_SCHEME_TO_SDK = {
    "Ed25519Sign": LicenseScheme.ED25519_SIGN,
    "EcdsaP256Sign": LicenseScheme.ECDSA_P256_SIGN,
    "Rsa2048Pkcs1Sign": LicenseScheme.RSA_2048_PKCS1_SIGN,
    "Rsa2048Pkcs1PssSign": LicenseScheme.RSA_2048_PKCS1_PSS_SIGN,
}

#: A reference clock from before any fixture was issued. Used only to read the signed
#: claims back out; every real assertion about expiry then pins `now` to the file's own
#: signed `iat`, which is stable forever, instead of the wall clock (the `valid`
#: fixtures expire an hour after they were generated).
BEFORE_ANY_FIXTURE_WAS_ISSUED = 0


def _entry(name: str) -> dict[str, Any]:
    return MANIFEST[name]


def _parse(name: str) -> MachineFile:
    return MachineFile.parse((FIXTURE_DIR / _entry(name)["file"]).read_text(encoding="utf-8"))


def _public_key(name: str) -> bytes:
    return base64.b64decode(_entry(name)["public_key_b64"])


def _scheme(name: str) -> LicenseScheme:
    return SERVER_SCHEME_TO_SDK[_entry(name)["scheme"]]


def _secrets(name: str) -> dict[str, Any]:
    """The `license_key`/`fingerprint` HKDF inputs, empty for a plain file."""
    entry = _entry(name)
    if not entry["encrypted"]:
        return {}
    return {"license_key": entry["license_key"], "fingerprint": entry["fingerprint"]}


def _claims(name: str) -> Any:
    """Read the signed claims back without tripping the expiry check."""
    _, claims = _parse(name).verify_with_claims(
        _public_key(name),
        _scheme(name),
        now=BEFORE_ANY_FIXTURE_WAS_ISSUED,
        **_secrets(name),
    )
    return claims


def _rewrap(machine_file: MachineFile, **overrides: str) -> str:
    """Re-wrap a parsed certificate as PEM, optionally corrupting an unsigned field.

    Only `alg` is ever overridden here. It sits in the outer envelope beside `enc`/`sig`
    and is *not* covered by the signature, so rewriting it is exactly what a tampering
    transport or storage layer can do to a genuine, correctly-signed file.
    """
    cert = {
        "enc": machine_file.enc,
        "sig": base64.b64encode(machine_file.sig).decode("ascii"),
        "alg": machine_file.alg,
        **overrides,
    }
    body = base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")
    return f"{PEM_HEADER}\n{body}\n{PEM_FOOTER}"


def test_manifest_and_fixture_directory_agree() -> None:
    on_disk = {p.name for p in FIXTURE_DIR.glob("*.machine")}
    in_manifest = {entry["file"] for entry in MANIFEST.values()}
    assert on_disk == in_manifest
    assert ALL_FIXTURES, "manifest is empty — the fixture set failed to load"


def test_every_manifest_scheme_is_mapped() -> None:
    """A fixture for a scheme this SDK cannot name should fail loudly, here."""
    assert {entry["scheme"] for entry in MANIFEST.values()} <= set(SERVER_SCHEME_TO_SDK)


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_parse_accepts_the_alg_the_server_emits(name: str) -> None:
    """M1: every `alg` the server produces carries `+v2` and must be accepted."""
    parsed = _parse(name)
    assert parsed.alg == _entry(name)["alg"]
    assert parsed.alg in VALID_ALGORITHMS
    assert parsed.alg.endswith("+v2")


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_enc_shape_matches_the_encoding_prefix(name: str) -> None:
    """M2: an encrypted `enc` is a dot-separated pair; a plain one is a single blob."""
    entry = _entry(name)
    parsed = _parse(name)
    assert ("." in parsed.enc) is entry["enc_is_dot_separated"]
    assert entry["enc_is_dot_separated"] is entry["encrypted"]
    if entry["encrypted"]:
        nonce_b64, _, cipher_b64 = parsed.enc.partition(".")
        # Independently decodable halves — the whole point of M2.
        assert len(base64.b64decode(nonce_b64, validate=True)) == 12
        assert len(base64.b64decode(cipher_b64, validate=True)) > 16


@pytest.mark.parametrize("name", UNEXPIRED_FIXTURES)
def test_valid_fixture_verifies_and_returns_the_machine(name: str) -> None:
    """M1 + M2: a live server-produced file opens and yields its payload."""
    entry = _entry(name)
    claims = _claims(name)
    machine = _parse(name).verify(
        _public_key(name),
        _scheme(name),
        now=claims.iat,
        **_secrets(name),
    )
    assert machine.fingerprint == entry["fingerprint"]
    assert str(machine.id)
    assert isinstance(machine.heartbeat_status, HeartbeatStatus)


@pytest.mark.parametrize("name", EXPIRED_FIXTURES)
def test_expired_fixture_is_rejected_as_expired_not_as_forged(name: str) -> None:
    """M3: an authentic-but-expired file must be a distinct outcome from a bad signature."""
    claims = _claims(name)
    assert claims.exp is not None
    with pytest.raises(MachineFileExpired) as excinfo:
        _parse(name).verify(
            _public_key(name),
            _scheme(name),
            now=claims.iat,
            **_secrets(name),
        )
    assert excinfo.value.exp == claims.exp
    # Reuses the licence-file path's outcome, so one `except` covers both file types...
    assert isinstance(excinfo.value, LicenseFileExpired)
    # ...and is emphatically not confusable with a forgery.
    assert not isinstance(excinfo.value, InvalidSignature)


@pytest.mark.parametrize("name", EXPIRED_FIXTURES)
def test_expired_fixture_is_rejected_against_the_local_clock_too(name: str) -> None:
    """The `now` hatch is optional: with no timestamp supplied the system clock applies.

    Stable forever — these fixtures expired before they were issued.
    """
    with pytest.raises(MachineFileExpired):
        _parse(name).verify(_public_key(name), _scheme(name), **_secrets(name))


@pytest.mark.parametrize("name", UNEXPIRED_FIXTURES)
def test_unexpired_fixture_is_rejected_once_its_exp_has_passed(name: str) -> None:
    """M3: expiry is enforced, not merely parsed — the same file fails later on."""
    claims = _claims(name)
    assert claims.exp is not None
    with pytest.raises(MachineFileExpired):
        _parse(name).verify(
            _public_key(name),
            _scheme(name),
            now=claims.exp + 61,
            **_secrets(name),
        )


@pytest.mark.parametrize("name", UNEXPIRED_FIXTURES)
def test_clock_skew_tolerance_is_honoured_but_small(name: str) -> None:
    """A file one second past `exp` still opens; a minute past it does not."""
    claims = _claims(name)
    assert claims.exp is not None
    machine = _parse(name).verify(
        _public_key(name), _scheme(name), now=claims.exp + 1, **_secrets(name)
    )
    assert machine.fingerprint == _entry(name)["fingerprint"]


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_verify_with_claims_exposes_the_signed_claims(name: str) -> None:
    """M3: `iat`/`jti`/`kid` travel inside the signature and must be readable."""
    entry = _entry(name)
    claims = _claims(name)
    assert claims.kid == entry["kid"]
    assert claims.iat > 0
    assert claims.jti
    assert claims.exp is not None
    assert (claims.exp < claims.iat) is entry["expired"]


@pytest.mark.parametrize("name", ENCRYPTED_FIXTURES)
def test_wrong_fingerprint_fails_decryption(name: str) -> None:
    """The fingerprint is HKDF `info`: a machine file only opens on its own machine."""
    entry = _entry(name)
    with pytest.raises(InvalidTag):
        _parse(name).verify(
            _public_key(name),
            _scheme(name),
            license_key=entry["license_key"],
            fingerprint="not-the-machine-this-was-issued-for",
            now=_claims(name).iat,
        )


@pytest.mark.parametrize("name", ENCRYPTED_FIXTURES)
def test_wrong_license_key_fails_decryption(name: str) -> None:
    entry = _entry(name)
    with pytest.raises(InvalidTag):
        _parse(name).verify(
            _public_key(name),
            _scheme(name),
            license_key="TAMGA-NOT-THE-RIGHT-LICENSE-KEY",
            fingerprint=entry["fingerprint"],
            now=_claims(name).iat,
        )


@pytest.mark.parametrize("name", ENCRYPTED_FIXTURES)
def test_encrypted_fixture_needs_both_hkdf_inputs(name: str) -> None:
    entry = _entry(name)
    parsed = _parse(name)
    with pytest.raises(ValueError, match="license_key and fingerprint"):
        parsed.verify(_public_key(name), _scheme(name), fingerprint=entry["fingerprint"])
    with pytest.raises(ValueError, match="license_key and fingerprint"):
        parsed.verify(_public_key(name), _scheme(name), license_key=entry["license_key"])


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_tampered_enc_fails_the_signature_before_any_decode(name: str) -> None:
    """Order matters: authenticate first, never decode attacker-controlled bytes first.

    `enc` is replaced with something that is neither valid base64 nor a valid
    `<nonce_b64>.<cipher_b64>` pair, and no HKDF inputs are supplied. An implementation
    that decoded, split or demanded the decryption inputs before checking the signature
    surfaces a `ValueError`/`binascii.Error` here instead of `InvalidSignature`.
    """
    parsed = _parse(name)
    tampered = MachineFile(enc="!!! not base64 !!!", sig=parsed.sig, alg=parsed.alg)
    with pytest.raises(InvalidSignature):
        tampered.verify(_public_key(name), _scheme(name))


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_flipped_enc_byte_fails_the_signature(name: str) -> None:
    parsed = _parse(name)
    flipped = "B" if parsed.enc[0] != "B" else "C"
    tampered = MachineFile(enc=flipped + parsed.enc[1:], sig=parsed.sig, alg=parsed.alg)
    with pytest.raises(InvalidSignature):
        tampered.verify(_public_key(name), _scheme(name), **_secrets(name))


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_alg_stripped_of_its_v2_marker_is_rejected(name: str) -> None:
    """M1: a pre-v2 file has no signed `exp`, so accepting one reinstates the old hole."""
    parsed = _parse(name)
    v1_alg = parsed.alg[: -len("+v2")]
    assert v1_alg not in VALID_ALGORITHMS
    with pytest.raises(ValueError, match="v2"):
        MachineFile.parse(_rewrap(parsed, alg=v1_alg))
    with pytest.raises(ValueError, match="v2"):
        MachineFile(enc=parsed.enc, sig=parsed.sig, alg=v1_alg).verify(
            _public_key(name), _scheme(name), **_secrets(name)
        )


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_corrupted_alg_outside_the_closed_vocabulary_is_rejected(name: str) -> None:
    parsed = _parse(name)
    with pytest.raises(ValueError, match="unsupported machine file algorithm"):
        MachineFile.parse(_rewrap(parsed, alg="base64+not-a-real-alg+v2"))
    # A substring check would wave through both of these.
    with pytest.raises(ValueError, match="unsupported machine file algorithm"):
        MachineFile.parse(_rewrap(parsed, alg=parsed.alg + "junk"))
    with pytest.raises(ValueError, match="unsupported machine file algorithm"):
        MachineFile.parse(_rewrap(parsed, alg="x" + parsed.alg))


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_scheme_from_the_caller_is_cross_checked_against_alg(name: str) -> None:
    """`alg` never selects the verifier, but a mismatch is still refused up front."""
    scheme = _scheme(name)
    other = next(s for s in SERVER_SCHEME_TO_SDK.values() if s is not scheme)
    with pytest.raises(ValueError, match="does not match the license's scheme"):
        _parse(name).verify(_public_key(name), other, **_secrets(name))


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_jwt_rs256_is_refused_before_any_crypto(name: str) -> None:
    with pytest.raises(SchemeNotSupportedError):
        _parse(name).verify(_public_key(name), LicenseScheme.RSA_2048_JWT_RS256, **_secrets(name))


def test_rsa_sha256_alg_cannot_identify_the_scheme() -> None:
    """The server emits `rsa-sha256` for both PKCS1 and JWT RS256.

    Same bytes, same `alg`, two different caller-supplied schemes, two different
    outcomes — the concrete proof that `scheme` is authoritative and `alg` is only ever
    a cross-check.
    """
    name = "rsa_pkcs1_plain_valid"
    parsed = _parse(name)
    assert parsed.alg == "base64+rsa-sha256+v2"

    with pytest.raises(SchemeNotSupportedError):
        parsed.verify(_public_key(name), LicenseScheme.RSA_2048_JWT_RS256)

    machine = parsed.verify(
        _public_key(name), LicenseScheme.RSA_2048_PKCS1_SIGN, now=_claims(name).iat
    )
    assert machine.fingerprint == _entry(name)["fingerprint"]


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_another_fixtures_public_key_fails_verification(name: str) -> None:
    """A key mix-up must fail closed, whatever key family it belongs to."""
    other = next(n for n in ALL_FIXTURES if _entry(n)["kid"] != _entry(name)["kid"])
    with pytest.raises(InvalidSignature):
        _parse(name).verify(_public_key(other), _scheme(name), **_secrets(name))
