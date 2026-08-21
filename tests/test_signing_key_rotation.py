"""Offline verification against a key set: the rotation defect, and its blast radius.

⚠️ Crypto-bearing — changes here require a mandatory security-reviewer pass.

The defect: a ``.lic`` or machine file signed *before* the account rotated its Ed25519
signing key is authentic, but against the one current key it fails with exactly the error
a forgery produces. A paying customer with a valid file is refused, and the error sends
support at the wrong problem.

So the assertions that matter here are the ones separating outcomes that used to be
identical:

* signed by a retired key the set holds  -> verifies, and says which key
* names a key the set does **not** hold  -> ``UnknownSigningKeyError``  (refresh the set)
* names a key the set **does** hold      -> ``InvalidSignature``        (forged)
* names the empty key                    -> ``SigningKeyNotPublishedError`` (server-side)

The machine-file half runs against certificates the *server* produced
(``tests/fixtures/machine_files/``), never ones this SDK encoded.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tamga.checkout.key_set import (
    NoUsableSigningKeyError,
    SigningKeyError,
    SigningKeyNotApplicableError,
    SigningKeyNotPublishedError,
    SigningKeySet,
    UnknownSigningKeyError,
)
from tamga.checkout.license_file import (
    ALG_ENCRYPTED,
    ALG_PLAIN,
    PEM_FOOTER,
    PEM_HEADER,
    LicenseFile,
    LicenseFileExpired,
    VerifiedLicenseFile,
)
from tamga.checkout.machine_file import MachineFile, VerifiedMachineFile
from tamga.crypto.ed25519 import UNBACKFILLED_ACCOUNT_KEY_ID, key_id
from tamga.crypto.hkdf import derive_license_file_key
from tamga.errors import SchemeNotSupportedError
from tamga.models.policy import LicenseScheme
from tamga.models.signing_key import ACTIVE_STATUS, RETIRED_STATUS, SigningKey

MACHINE_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "machine_files"
MACHINE_MANIFEST: dict[str, dict[str, Any]] = json.loads(
    (MACHINE_FIXTURE_DIR / "manifest.json").read_text()
)

#: Far enough in the past that no fixture's signed `exp` has been reached, so the
#: `valid` fixtures (which expire an hour after generation) stay verifiable forever.
BEFORE_ANY_FIXTURE_WAS_ISSUED = 0

LICENSE_ID = "018f2f3a-0000-7000-8000-000000000030"


def _published(public_key: ed25519.Ed25519PublicKey) -> str:
    """A public key in the form the server publishes: standard base64 of the raw 32."""
    return base64.b64encode(public_key.public_bytes_raw()).decode("ascii")


def _payload(kid: str, exp: int | None = None) -> dict[str, Any]:
    meta: dict[str, Any] = {"iat": 1767225600, "jti": "test-jti", "kid": kid}
    if exp is not None:
        meta["exp"] = exp
    return {
        "data": {
            "id": LICENSE_ID,
            "type": "licenses",
            "attributes": {"key": "TEST-LICENSE-KEY", "status": "ACTIVE"},
        },
        "meta": meta,
    }


def _certificate(enc: str, sig: bytes, alg: str) -> str:
    cert = {
        "enc": enc,
        "sig": base64.b64encode(sig).decode("ascii"),
        "alg": alg,
    }
    body = base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")
    return f"{PEM_HEADER}\n{body}\n{PEM_FOOTER}"


def _plain_lic(private_key: ed25519.Ed25519PrivateKey, payload: dict[str, Any]) -> LicenseFile:
    enc = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    # ⚠️ sign the base64 STRING bytes, never the decoded bytes.
    return LicenseFile.parse(_certificate(enc, private_key.sign(enc.encode("ascii")), ALG_PLAIN))


def _encrypted_lic(
    private_key: ed25519.Ed25519PrivateKey, payload: dict[str, Any], license_key: str
) -> LicenseFile:
    nonce = os.urandom(12)
    sealed = AESGCM(derive_license_file_key(license_key)).encrypt(
        nonce, json.dumps(payload).encode("utf-8"), None
    )
    enc = base64.b64encode(nonce + sealed).decode("ascii")
    return LicenseFile.parse(
        _certificate(enc, private_key.sign(enc.encode("ascii")), ALG_ENCRYPTED)
    )


@pytest.fixture
def rotated_account() -> dict[str, Any]:
    """An account that has rotated once: an active key and the retired one before it."""
    retired_private = ed25519.Ed25519PrivateKey.generate()
    active_private = ed25519.Ed25519PrivateKey.generate()
    retired_public = _published(retired_private.public_key())
    active_public = _published(active_private.public_key())
    return {
        "retired_private": retired_private,
        "active_private": active_private,
        "retired_public": retired_public,
        "active_public": active_public,
        "retired_kid": key_id(retired_public),
        "active_kid": key_id(active_public),
        "key_set": SigningKeySet(
            [
                SigningKey.ed25519(active_public, status=ACTIVE_STATUS),
                SigningKey.ed25519(retired_public, status=RETIRED_STATUS),
            ]
        ),
    }


class TestLicenseFileKeySetVerification:
    def test_a_file_signed_before_the_rotation_still_verifies(
        self, rotated_account: dict[str, Any]
    ) -> None:
        """The defect, stated as a passing test."""
        file = _plain_lic(
            rotated_account["retired_private"], _payload(rotated_account["retired_kid"])
        )

        verified = file.verify_with_key_set(rotated_account["key_set"])

        assert isinstance(verified, VerifiedLicenseFile)
        assert str(verified.license.id) == LICENSE_ID
        assert verified.claims.kid == rotated_account["retired_kid"]
        assert verified.key.kid == rotated_account["retired_kid"]
        assert verified.key.is_retired, "the caller must be able to see this file is stale"

    def test_a_file_signed_by_the_current_key_verifies_and_is_not_retired(
        self, rotated_account: dict[str, Any]
    ) -> None:
        file = _plain_lic(
            rotated_account["active_private"], _payload(rotated_account["active_kid"])
        )

        verified = file.verify_with_key_set(rotated_account["key_set"])

        assert verified.key.kid == rotated_account["active_kid"]
        assert not verified.key.is_retired

    def test_a_key_the_set_does_not_hold_is_not_reported_as_a_forgery(
        self, rotated_account: dict[str, Any]
    ) -> None:
        """The support-desk half of the defect: 'my keys are stale', not 'refuse them'."""
        stale_set = SigningKeySet.from_public_keys([rotated_account["active_public"]])
        file = _plain_lic(
            rotated_account["retired_private"], _payload(rotated_account["retired_kid"])
        )

        with pytest.raises(UnknownSigningKeyError) as caught:
            file.verify_with_key_set(stale_set)

        assert caught.value.kid == rotated_account["retired_kid"]
        assert caught.value.available == (rotated_account["active_kid"],)
        assert not isinstance(caught.value, SigningKeyNotPublishedError)

    def test_a_forgery_naming_a_key_in_the_set_is_still_a_signature_failure(
        self, rotated_account: dict[str, Any]
    ) -> None:
        """The other half: this one really is forged, and must not look like rotation."""
        attacker = ed25519.Ed25519PrivateKey.generate()
        file = _plain_lic(attacker, _payload(rotated_account["active_kid"]))

        with pytest.raises(InvalidSignature):
            file.verify_with_key_set(rotated_account["key_set"])

    def test_a_tampered_payload_under_a_known_kid_is_a_signature_failure(
        self, rotated_account: dict[str, Any]
    ) -> None:
        signed = _plain_lic(
            rotated_account["active_private"], _payload(rotated_account["active_kid"])
        )
        tampered = LicenseFile(
            enc=base64.b64encode(
                json.dumps(_payload(rotated_account["active_kid"], exp=99999999999)).encode()
            ).decode("ascii"),
            sig=signed.sig,
            alg=signed.alg,
        )

        with pytest.raises(InvalidSignature):
            tampered.verify_with_key_set(rotated_account["key_set"])

    def test_the_empty_key_id_gets_its_own_condition(self, rotated_account: dict[str, Any]) -> None:
        """`key_id("")` means the *server* published no key; refetching cannot help."""
        orphan = ed25519.Ed25519PrivateKey.generate()
        file = _plain_lic(orphan, _payload(UNBACKFILLED_ACCOUNT_KEY_ID))

        with pytest.raises(SigningKeyNotPublishedError) as caught:
            file.verify_with_key_set(rotated_account["key_set"])

        assert caught.value.kid == UNBACKFILLED_ACCOUNT_KEY_ID
        # Still catchable as the broader condition, so a caller that only wants
        # "not verifiable with the keys I have" needs one `except`.
        assert isinstance(caught.value, UnknownSigningKeyError)
        assert "rotated" in str(caught.value)
        assert "not in the key set" not in str(caught.value)

    def test_an_empty_key_set_says_so_before_looking_at_the_file(
        self, rotated_account: dict[str, Any]
    ) -> None:
        file = _plain_lic(
            rotated_account["active_private"], _payload(rotated_account["active_kid"])
        )

        with pytest.raises(NoUsableSigningKeyError) as caught:
            file.verify_with_key_set(SigningKeySet())

        assert caught.value.available == ()
        assert "empty" in str(caught.value)

    def test_a_set_of_only_unusable_keys_is_not_an_unknown_key(
        self, rotated_account: dict[str, Any]
    ) -> None:
        unusable = SigningKeySet(
            [
                SigningKey(kid="future-alg", public_key="AAAA", algorithm="rsa2048"),
                SigningKey(kid="undecodable", public_key="not base64!!"),
            ]
        )
        file = _plain_lic(
            rotated_account["active_private"], _payload(rotated_account["active_kid"])
        )

        with pytest.raises(NoUsableSigningKeyError) as caught:
            file.verify_with_key_set(unusable)

        assert caught.value.available == ("future-alg", "undecodable")

    def test_an_encrypted_file_verifies_against_the_key_set(
        self, rotated_account: dict[str, Any], sample_license_key: str
    ) -> None:
        file = _encrypted_lic(
            rotated_account["retired_private"],
            _payload(rotated_account["retired_kid"]),
            sample_license_key,
        )

        verified = file.verify_with_key_set(rotated_account["key_set"], sample_license_key)

        assert verified.key.kid == rotated_account["retired_kid"]
        assert str(verified.license.id) == LICENSE_ID

    def test_an_encrypted_file_still_reports_an_unknown_key(
        self, rotated_account: dict[str, Any], sample_license_key: str
    ) -> None:
        """Reading the claim needs the payload decrypted, so this path is separate."""
        stale_set = SigningKeySet.from_public_keys([rotated_account["active_public"]])
        file = _encrypted_lic(
            rotated_account["retired_private"],
            _payload(rotated_account["retired_kid"]),
            sample_license_key,
        )

        with pytest.raises(UnknownSigningKeyError) as caught:
            file.verify_with_key_set(stale_set, sample_license_key)

        assert caught.value.kid == rotated_account["retired_kid"]

    def test_an_unreadable_claim_degrades_to_a_signature_failure(
        self, rotated_account: dict[str, Any], sample_license_key: str
    ) -> None:
        """No license key, so the `kid` cannot be read — that is not an unknown key."""
        file = _encrypted_lic(
            rotated_account["retired_private"],
            _payload(rotated_account["retired_kid"]),
            sample_license_key,
        )
        stale_set = SigningKeySet.from_public_keys([rotated_account["active_public"]])

        with pytest.raises(InvalidSignature):
            file.verify_with_key_set(stale_set)

    def test_expiry_is_still_enforced_on_the_key_set_path(
        self, rotated_account: dict[str, Any]
    ) -> None:
        """Selecting a key must not become a way around the signed `exp`."""
        file = _plain_lic(
            rotated_account["active_private"],
            _payload(rotated_account["active_kid"], exp=1767225600),
        )

        with pytest.raises(LicenseFileExpired):
            file.verify_with_key_set(rotated_account["key_set"], now=1767229200)

    def test_a_mislabelled_key_still_verifies_its_own_files(
        self, rotated_account: dict[str, Any]
    ) -> None:
        """Selection is by signature, so a wrong published `kid` costs nothing."""
        mislabelled = SigningKeySet(
            [SigningKey(kid="0000000000000000", public_key=rotated_account["active_public"])]
        )
        file = _plain_lic(
            rotated_account["active_private"], _payload(rotated_account["active_kid"])
        )

        verified = file.verify_with_key_set(mislabelled)

        assert verified.key.kid == "0000000000000000"
        assert mislabelled.inconsistent_keys == mislabelled.keys

    def test_the_payload_is_not_read_before_the_signature_passes(
        self, rotated_account: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ordering invariant this package is built on, asserted rather than described.

        On the happy path nothing may parse attacker-supplied bytes before something has
        vouched for them, so the unverified-claim probe must never run.
        """

        def _forbidden(self: LicenseFile, license_key: str | None) -> str | None:
            raise AssertionError("the unverified kid probe ran on the happy path")

        monkeypatch.setattr(LicenseFile, "_unverified_kid", _forbidden)
        file = _plain_lic(
            rotated_account["active_private"], _payload(rotated_account["active_kid"])
        )

        assert (
            file.verify_with_key_set(rotated_account["key_set"]).key.kid
            == (rotated_account["active_kid"])
        )

    @pytest.mark.parametrize(
        "raises",
        [
            pytest.param(NoUsableSigningKeyError, id="no_usable_key"),
            pytest.param(UnknownSigningKeyError, id="unknown_key"),
            pytest.param(SigningKeyNotPublishedError, id="not_published"),
            pytest.param(SigningKeyNotApplicableError, id="not_applicable"),
        ],
    )
    def test_every_new_failure_stays_inside_the_documented_value_error_contract(
        self, raises: type[Exception]
    ) -> None:
        """A caller written as the documented `except (ValueError, LicenseFileExpired):`
        must keep catching every rejection."""
        assert issubclass(raises, SigningKeyError)
        assert issubclass(raises, ValueError)


class TestMachineFileKeySetVerification:
    """Against certificates the *server* produced — see ``fixtures/machine_files/README``."""

    ED25519_FIXTURE = "ed25519_plain_valid"
    ED25519_ENCRYPTED_FIXTURE = "ed25519_encrypted_valid"

    def _fixture(self, name: str) -> tuple[MachineFile, dict[str, Any]]:
        entry = MACHINE_MANIFEST[name]
        return MachineFile.parse((MACHINE_FIXTURE_DIR / entry["file"]).read_text()), entry

    def test_a_server_signed_file_verifies_against_a_set_holding_its_key(self) -> None:
        file, entry = self._fixture(self.ED25519_FIXTURE)
        key_set = SigningKeySet.from_public_keys([entry["public_key_b64"]])

        verified = file.verify_with_key_set(
            key_set, LicenseScheme.ED25519_SIGN, now=BEFORE_ANY_FIXTURE_WAS_ISSUED
        )

        assert isinstance(verified, VerifiedMachineFile)
        assert verified.key.kid == entry["kid"]
        assert verified.claims.kid == entry["kid"]
        assert verified.machine.fingerprint == entry["fingerprint"]

    def test_a_server_signed_file_verifies_under_a_retired_key_after_a_rotation(self) -> None:
        """The rotation case, on a certificate this SDK did not produce."""
        file, entry = self._fixture(self.ED25519_FIXTURE)
        newer = _published(ed25519.Ed25519PrivateKey.generate().public_key())
        key_set = SigningKeySet(
            [
                SigningKey.ed25519(newer, status=ACTIVE_STATUS),
                SigningKey.ed25519(entry["public_key_b64"], status=RETIRED_STATUS),
            ]
        )

        verified = file.verify_with_key_set(
            key_set, LicenseScheme.ED25519_SIGN, now=BEFORE_ANY_FIXTURE_WAS_ISSUED
        )

        assert verified.key.kid == entry["kid"]
        assert verified.key.is_retired

    def test_an_encrypted_server_signed_file_verifies_against_a_key_set(self) -> None:
        file, entry = self._fixture(self.ED25519_ENCRYPTED_FIXTURE)
        key_set = SigningKeySet.from_public_keys([entry["public_key_b64"]])

        verified = file.verify_with_key_set(
            key_set,
            LicenseScheme.ED25519_SIGN,
            license_key=entry["license_key"],
            fingerprint=entry["fingerprint"],
            now=BEFORE_ANY_FIXTURE_WAS_ISSUED,
        )

        assert verified.key.kid == entry["kid"]

    def test_a_stale_key_set_reports_the_files_own_kid(self) -> None:
        file, entry = self._fixture(self.ED25519_FIXTURE)
        newer = _published(ed25519.Ed25519PrivateKey.generate().public_key())

        with pytest.raises(UnknownSigningKeyError) as caught:
            file.verify_with_key_set(
                SigningKeySet.from_public_keys([newer]),
                LicenseScheme.ED25519_SIGN,
                now=BEFORE_ANY_FIXTURE_WAS_ISSUED,
            )

        assert caught.value.kid == entry["kid"]

    @pytest.mark.parametrize(
        "scheme",
        [
            pytest.param(LicenseScheme.RSA_2048_PKCS1_SIGN, id="rsa_pkcs1"),
            pytest.param(LicenseScheme.RSA_2048_PKCS1_PSS_SIGN, id="rsa_pss"),
            pytest.param(LicenseScheme.ECDSA_P256_SIGN, id="ecdsa_p256"),
        ],
    )
    def test_a_non_ed25519_scheme_is_refused_rather_than_mis_answered(
        self, scheme: LicenseScheme
    ) -> None:
        """The `kid` names the account's Ed25519 key whatever signed the file
        (``check_out_machine.rs:125-129``), so matching it against a key set would be
        meaningless — and reporting a genuine RSA file as a forgery would be worse."""
        file, _ = self._fixture(self.ED25519_FIXTURE)

        with pytest.raises(SigningKeyNotApplicableError) as caught:
            file.verify_with_key_set(SigningKeySet(), scheme)

        assert caught.value.scheme == scheme.value

    def test_jwt_rs256_is_rejected_as_a_scheme_not_quietly_reclassified(self) -> None:
        """`RSA_2048_JWT_RS256` is rejected, not unsupported-and-ignored — the same
        outcome `verify` produces, not the key-set error."""
        file, _ = self._fixture(self.ED25519_FIXTURE)

        with pytest.raises(SchemeNotSupportedError):
            file.verify_with_key_set(SigningKeySet(), LicenseScheme.RSA_2048_JWT_RS256)

    def test_an_expired_server_signed_file_still_expires(self) -> None:
        file, entry = self._fixture("ed25519_plain_expired")
        key_set = SigningKeySet.from_public_keys([entry["public_key_b64"]])

        with pytest.raises(LicenseFileExpired):
            file.verify_with_key_set(key_set, LicenseScheme.ED25519_SIGN)

    def test_a_forged_machine_file_naming_a_held_key_is_a_signature_failure(self) -> None:
        file, entry = self._fixture(self.ED25519_FIXTURE)
        tampered = MachineFile(enc=file.enc + "AA", sig=file.sig, alg=file.alg)
        key_set = SigningKeySet.from_public_keys([entry["public_key_b64"]])

        with pytest.raises((InvalidSignature, ValueError)) as caught:
            tampered.verify_with_key_set(
                key_set, LicenseScheme.ED25519_SIGN, now=BEFORE_ANY_FIXTURE_WAS_ISSUED
            )

        assert not isinstance(caught.value, UnknownSigningKeyError)

    def test_the_payload_is_not_read_before_the_signature_passes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _forbidden(
            self: MachineFile, license_key: str | None, fingerprint: str | None
        ) -> str | None:
            raise AssertionError("the unverified kid probe ran on the happy path")

        monkeypatch.setattr(MachineFile, "_unverified_kid", _forbidden)
        file, entry = self._fixture(self.ED25519_FIXTURE)

        file.verify_with_key_set(
            SigningKeySet.from_public_keys([entry["public_key_b64"]]),
            LicenseScheme.ED25519_SIGN,
            now=BEFORE_ANY_FIXTURE_WAS_ISSUED,
        )
