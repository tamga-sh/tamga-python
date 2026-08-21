"""Offline verification: ``.lic`` license files and machine files.

Both formats share the same outer ``{enc, sig, alg}`` envelope but differ in
signing scheme dispatch and encryption key derivation — see
``tamga.checkout.license_file`` and ``tamga.checkout.machine_file``.

Both also carry a signed ``kid`` claim naming the key that signed them, which is
what makes an account's signing-key rotation survivable offline: verify against a
``tamga.checkout.key_set.SigningKeySet`` instead of a single public key, and a
file signed before the rotation still verifies, while one naming a key you do not
hold is reported as such instead of as a forgery.
"""

from __future__ import annotations

from tamga.checkout.key_set import (
    NoUsableSigningKeyError,
    SigningKeyError,
    SigningKeyNotApplicableError,
    SigningKeyNotPublishedError,
    SigningKeySet,
    UnknownSigningKeyError,
)
from tamga.checkout.license_file import LicenseFile, VerifiedLicenseFile
from tamga.checkout.machine_file import MachineFile, VerifiedMachineFile
from tamga.crypto.ed25519 import UNBACKFILLED_ACCOUNT_KEY_ID, key_id
from tamga.models.signing_key import SigningKey

__all__ = [
    "UNBACKFILLED_ACCOUNT_KEY_ID",
    "LicenseFile",
    "MachineFile",
    "NoUsableSigningKeyError",
    "SigningKey",
    "SigningKeyError",
    "SigningKeyNotApplicableError",
    "SigningKeyNotPublishedError",
    "SigningKeySet",
    "UnknownSigningKeyError",
    "VerifiedLicenseFile",
    "VerifiedMachineFile",
    "key_id",
]
