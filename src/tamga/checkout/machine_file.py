"""Offline machine file parsing and multi-scheme verification.

Same inner ``{enc, sig, alg}`` JSON structure as license files, wrapped in
``-----BEGIN/END MACHINE FILE-----`` markers instead. Two key differences
from license checkout (``tamga.checkout.license_file``):

1. The signing scheme is taken from the **license's** ``scheme`` field
   (``ED25519_SIGN`` / ``RSA_2048_PKCS1_SIGN`` / ``RSA_2048_PKCS1_PSS_SIGN`` /
   ``ECDSA_P256_SIGN``), not hardcoded to Ed25519. ``RSA_2048_JWT_RS256`` is
   explicitly rejected (server returns ``422 SCHEME_NOT_SUPPORTED``) — mirror
   that rejection client-side rather than attempting to verify it.
2. The encryption key (when encrypted) is HKDF-SHA256 derived
   (``tamga.crypto.hkdf``), requiring both the license key and the target
   machine's fingerprint — not the naive license-checkout derivation.
"""

from __future__ import annotations

from dataclasses import dataclass

from tamga.models.machine import MachineResource
from tamga.models.policy import LicenseScheme

PEM_HEADER: str = "-----BEGIN MACHINE FILE-----"
PEM_FOOTER: str = "-----END MACHINE FILE-----"

REJECTED_SCHEMES: frozenset[LicenseScheme] = frozenset({LicenseScheme.RSA_2048_JWT_RS256})
"""Schemes the server itself rejects for machine checkout (422 SCHEME_NOT_SUPPORTED)."""


@dataclass(frozen=True)
class MachineFile:
    """A parsed (but not yet verified) machine file.

    Attributes:
        enc: The base64 payload string (signing-message gotcha applies here
            exactly as it does for ``LicenseFile`` — see
            ``tamga.checkout.license_file``).
        sig: The base64-decoded raw signature bytes.
        alg: Algorithm string, e.g. ``"base64+ed25519"`` or an
            RSA/ECDSA-flavored equivalent.
    """

    enc: str
    sig: bytes
    alg: str

    @classmethod
    def parse(cls, certificate: str) -> MachineFile:
        """Parse a machine-file certificate string into its structured form.

        Same PEM-strip / base64-decode / JSON-parse pipeline as
        ``LicenseFile.parse``, with the ``MACHINE FILE`` markers instead of
        ``LICENSE FILE``.

        Args:
            certificate: The full machine-file contents, including PEM markers.

        Returns:
            A parsed, not-yet-verified ``MachineFile``.

        Raises:
            ValueError: On malformed markers, invalid base64/JSON, or (at
                verify time) an unrecognized/rejected scheme.
        """
        raise NotImplementedError

    def verify(
        self,
        public_key: bytes,
        scheme: LicenseScheme,
        license_key: str | None = None,
        fingerprint: str | None = None,
    ) -> MachineResource:
        """Run the full verification pipeline and return the embedded machine.

        Dispatches signature verification by ``scheme``:
        ``ED25519_SIGN`` -> ``tamga.crypto.ed25519.verify``;
        ``RSA_2048_PKCS1_SIGN`` -> ``tamga.crypto.rsa.verify_pkcs1v15``;
        ``RSA_2048_PKCS1_PSS_SIGN`` -> ``tamga.crypto.rsa.verify_pss``;
        ``ECDSA_P256_SIGN`` -> ``tamga.crypto.ecdsa.verify_p256``.
        ``RSA_2048_JWT_RS256`` (and any other unrecognized scheme) must raise
        ``SchemeNotSupportedError`` immediately rather than falling through
        to a different verifier.

        If the file is encrypted, both ``license_key`` and ``fingerprint``
        are required to derive the HKDF-based decryption key.

        Args:
            public_key: Public key bytes/PEM matching ``scheme``'s algorithm family.
            scheme: The license's signing scheme, driving verifier dispatch.
            license_key: Required only if the file is encrypted.
            fingerprint: Required only if the file is encrypted.

        Returns:
            The verified, embedded ``MachineResource``.

        Raises:
            tamga.errors.SchemeNotSupportedError: If ``scheme`` is
                ``RSA_2048_JWT_RS256`` or otherwise unrecognized.
            cryptography.exceptions.InvalidSignature: If signature verification fails.
            cryptography.exceptions.InvalidTag: If AES-256-GCM authentication fails.
        """
        raise NotImplementedError
