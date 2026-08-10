"""``.lic`` offline license file parsing and verification.

File format::

    -----BEGIN LICENSE FILE-----
    <base64 of JSON: {"enc": "<base64>", "sig": "<base64 ed25519 sig>", "alg": "<string>"}>
    -----END LICENSE FILE-----

``alg`` is exactly ``"base64+ed25519"`` (plain) or ``"aes-256-gcm+ed25519"``
(encrypted) — the checkout signature is **always Ed25519**, independent of
the license's own key ``scheme`` (contrast with machine files, which dispatch
on scheme — see ``tamga.checkout.machine_file``).

⚠️ **The single most important trap in this SDK**: the Ed25519 signature
covers ``enc``'s ASCII/UTF-8 bytes — the base64 **string itself**
(``enc.encode("ascii")``) — NOT the bytes you get from
``base64.b64decode(enc)``. Get this backwards and every signature will fail
to verify even though the key and data are both correct.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tamga.models.license import LicenseResource

PEM_HEADER: str = "-----BEGIN LICENSE FILE-----"
PEM_FOOTER: str = "-----END LICENSE FILE-----"

ALG_PLAIN: str = "base64+ed25519"
ALG_ENCRYPTED: str = "aes-256-gcm+ed25519"
VALID_ALGORITHMS: frozenset[str] = frozenset({ALG_PLAIN, ALG_ENCRYPTED})


@dataclass(frozen=True)
class LicenseFile:
    """A parsed (but not yet verified) ``.lic`` file.

    Attributes:
        enc: The base64 payload string, exactly as it appeared in the file.
            This is the value whose ASCII bytes were signed — see the module
            docstring's signing-message gotcha.
        sig: The base64-decoded raw signature bytes.
        alg: One of ``ALG_PLAIN`` or ``ALG_ENCRYPTED``.
    """

    enc: str
    sig: bytes
    alg: str

    @classmethod
    def parse(cls, certificate: str) -> LicenseFile:
        """Parse a ``.lic`` certificate string into its structured form.

        Steps: strip the ``BEGIN``/``END LICENSE FILE`` PEM markers ->
        base64-decode the body -> parse the inner ``{enc, sig, alg}`` JSON ->
        base64-decode ``sig`` -> validate ``alg`` is one of
        ``VALID_ALGORITHMS``.

        Args:
            certificate: The full ``.lic`` file contents, including PEM markers.

        Returns:
            A parsed, not-yet-verified ``LicenseFile``.

        Raises:
            ValueError: On malformed PEM markers, invalid base64, invalid
                JSON, or an unrecognized ``alg`` value. Raised as a clear
                parse error, not a raw exception from an inner decode step.
        """
        raise NotImplementedError

    def verify(self, public_key: bytes) -> LicenseResource:
        """Run the full verification pipeline and return the embedded license.

        Pipeline: Ed25519-verify ``sig`` against ``self.enc``'s ASCII bytes
        using ``public_key`` -> base64-decode ``self.enc`` -> if
        ``self.alg == ALG_ENCRYPTED``, derive the naive key from the caller's
        license key and AES-256-GCM-open the payload -> parse the resulting
        bytes as ``{"data": <LicenseResource>}``.

        Args:
            public_key: The account's raw 32-byte Ed25519 public key.

        Returns:
            The verified, embedded ``LicenseResource``.

        Raises:
            cryptography.exceptions.InvalidSignature: If Ed25519 verification fails.
            cryptography.exceptions.InvalidTag: If AES-256-GCM authentication fails.
        """
        raise NotImplementedError

    def is_expired(self, as_of: datetime | None = None) -> bool:
        """Check the unsigned ``expiry`` metadata field.

        Advisory only — ``ttl``/``expiry`` are metadata, not embedded in the
        signed payload, and are never re-checked by the server on any later
        validation. Expiry enforcement for an offline file is entirely this
        SDK's (and ultimately the caller's) responsibility.

        Args:
            as_of: Reference time to compare against; defaults to now (UTC).

        Returns:
            Whether the file's ``expiry`` metadata is in the past relative
            to ``as_of``.
        """
        raise NotImplementedError
