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

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature

from tamga.checkout._envelope import parse_certificate_envelope
from tamga.crypto.aes_gcm import decrypt as aes_gcm_decrypt
from tamga.crypto.ed25519 import verify as ed25519_verify
from tamga.crypto.naive_key import derive_license_file_key
from tamga.models.license import LicenseResource

PEM_HEADER: str = "-----BEGIN LICENSE FILE-----"
PEM_FOOTER: str = "-----END LICENSE FILE-----"

ALG_PLAIN: str = "base64+ed25519"
ALG_ENCRYPTED: str = "aes-256-gcm+ed25519"
VALID_ALGORITHMS: frozenset[str] = frozenset({ALG_PLAIN, ALG_ENCRYPTED})

_NONCE_LENGTH = 12
_GCM_TAG_LENGTH = 16


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
    expiry: str | None = None
    """ISO 8601 expiry timestamp, if known. Not embedded in the signed ``.lic``
    bytes themselves — only present when this ``LicenseFile`` was built from a
    ``POST`` checkout's ``LicenseFileResource.expiry`` (see ``TamgaClient``).
    A ``LicenseFile`` parsed directly from raw ``GET``-checkout bytes (which
    carry no expiry metadata in-band) leaves this ``None``.
    """

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
        enc, sig_bytes, alg = parse_certificate_envelope(certificate, PEM_HEADER, PEM_FOOTER)
        if alg not in VALID_ALGORITHMS:
            raise ValueError(
                f"unsupported license file algorithm: {alg!r} "
                f"(expected one of {sorted(VALID_ALGORITHMS)})"
            )
        return cls(enc=enc, sig=sig_bytes, alg=alg)

    def verify(self, public_key: bytes, license_key: str | None = None) -> LicenseResource:
        """Run the full verification pipeline and return the embedded license.

        Pipeline: Ed25519-verify ``sig`` against ``self.enc``'s ASCII bytes
        using ``public_key`` -> base64-decode ``self.enc`` -> if
        ``self.alg == ALG_ENCRYPTED``, derive the naive key from the caller's
        license key and AES-256-GCM-open the payload -> parse the resulting
        bytes as ``{"data": <LicenseResource>}``.

        Args:
            public_key: The account's raw 32-byte Ed25519 public key.
            license_key: The license's raw key string. Required only if
                ``self.alg == ALG_ENCRYPTED``.

        Returns:
            The verified, embedded ``LicenseResource``.

        Raises:
            cryptography.exceptions.InvalidSignature: If Ed25519 verification fails.
            cryptography.exceptions.InvalidTag: If AES-256-GCM authentication fails.
            ValueError: If the file is encrypted but no ``license_key`` was supplied.
        """
        # ⚠️ Sign over `self.enc`'s ASCII/UTF-8 STRING bytes, never
        # `base64.b64decode(self.enc)` — see module docstring.
        message_bytes = self.enc.encode("ascii")
        if not ed25519_verify(public_key, message_bytes, self.sig):
            raise InvalidSignature("license file signature verification failed")

        payload_bytes = base64.b64decode(self.enc)

        if self.alg == ALG_ENCRYPTED:
            if license_key is None:
                raise ValueError("license_key is required to decrypt an encrypted license file")
            if len(payload_bytes) < _NONCE_LENGTH + _GCM_TAG_LENGTH:
                raise ValueError(
                    "malformed encrypted license file payload: too short to "
                    f"contain a {_NONCE_LENGTH}-byte nonce and {_GCM_TAG_LENGTH}-byte GCM tag"
                )
            nonce = payload_bytes[:_NONCE_LENGTH]
            ciphertext_and_tag = payload_bytes[_NONCE_LENGTH:]
            key = derive_license_file_key(license_key)
            plaintext = aes_gcm_decrypt(key, nonce, ciphertext_and_tag)
        else:
            plaintext = payload_bytes

        # SECURITY/robustness: without this wrapping, a malformed plain (or
        # a plaintext that ends up mis-routed via the unsigned `alg`-field
        # corruption scenario documented in machine_file.py's module
        # docstring) leaks a raw json.JSONDecodeError/KeyError from deep
        # inside verify() instead of a documented, catchable ValueError.
        # Found via audit; see tests/test_checkout_hardening.py.
        try:
            parsed = json.loads(plaintext)
        except json.JSONDecodeError as exc:
            raise ValueError("malformed license file: decrypted payload is not valid JSON") from exc
        try:
            data = parsed["data"]
        except (KeyError, TypeError) as exc:
            raise ValueError("malformed license file: payload is missing the 'data' key") from exc
        return LicenseResource(
            id=data["id"],
            type=data["type"],
            attributes=data.get("attributes", {}),
            relationships=data.get("relationships", {}),
        )

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
            to ``as_of``. ``False`` if ``self.expiry`` is unknown (e.g. this
            ``LicenseFile`` was parsed directly from raw ``GET``-checkout
            bytes, which carry no expiry metadata in-band) — there is
            nothing to compare against, so this is not treated as expired.
        """
        if self.expiry is None:
            return False
        reference = as_of if as_of is not None else datetime.now(timezone.utc)
        # A timezone-naive as_of (e.g. the very natural datetime.now(), with
        # no tz argument) would otherwise raise "TypeError: can't compare
        # offset-naive and offset-aware datetimes" -- the docstring says
        # "defaults to now (UTC)" without stating a caller-supplied as_of
        # must also be tz-aware, so treat a naive value as already being in
        # UTC rather than raising. Found via audit; see
        # tests/test_checkout_hardening.py.
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        expiry_dt = datetime.fromisoformat(self.expiry.replace("Z", "+00:00"))
        return expiry_dt < reference
