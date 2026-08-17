"""``.lic`` offline license file parsing and verification.

File format::

    -----BEGIN LICENSE FILE-----
    <base64 of JSON: {"enc": "<base64>", "sig": "<base64 ed25519 sig>", "alg": "<string>"}>
    -----END LICENSE FILE-----

``alg`` is exactly ``"base64+ed25519+v2"`` (plain) or
``"aes-256-gcm+ed25519+v2"`` (encrypted) — the checkout signature is **always
Ed25519**, independent of the license's own key ``scheme`` (contrast with
machine files, which dispatch on scheme — see ``tamga.checkout.machine_file``).

**Format v2, and why v1 files are refused.** In v1 the ``ttl``/``expiry`` a
caller asked for lived only in the JSON:API envelope *around* the certificate,
never inside the signed bytes. A 24-hour trial file was therefore
cryptographically valid forever: the client is the attacker, so any check built
on the envelope is bypassed by simply keeping — or redistributing — the raw
``certificate`` string. v2 moves ``iat``/``exp``/``jti``/``kid`` inside the
signature, and this module enforces ``exp``. Accepting both formats would give
the old behaviour back, so a file whose ``alg`` lacks the ``+v2`` suffix is
rejected.

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
from tamga.crypto.hkdf import derive_license_file_key
from tamga.models.license import LicenseResource

PEM_HEADER: str = "-----BEGIN LICENSE FILE-----"
PEM_FOOTER: str = "-----END LICENSE FILE-----"

ALG_PLAIN: str = "base64+ed25519+v2"
ALG_ENCRYPTED: str = "aes-256-gcm+ed25519+v2"
VALID_ALGORITHMS: frozenset[str] = frozenset({ALG_PLAIN, ALG_ENCRYPTED})

_NONCE_LENGTH = 12
_GCM_TAG_LENGTH = 16

CLOCK_SKEW_TOLERANCE_SECONDS: int = 60
"""How much clock skew to tolerate when checking ``exp``.

Deliberately small. The client's clock is under the attacker's control, so a
generous allowance is just a free extension on every expired file; this covers
ordinary NTP drift and nothing more.
"""


class LicenseFileExpired(ValueError):
    """The file's signature verified, but its signed ``exp`` claim has passed.

    Distinct from a signature failure on purpose: a caller that cannot tell
    "expired" from "forged" either warns the user about tampering when their
    trial merely ended, or treats a forgery as a renewal prompt.
    """

    def __init__(self, exp: int) -> None:
        """Initialize with the signed ``exp`` claim (Unix timestamp) that failed the check."""
        super().__init__(f"license file expired at unix timestamp {exp}")
        self.exp = exp


@dataclass(frozen=True)
class LicenseFileClaims:
    """The claims carried *inside* the signed bytes.

    These are the point of format v2: unlike the response envelope, they cannot
    be edited by whoever holds the file.

    Attributes:
        iat: Issued-at, seconds since the Unix epoch.
        exp: Expiry, seconds since the Unix epoch. ``None`` means the file
            never expires (checkout was made without a ``ttl``).
        jti: Unique per checkout — usable for replay detection.
        kid: Identifies the signing key, so a file survives a key rotation.
    """

    iat: int
    jti: str
    kid: str
    exp: int | None = None


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

    def verify(
        self,
        public_key: bytes,
        license_key: str | None = None,
        now: int | None = None,
    ) -> LicenseResource:
        """Run the full verification pipeline and return the embedded license.

        Pipeline: Ed25519-verify ``sig`` against ``self.enc``'s ASCII bytes
        using ``public_key`` -> base64-decode ``self.enc`` -> if
        ``self.alg == ALG_ENCRYPTED``, derive the AES key with HKDF and
        AES-256-GCM-open the payload -> parse the resulting bytes as
        ``{"data": <LicenseResource>, "meta": <claims>}`` -> **enforce**
        ``meta.exp``.

        The signature only establishes that the file is authentic. Without the
        expiry check, verifying it would say nothing about whether it is still
        valid — which is exactly the v1 behaviour format v2 exists to close.

        Args:
            public_key: The account's raw 32-byte Ed25519 public key.
            license_key: The license's raw key string. Required only if
                ``self.alg == ALG_ENCRYPTED``.
            now: Current Unix timestamp. Defaults to the system clock. Pass a
                server-supplied timestamp instead if you are defending against
                a user winding their clock back to revive an expired file.

        Returns:
            The verified, embedded ``LicenseResource``.

        Raises:
            cryptography.exceptions.InvalidSignature: If Ed25519 verification fails.
            cryptography.exceptions.InvalidTag: If AES-256-GCM authentication fails.
            LicenseFileExpired: If the file is authentic but its signed
                ``exp`` claim has passed (beyond the 60s skew tolerance).
            ValueError: If the file is encrypted but no ``license_key`` was
                supplied, or the payload is malformed / missing its signed
                ``meta`` claims.
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

        claims = _parse_claims(parsed)
        _enforce_expiry(claims, now)

        return LicenseResource(
            id=data["id"],
            type=data["type"],
            attributes=data.get("attributes", {}),
            relationships=data.get("relationships", {}),
        )

    def verify_with_claims(
        self,
        public_key: bytes,
        license_key: str | None = None,
        now: int | None = None,
    ) -> tuple[LicenseResource, LicenseFileClaims]:
        """As :meth:`verify`, also returning the signed claims.

        Use this when you want ``jti`` for replay detection or ``kid`` for
        key-rotation bookkeeping. Expiry is enforced either way — it is not
        opt-in.
        """
        license = self.verify(public_key, license_key, now)
        payload_bytes = base64.b64decode(self.enc)
        if self.alg == ALG_ENCRYPTED:
            assert license_key is not None  # verify() already enforced this
            nonce = payload_bytes[:_NONCE_LENGTH]
            plaintext = aes_gcm_decrypt(
                derive_license_file_key(license_key), nonce, payload_bytes[_NONCE_LENGTH:]
            )
        else:
            plaintext = payload_bytes
        return license, _parse_claims(json.loads(plaintext))

    def is_expired(self, as_of: datetime | None = None) -> bool:
        """Check the unsigned ``expiry`` metadata field.

        Advisory only, and **not** the expiry check that matters: this reads
        the ``expiry`` a ``POST`` checkout echoed back beside the
        certificate, which lives outside the signature and is never
        re-checked by the server on any later validation. The enforced copy
        is the signed ``meta.exp`` claim inside the certificate, which
        :meth:`verify` rejects on — that enforcement is not opt-in and does
        not need this method.

        Useful for showing a renewal prompt before a file actually lapses,
        without re-running verification.

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


def _parse_claims(parsed: object) -> LicenseFileClaims:
    """Pull the signed ``meta`` claims out of a decoded payload.

    A payload with no ``meta`` is a v1 file. The ``alg`` gate should have
    caught it already; this is the second line, so a file cannot reach the
    expiry check with nothing to check.
    """
    if not isinstance(parsed, dict):
        raise ValueError("malformed license file: payload is not a JSON object")
    meta = parsed.get("meta")
    if not isinstance(meta, dict):
        raise ValueError(
            "malformed license file: payload is missing the signed 'meta' claims "
            "(this looks like a pre-v2 file)"
        )
    try:
        return LicenseFileClaims(
            iat=int(meta["iat"]),
            jti=str(meta["jti"]),
            kid=str(meta["kid"]),
            exp=int(meta["exp"]) if meta.get("exp") is not None else None,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"malformed license file: bad 'meta' claims ({exc})") from exc


def _enforce_expiry(claims: LicenseFileClaims, now: int | None) -> None:
    """Reject a file whose signed ``exp`` has passed."""
    if claims.exp is None:
        return
    reference = now if now is not None else int(datetime.now(timezone.utc).timestamp())
    if reference - CLOCK_SKEW_TOLERANCE_SECONDS > claims.exp:
        raise LicenseFileExpired(claims.exp)
