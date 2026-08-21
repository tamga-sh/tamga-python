"""Offline machine file parsing and multi-scheme verification.

Same inner ``{enc, sig, alg}`` JSON structure as license files, wrapped in
``-----BEGIN/END MACHINE FILE-----`` markers instead. Three key differences
from license checkout (``tamga.checkout.license_file``):

1. The signing scheme is taken from the **license's** ``scheme`` field
   (``ED25519_SIGN`` / ``RSA_2048_PKCS1_SIGN`` / ``RSA_2048_PKCS1_PSS_SIGN`` /
   ``ECDSA_P256_SIGN``), not hardcoded to Ed25519. ``RSA_2048_JWT_RS256`` is
   explicitly rejected (server returns ``422 SCHEME_NOT_SUPPORTED``) — mirror
   that rejection client-side rather than attempting to verify it.
2. The encryption key (when encrypted) needs both the license key and the
   target machine's fingerprint, so a machine file only decrypts on the
   machine it was issued for. Both file types derive their key with
   HKDF-SHA256 (``tamga.crypto.hkdf``); they differ only in salt and
   ``info`` — here the ``info`` is the fingerprint.
3. An **encrypted** machine file's ``enc`` is ``"<nonce_b64>.<cipher_b64>"``:
   two *separately* base64-encoded halves joined by a literal ``.``, not one
   base64 blob of ``nonce ‖ ciphertext ‖ tag``. License files use the single
   blob; machine files do not, so the two decryptors are not interchangeable.
   See the "wire format" note below.

**Format v2.** Machine-file ``alg`` values carry the same mandatory ``+v2``
suffix license files do — ``base64+ed25519+v2``, ``aes-256-gcm+ecdsa-p256+v2``
and so on — and a file whose ``alg`` lacks it is rejected with no fallback
path. v1 machine files predate the signed ``meta`` claims, so their requested
``ttl`` lived only in the JSON:API envelope *around* the certificate and a
short-lived file stayed cryptographically valid forever. The signed
``iat``/``exp``/``jti``/``kid`` claims are now inside the signature, and
:meth:`MachineFile.verify` **enforces** ``exp`` exactly as
``tamga.checkout.license_file`` does — same
``CLOCK_SKEW_TOLERANCE_SECONDS``, same trusted-timestamp escape hatch, and an
expiry surfaces as :class:`MachineFileExpired`, a subclass of
``LicenseFileExpired`` so one ``except`` clause covers both file types.
``exp`` is optional by design: a checkout made without a ``ttl`` produces a
file with no ``exp`` that genuinely never expires, so an absent claim is not
an error.

**Key rotation, and why it stops at Ed25519 here.**
:meth:`MachineFile.verify_with_key_set` is the key-set counterpart to
:meth:`MachineFile.verify`, but only for ``ED25519_SIGN``. The server picks a
machine file's signing key by the license's ``scheme`` while computing its
``kid`` claim from ``account.ed25519_public_key`` whatever the scheme, so an
RSA- or ECDSA-signed file names a key that had no part in its signature — and
only Ed25519 keys are ever published or rotated. See ``tamga.checkout.key_set``.

⚠️ **Wire format of an encrypted ``enc``** (server:
``src/shared/crypto/machine_file.rs`` -> ``FieldEncryption::encrypt``): the
nonce and the ciphertext are base64-encoded *independently* and joined with a
``.``; the ciphertext half already carries the appended 16-byte GCM tag. The
signature covers the whole ``enc`` **string**, dot included, so the order is
always: verify the signature, *then* split, *then* decode, *then* decrypt —
never decode attacker-controlled bytes before authenticating them. Which
branch to take is decided by ``alg``'s encoding prefix, never by whether a
``.`` happens to be present.

⚠️ **``alg`` is not covered by the signature** (security-review note, Section
F): the signature covers only ``enc``'s ASCII bytes (see the signing-message
gotcha above) — ``alg`` lives in the same unsigned outer JSON envelope as
``enc``/``sig`` and is never itself authenticated. A party able to tamper
with the unsigned envelope (e.g. a broken transport/storage layer) cannot
forge a new valid certificate this way (they still can't produce a valid
``sig`` over a chosen ``enc``), but *can* turn an otherwise-valid,
correctly-signed certificate into one that fails to decrypt/parse purely by
corrupting ``alg``. ``MachineFile.parse`` therefore validates ``alg``
against the closed ``VALID_ALGORITHMS`` set (mirroring
``tamga.checkout.license_file.LicenseFile``'s stricter check) so a
corrupted value fails fast with a clear ``ValueError`` rather than an opaque
``InvalidTag``/JSON-parse exception from deeper in ``verify()``.

⚠️ **``scheme`` must come from a trusted source** (security-review note):
``MachineFile.verify``'s ``scheme`` parameter must be sourced from the
license's own ``scheme`` field via an authenticated API response —
never from this certificate's own unauthenticated ``alg`` string or any
other untrusted input. Feeding an attacker-influenced ``scheme`` value in
could force verification down a mismatched key-family path (the dispatch
table itself is a closed, safe mapping — see ``_VERIFIERS`` — but only if
``scheme`` itself is trustworthy). ``alg``'s signing suffix cannot stand in
for it even in principle: the server emits the identical ``rsa-sha256``
suffix for both ``RSA_2048_PKCS1_SIGN`` and ``RSA_2048_JWT_RS256``, so the
suffix does not identify a scheme. It is only ever cross-checked *against*
the caller-supplied ``scheme`` — never used to select a verifier.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag

from tamga.checkout._envelope import b64decode_strict, parse_certificate_envelope
from tamga.checkout.key_set import (
    SigningKeyNotApplicableError,
    SigningKeySet,
    _resolve_signing_key,
)
from tamga.checkout.license_file import (
    LicenseFileClaims,
    LicenseFileExpired,
    _enforce_expiry,
    _parse_claims,
)
from tamga.crypto.aes_gcm import decrypt as aes_gcm_decrypt
from tamga.crypto.ecdsa import verify_p256
from tamga.crypto.ed25519 import verify as ed25519_verify
from tamga.crypto.hkdf import derive_machine_file_key
from tamga.crypto.rsa import verify_pkcs1v15, verify_pss
from tamga.errors import SchemeNotSupportedError
from tamga.models.machine import HeartbeatStatus, MachineResource
from tamga.models.policy import LicenseScheme
from tamga.models.signing_key import SigningKey

PEM_HEADER: str = "-----BEGIN MACHINE FILE-----"
PEM_FOOTER: str = "-----END MACHINE FILE-----"

REJECTED_SCHEMES: frozenset[LicenseScheme] = frozenset({LicenseScheme.RSA_2048_JWT_RS256})
"""Schemes the server itself rejects for machine checkout (422 SCHEME_NOT_SUPPORTED)."""

_NONCE_LENGTH = 12
_GCM_TAG_LENGTH = 16

_ENC_PREFIX_PLAIN = "base64"
_ENC_PREFIX_ENCRYPTED = "aes-256-gcm"
_ENC_SEPARATOR = "."
_ALG_V2_MARKER = "v2"

#: Server-side scheme -> ``alg`` signing-suffix mapping. **Not invertible**:
#: the server maps `RSA_2048_JWT_RS256` to the same `rsa-sha256` suffix as
#: `RSA_2048_PKCS1_SIGN`, which is precisely why a file's own `alg` can never
#: identify its scheme and the caller must supply one.
_SCHEME_TO_ALG_SUFFIX: dict[LicenseScheme, str] = {
    LicenseScheme.ED25519_SIGN: "ed25519",
    LicenseScheme.RSA_2048_PKCS1_SIGN: "rsa-sha256",
    LicenseScheme.RSA_2048_PKCS1_PSS_SIGN: "rsa-pss-sha256",
    LicenseScheme.ECDSA_P256_SIGN: "ecdsa-p256",
}

_SIGNING_SUFFIXES = frozenset(_SCHEME_TO_ALG_SUFFIX.values())

#: Closed set of `alg` values the server can actually produce for a machine
#: file (`{enc_prefix}+{signing_suffix}+v2`, matching the server's own
#: machine-file encoder and its scheme-to-`alg`-suffix mapping).
#: Security-review finding M-1: `MachineFile.parse` previously accepted any
#: `alg` string and `verify()` branched on a loose `"aes-256-gcm" in self.alg`
#: substring check — both are now validated against this closed set at parse
#: time, mirroring `LicenseFile`'s stricter `VALID_ALGORITHMS` check, so a
#: corrupted `alg` (which is NOT covered by the signature — see module
#: docstring) fails fast with a clear typed error instead of an opaque crypto
#: exception. The `+v2` marker is part of every member: the set previously
#: omitted it, which rejected every file the server actually emits.
VALID_ALGORITHMS: frozenset[str] = frozenset(
    f"{prefix}+{suffix}+{_ALG_V2_MARKER}"
    for prefix in (_ENC_PREFIX_PLAIN, _ENC_PREFIX_ENCRYPTED)
    for suffix in _SIGNING_SUFFIXES
)

_VERIFIERS = {
    LicenseScheme.ED25519_SIGN: ed25519_verify,
    LicenseScheme.RSA_2048_PKCS1_SIGN: verify_pkcs1v15,
    LicenseScheme.RSA_2048_PKCS1_PSS_SIGN: verify_pss,
    LicenseScheme.ECDSA_P256_SIGN: verify_p256,
}


class MachineFileExpired(LicenseFileExpired):
    """The machine file's signature verified, but its signed ``exp`` has passed.

    Subclasses ``tamga.checkout.license_file.LicenseFileExpired`` on purpose:
    both offline file types carry the same signed ``meta.exp`` claim and a
    caller wants the same reaction to it — "fetch a fresh one", as opposed to
    the "forged or corrupt" reaction an ``InvalidSignature``/``ValueError``
    calls for. A single ``except LicenseFileExpired:`` therefore covers both,
    while the distinct type is still available for callers that want to tell
    which file expired.
    """

    def __init__(self, exp: int) -> None:
        """Initialize with the signed ``exp`` claim (Unix timestamp) that failed the check."""
        super().__init__(exp, file_kind="machine file")


def _validate_alg(alg: str) -> tuple[str, str]:
    """Validate a machine-file ``alg`` and split it into its parts.

    The encoding prefix is everything before the **first** ``+`` and the
    ``v2`` marker is everything after the **last** one; whatever sits between
    them is the signing suffix. Splitting any other way mis-reads the two
    hyphenated encoding prefixes and suffixes the server emits
    (``aes-256-gcm``, ``rsa-pss-sha256``, ``ecdsa-p256``).

    Args:
        alg: The raw ``alg`` string from the certificate's outer envelope.

    Returns:
        ``(encoding_prefix, signing_suffix)``, both known-good members of the
        closed ``VALID_ALGORITHMS`` vocabulary.

    Raises:
        ValueError: If ``alg`` lacks the mandatory ``+v2`` marker (a pre-v2
            file, refused with no fallback) or is outside
            ``VALID_ALGORITHMS``.
    """
    prefix, first_sep, remainder = alg.partition("+")
    suffix, last_sep, marker = remainder.rpartition("+")
    if not first_sep or not last_sep or marker != _ALG_V2_MARKER:
        raise ValueError(
            f"unsupported machine file algorithm: {alg!r} — missing the mandatory "
            f"'+{_ALG_V2_MARKER}' marker (this looks like a pre-v2 file, which is "
            "refused because its expiry was never covered by the signature)"
        )
    if alg not in VALID_ALGORITHMS:
        raise ValueError(
            f"unsupported machine file algorithm: {alg!r} "
            f"(expected one of {sorted(VALID_ALGORITHMS)})"
        )
    return prefix, suffix


@dataclass(frozen=True)
class VerifiedMachineFile:
    """A machine file that verified, and the key it verified under.

    Returned by :meth:`MachineFile.verify_with_key_set`. A dataclass rather than
    a tuple so a later addition here does not break every call site.

    Attributes:
        machine: The verified, embedded machine.
        claims: The signed claims that travelled inside the signature.
        key: The key the signature verified under; ``key.is_retired`` marks a
            file issued before the account's last rotation.
    """

    machine: MachineResource
    claims: LicenseFileClaims
    key: SigningKey


@dataclass(frozen=True)
class MachineFile:
    """A parsed (but not yet verified) machine file.

    Attributes:
        enc: The payload string (signing-message gotcha applies here exactly
            as it does for ``LicenseFile`` — see
            ``tamga.checkout.license_file``). Base64 for a plain file;
            ``"<nonce_b64>.<cipher_b64>"`` for an encrypted one.
        sig: The base64-decoded raw signature bytes.
        alg: Algorithm string, e.g. ``"base64+ed25519+v2"`` or an
            RSA/ECDSA-flavored equivalent. Always carries the ``+v2`` marker.
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
            ValueError: On malformed markers, invalid base64/JSON, or an
                ``alg`` value outside ``VALID_ALGORITHMS`` — including one
                missing the mandatory ``+v2`` marker (security-review
                hardening — see module docstring's "``alg`` is not covered
                by the signature" note). At verify time, an
                unrecognized/rejected ``scheme`` instead raises
                ``tamga.errors.SchemeNotSupportedError``.
        """
        enc, sig_bytes, alg = parse_certificate_envelope(certificate, PEM_HEADER, PEM_FOOTER)
        _validate_alg(alg)
        return cls(enc=enc, sig=sig_bytes, alg=alg)

    def verify(
        self,
        public_key: bytes,
        scheme: LicenseScheme,
        license_key: str | None = None,
        fingerprint: str | None = None,
        now: int | None = None,
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

        The signed ``meta.exp`` claim is enforced once the signature passes —
        that enforcement is not opt-in. An authentic file whose ``exp`` has
        gone by raises :class:`MachineFileExpired` rather than returning a
        resource, so "expired, fetch a fresh one" stays distinguishable from
        "forged or corrupt".

        Args:
            public_key: Public key bytes/PEM matching ``scheme``'s algorithm family.
            scheme: The license's signing scheme, driving verifier dispatch.
                Must come from an authenticated response, never from this
                file's own ``alg`` — see the module docstring.
            license_key: Required only if the file is encrypted.
            fingerprint: Required only if the file is encrypted.
            now: Current Unix timestamp, used for the ``exp`` check. Defaults
                to the system clock. Pass a server-supplied timestamp instead
                if you are defending against a user winding their clock back
                to revive an expired file — the same escape hatch
                ``LicenseFile.verify`` offers, for the same reason.

        Returns:
            The verified, embedded ``MachineResource``. Note its
            ``heartbeat_status``: unlike the ping/reset/create responses — each
            of which reports a timestamp the same call just wrote — checkout
            resolves the machine by a *read*, so this field is a genuine
            staleness verdict and is the one place in this SDK where
            ``HeartbeatStatus.DEAD`` can actually surface. An unrecognized
            value falls back to ``NOT_STARTED`` rather than raising after the
            signature has already passed.

        Raises:
            tamga.errors.SchemeNotSupportedError: If ``scheme`` is
                ``RSA_2048_JWT_RS256`` or otherwise unrecognized.
            cryptography.exceptions.InvalidSignature: If signature verification fails.
            cryptography.exceptions.InvalidTag: If AES-256-GCM authentication fails.
            MachineFileExpired: If the file is authentic but its signed
                ``exp`` claim has passed (beyond the 60s skew tolerance).
            ValueError: If ``alg`` is corrupt, the file is encrypted but no
                ``license_key``/``fingerprint`` was supplied, or the payload
                is malformed / missing its signed ``meta`` claims.
        """
        machine, _ = self._verify(public_key, scheme, license_key, fingerprint, now)
        return machine

    def verify_with_claims(
        self,
        public_key: bytes,
        scheme: LicenseScheme,
        license_key: str | None = None,
        fingerprint: str | None = None,
        now: int | None = None,
    ) -> tuple[MachineResource, LicenseFileClaims]:
        """As :meth:`verify`, also returning the signed claims.

        Use this when you want ``jti`` for replay detection or ``kid`` for
        key-rotation bookkeeping. Expiry is enforced either way — it is not
        opt-in. The claims are the same ``LicenseFileClaims`` shape the
        ``.lic`` path returns; the server builds both from one struct.

        Args:
            public_key: Public key bytes/PEM matching ``scheme``'s algorithm family.
            scheme: The license's signing scheme, driving verifier dispatch.
            license_key: Required only if the file is encrypted.
            fingerprint: Required only if the file is encrypted.
            now: Current Unix timestamp; see :meth:`verify`.

        Returns:
            ``(machine, claims)`` — the verified ``MachineResource`` and the
            signed ``iat``/``exp``/``jti``/``kid`` claims that travelled
            inside the signature.
        """
        return self._verify(public_key, scheme, license_key, fingerprint, now)

    def verify_with_key_set(
        self,
        key_set: SigningKeySet,
        scheme: LicenseScheme,
        license_key: str | None = None,
        fingerprint: str | None = None,
        now: int | None = None,
    ) -> VerifiedMachineFile:
        """As :meth:`verify_with_claims`, against a key set instead of one key.

        **Ed25519-signed machine files only**, and the restriction is the
        server's rather than this SDK's. A machine file's signing key is chosen
        by the license's ``scheme`` (``check_out_machine.rs:86-99``), but its
        ``kid`` claim is computed from ``account.ed25519_public_key`` *whatever*
        the scheme (``:125-129``). For an RSA- or ECDSA-signed file the claim
        therefore names a key that had no part in the signature, and
        ``/signing-keys`` publishes Ed25519 keys only in any case — so those
        raise :class:`tamga.checkout.key_set.SigningKeyNotApplicableError` and
        must go through :meth:`verify` with the account's own key for that
        algorithm. Nothing is lost by it: ``/actions/rotate-signing-key`` rotates
        the Ed25519 key alone, so no other scheme has a rotation to survive.

        Everything else matches ``LicenseFile.verify_with_key_set`` — see there
        for what a key set is for and where one comes from.

        Args:
            key_set: The keys the caller trusts.
            scheme: The license's signing scheme, from an authenticated response
                and never from this file's own ``alg`` — the same rule
                :meth:`verify` states, for the same reason.
            license_key: Required only if the file is encrypted.
            fingerprint: Required only if the file is encrypted.
            now: Current Unix timestamp; see :meth:`verify`.

        Returns:
            The verified machine, its signed claims, and the key it verified
            under.

        Raises:
            tamga.errors.SchemeNotSupportedError: If ``scheme`` is
                ``RSA_2048_JWT_RS256`` or otherwise unrecognized — rejected here
                exactly as :meth:`verify` rejects it, never fallen through.
            tamga.checkout.key_set.SigningKeyNotApplicableError: If ``scheme`` is
                a recognized non-Ed25519 scheme.
            tamga.checkout.key_set.NoUsableSigningKeyError: If the set holds no
                usable Ed25519 key.
            tamga.checkout.key_set.SigningKeyNotPublishedError: If the file names
                the empty key — the signing account published none at all.
            tamga.checkout.key_set.UnknownSigningKeyError: If the file names a key
                the set does not hold. **Not a forgery** — refresh the set.
            cryptography.exceptions.InvalidSignature: If the key the file names is
                in the set and the signature still fails.
            MachineFileExpired: If the file is authentic but its signed ``exp``
                has passed.
            ValueError: Exactly as :meth:`verify_with_claims`.
        """
        # Reject up front, before touching any parsing or crypto, and in the
        # same order `_verify` does — RSA_2048_JWT_RS256 must never fall through
        # to a different verifier or to the "wrong scheme for a key set" branch.
        if scheme in REJECTED_SCHEMES or _VERIFIERS.get(scheme) is None:
            raise SchemeNotSupportedError(
                status=422,
                code="SCHEME_NOT_SUPPORTED",
                detail=f"scheme {scheme!r} is not supported for machine file checkout",
            )
        if scheme is not LicenseScheme.ED25519_SIGN:
            raise SigningKeyNotApplicableError(scheme.value)

        # Encode once, and outside the per-key callback: a non-ASCII `enc` must
        # fail identically whatever the set holds, and `_resolve_signing_key`
        # documents its `verify` callback as non-raising.
        message_bytes = self.enc.encode("ascii")
        key, public_key_bytes = _resolve_signing_key(
            key_set,
            lambda public_key: ed25519_verify(public_key, message_bytes, self.sig),
            lambda: self._unverified_kid(license_key, fingerprint),
        )
        machine, claims = self._verify(public_key_bytes, scheme, license_key, fingerprint, now)
        return VerifiedMachineFile(machine=machine, claims=claims, key=key)

    def _verify(
        self,
        public_key: bytes,
        scheme: LicenseScheme,
        license_key: str | None,
        fingerprint: str | None,
        now: int | None,
    ) -> tuple[MachineResource, LicenseFileClaims]:
        """Shared verification pipeline behind :meth:`verify`/:meth:`verify_with_claims`."""
        # Reject up front, before touching any parsing/crypto — never let
        # RSA_2048_JWT_RS256 fall through to a different verifier.
        verifier = _VERIFIERS.get(scheme)
        if scheme in REJECTED_SCHEMES or verifier is None:
            raise SchemeNotSupportedError(
                status=422,
                code="SCHEME_NOT_SUPPORTED",
                detail=f"scheme {scheme!r} is not supported for machine file checkout",
            )

        # Re-validate rather than trusting `parse()` to have run: this
        # dataclass is constructible directly.
        enc_prefix, alg_suffix = _validate_alg(self.alg)

        # Cross-check only, in the safe direction: scheme -> expected suffix.
        # Never suffix -> scheme; `rsa-sha256` maps back to two schemes, so
        # that direction does not exist. `scheme` stays authoritative.
        if alg_suffix != _SCHEME_TO_ALG_SUFFIX[scheme]:
            raise ValueError(
                f"machine file algorithm {self.alg!r} does not match the license's "
                f"scheme {scheme.value} (expected signing suffix "
                f"{_SCHEME_TO_ALG_SUFFIX[scheme]!r}, got {alg_suffix!r})"
            )

        # ⚠️ Same signing-message gotcha as LicenseFile.verify: the ASCII
        # STRING bytes of `enc`, never its decoded bytes. This runs BEFORE
        # any split/decode/decrypt — nothing attacker-controlled is decoded
        # until it has been authenticated.
        message_bytes = self.enc.encode("ascii")
        if not verifier(public_key, message_bytes, self.sig):
            raise InvalidSignature("machine file signature verification failed")

        plaintext = self._decode_payload(enc_prefix, license_key, fingerprint)

        # SECURITY/robustness: same class of gap as license_file.py's verify()
        # -- without this wrapping, a malformed plaintext leaks a raw
        # json.JSONDecodeError/KeyError instead of a documented ValueError.
        # Found via audit; see tests/test_checkout_hardening.py.
        try:
            parsed = json.loads(plaintext)
        except json.JSONDecodeError as exc:
            raise ValueError("malformed machine file: decrypted payload is not valid JSON") from exc
        try:
            data = parsed["data"]
        except (KeyError, TypeError) as exc:
            raise ValueError("malformed machine file: payload is missing the 'data' key") from exc
        # Without this, a `data` that is a list/string reaches `data.get(...)`
        # below and raises AttributeError -- outside every documented `Raises:`
        # on verify(). Found by the security-reviewer pass.
        if not isinstance(data, dict):
            raise ValueError("malformed machine file: payload's 'data' is not a JSON object")

        # The signature only establishes that the file is authentic. Without
        # this, verifying it would say nothing about whether it is still
        # valid — the v1 behaviour format v2 exists to close.
        claims = _parse_claims(parsed, file_kind="machine file")
        _enforce_expiry(claims, now, expired_error=MachineFileExpired)

        # Same class of gap as the `data` check above, which the first pass
        # only closed halfway: `data["id"]` below is a bare subscript, so a
        # payload without it raises KeyError, and an `attributes` that is
        # present but not an object raises AttributeError from `.get`. Both
        # are outside every documented `Raises:` on verify()/
        # verify_with_claims(), so a caller written as the documented
        # `except (ValueError, MachineFileExpired):` misses the rejection
        # entirely. Only reachable behind a valid signature, so not a bypass —
        # a contract gap. Found by the mandatory security-reviewer pass.
        if "id" not in data:
            raise ValueError("malformed machine file: payload's 'data' is missing 'id'")
        attributes = data.get("attributes")
        if attributes is None:
            attributes = {}
        if not isinstance(attributes, dict):
            raise ValueError(
                "malformed machine file: payload's 'data.attributes' is not a JSON object"
            )

        # SECURITY/robustness: an unrecognized heartbeat_status (a future
        # server-side addition, or any value not yet modeled) must not crash
        # verify() with an uncaught ValueError after the signature has
        # already passed -- fall back the same lenient way
        # models/policy.py's OverageStrategy/HeartbeatResurrectionStrategy
        # already handle DENY_ACCESS/NO_RESURRECTION. Found via audit; see
        # tests/test_checkout_hardening.py.
        raw_heartbeat_status = attributes.get("heartbeat_status", "NOT_STARTED")
        try:
            heartbeat_status = HeartbeatStatus(raw_heartbeat_status)
        except ValueError:
            heartbeat_status = HeartbeatStatus.NOT_STARTED

        machine = MachineResource(
            id=data["id"],
            fingerprint=attributes.get("fingerprint", ""),
            name=attributes.get("name"),
            ip=attributes.get("ip"),
            hostname=attributes.get("hostname"),
            platform=attributes.get("platform"),
            cores=attributes.get("cores"),
            memory=attributes.get("memory"),
            disk=attributes.get("disk"),
            metadata=attributes.get("metadata", {}) or {},
            heartbeat_status=heartbeat_status,
        )
        return machine, claims

    def _decode_payload(
        self, enc_prefix: str, license_key: str | None, fingerprint: str | None
    ) -> bytes:
        """Decode (and if encrypted, AES-256-GCM-open) an ``enc``.

        Split out of :meth:`_verify` so :meth:`_unverified_kid` runs the exact
        same steps rather than a second, drifting copy. It authenticates nothing
        by itself beyond AES-GCM's tag — the ordering rule is the caller's:
        :meth:`_verify` calls it only after the signature has passed, and
        :meth:`_unverified_kid` only once every key in a set has failed.

        Exact prefix match against the closed ``alg`` vocabulary (security-review
        hardening, finding M-1) — no bare substring check, and never a branch on
        whether a ``.`` happens to appear in ``enc``.
        """
        if enc_prefix == _ENC_PREFIX_ENCRYPTED:
            return self._decrypt(license_key, fingerprint)
        return b64decode_strict(self.enc, "payload", file_kind="machine file")

    def _unverified_kid(self, license_key: str | None, fingerprint: str | None) -> str | None:
        """Read the ``kid`` claim **without** verifying the signature.

        Only ever called by :meth:`verify_with_key_set`, and only once every key
        in the set has failed — see ``tamga.checkout.key_set``'s module docstring
        for why that ordering is the safe one. The value chooses between two
        error labels and is used for nothing else.

        Returns:
            The claimed ``kid``, or ``None`` if the payload cannot be reached or
            carries no readable claims — treated by the caller as an ordinary
            signature failure.
        """
        try:
            enc_prefix, _ = _validate_alg(self.alg)
            plaintext = self._decode_payload(enc_prefix, license_key, fingerprint)
            return _parse_claims(json.loads(plaintext), file_kind="machine file").kid
        # ValueError covers malformed alg/payload and the missing-key paths, plus
        # json.JSONDecodeError (a ValueError subclass); InvalidTag covers a
        # payload that will not decrypt. Not a bare `except`: anything else here
        # is a bug worth surfacing rather than an unreadable `kid`.
        except (ValueError, InvalidTag):
            return None

    def _decrypt(self, license_key: str | None, fingerprint: str | None) -> bytes:
        """Split, decode and AES-256-GCM-open an already-authenticated ``enc``.

        ``enc`` is ``"<nonce_b64>.<cipher_b64>"``: two independently
        base64-encoded halves, with the 16-byte GCM tag already appended to
        the ciphertext half. Decoding the whole string in one pass and
        slicing 12 bytes off the front is the mis-reading this format
        invites — Python's non-validating base64 decoder silently drops the
        ``.`` and yields convincing garbage instead of failing.
        """
        if license_key is None or fingerprint is None:
            raise ValueError(
                "license_key and fingerprint are both required to decrypt an encrypted machine file"
            )
        nonce_b64, separator, cipher_b64 = self.enc.partition(_ENC_SEPARATOR)
        if not separator or _ENC_SEPARATOR in cipher_b64:
            raise ValueError(
                "malformed encrypted machine file payload: expected exactly one "
                f"{_ENC_SEPARATOR!r}-separated '<nonce_b64>.<ciphertext_b64>' pair"
            )
        nonce = b64decode_strict(nonce_b64, "nonce", file_kind="machine file")
        ciphertext_and_tag = b64decode_strict(cipher_b64, "ciphertext", file_kind="machine file")
        if len(nonce) != _NONCE_LENGTH:
            raise ValueError(
                f"malformed encrypted machine file payload: nonce is {len(nonce)} bytes, "
                f"expected {_NONCE_LENGTH}"
            )
        if len(ciphertext_and_tag) < _GCM_TAG_LENGTH:
            raise ValueError(
                "malformed encrypted machine file payload: ciphertext is too short to "
                f"contain a {_GCM_TAG_LENGTH}-byte GCM tag"
            )
        key = derive_machine_file_key(license_key, fingerprint)
        return aes_gcm_decrypt(key, nonce, ciphertext_and_tag)
