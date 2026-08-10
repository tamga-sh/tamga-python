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

⚠️ **``scheme`` must come from a trusted source** (security-review note,
Section F): ``MachineFile.verify``'s ``scheme`` parameter must be sourced
from the license's own ``scheme`` field via an authenticated API response —
never from this certificate's own unauthenticated ``alg`` string or any
other untrusted input. Feeding an attacker-influenced ``scheme`` value in
could force verification down a mismatched key-family path (the dispatch
table itself is a closed, safe mapping — see ``_VERIFIERS`` — but only if
``scheme`` itself is trustworthy).
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from tamga.checkout._envelope import parse_certificate_envelope
from tamga.crypto.aes_gcm import decrypt as aes_gcm_decrypt
from tamga.crypto.ecdsa import verify_p256
from tamga.crypto.ed25519 import verify as ed25519_verify
from tamga.crypto.hkdf import derive_machine_file_key
from tamga.crypto.rsa import verify_pkcs1v15, verify_pss
from tamga.errors import SchemeNotSupportedError
from tamga.models.machine import HeartbeatStatus, MachineResource
from tamga.models.policy import LicenseScheme

PEM_HEADER: str = "-----BEGIN MACHINE FILE-----"
PEM_FOOTER: str = "-----END MACHINE FILE-----"

REJECTED_SCHEMES: frozenset[LicenseScheme] = frozenset({LicenseScheme.RSA_2048_JWT_RS256})
"""Schemes the server itself rejects for machine checkout (422 SCHEME_NOT_SUPPORTED)."""

_NONCE_LENGTH = 12
_GCM_TAG_LENGTH = 16

_ENC_PREFIX_PLAIN = "base64"
_ENC_PREFIX_ENCRYPTED = "aes-256-gcm"
_SIGNING_SUFFIXES = frozenset({"ed25519", "rsa-sha256", "rsa-pss-sha256", "ecdsa-p256"})

#: Closed set of `alg` values the server can actually produce for a machine
#: file (`{enc_prefix}+{signing_suffix}`, from
#: `tamga-api`'s `shared/crypto/machine_file.rs::encode_machine_file` /
#: `scheme_to_alg_suffix`). Security-review finding (Section F, M-1):
#: `MachineFile.parse` previously accepted any `alg` string and `verify()`
#: branched on a loose `"aes-256-gcm" in self.alg` substring check — both
#: are now validated against this closed set at parse time, mirroring
#: `LicenseFile`'s stricter `VALID_ALGORITHMS` check, so a corrupted `alg`
#: (which is NOT covered by the signature — see module docstring) fails
#: fast with a clear typed error instead of an opaque crypto exception.
VALID_ALGORITHMS: frozenset[str] = frozenset(
    f"{prefix}+{suffix}"
    for prefix in (_ENC_PREFIX_PLAIN, _ENC_PREFIX_ENCRYPTED)
    for suffix in _SIGNING_SUFFIXES
)

_VERIFIERS = {
    LicenseScheme.ED25519_SIGN: ed25519_verify,
    LicenseScheme.RSA_2048_PKCS1_SIGN: verify_pkcs1v15,
    LicenseScheme.RSA_2048_PKCS1_PSS_SIGN: verify_pss,
    LicenseScheme.ECDSA_P256_SIGN: verify_p256,
}


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
            ValueError: On malformed markers, invalid base64/JSON, or an
                ``alg`` value outside ``VALID_ALGORITHMS`` (security-review
                hardening — see module docstring's "``alg`` is not covered
                by the signature" note). At verify time, an
                unrecognized/rejected ``scheme`` instead raises
                ``tamga.errors.SchemeNotSupportedError``.
        """
        enc, sig_bytes, alg = parse_certificate_envelope(certificate, PEM_HEADER, PEM_FOOTER)
        if alg not in VALID_ALGORITHMS:
            raise ValueError(
                f"unsupported machine file algorithm: {alg!r} "
                f"(expected one of {sorted(VALID_ALGORITHMS)})"
            )
        return cls(enc=enc, sig=sig_bytes, alg=alg)

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
        # Reject up front, before touching any parsing/crypto — never let
        # RSA_2048_JWT_RS256 fall through to a different verifier.
        verifier = _VERIFIERS.get(scheme)
        if scheme in REJECTED_SCHEMES or verifier is None:
            raise SchemeNotSupportedError(
                status=422,
                code="SCHEME_NOT_SUPPORTED",
                detail=f"scheme {scheme!r} is not supported for machine file checkout",
            )

        # ⚠️ Same signing-message gotcha as LicenseFile.verify: the ASCII
        # STRING bytes of `enc`, never its decoded bytes.
        message_bytes = self.enc.encode("ascii")
        if not verifier(public_key, message_bytes, self.sig):
            raise InvalidSignature("machine file signature verification failed")

        payload_bytes = base64.b64decode(self.enc)

        # Exact prefix match against the closed alg vocabulary validated in
        # `parse()` — no longer a bare substring check (security-review
        # hardening, Section F M-1).
        if self.alg.startswith(f"{_ENC_PREFIX_ENCRYPTED}+"):
            if license_key is None or fingerprint is None:
                raise ValueError(
                    "license_key and fingerprint are both required to decrypt "
                    "an encrypted machine file"
                )
            if len(payload_bytes) < _NONCE_LENGTH + _GCM_TAG_LENGTH:
                raise ValueError(
                    "malformed encrypted machine file payload: too short to "
                    f"contain a {_NONCE_LENGTH}-byte nonce and {_GCM_TAG_LENGTH}-byte GCM tag"
                )
            nonce = payload_bytes[:_NONCE_LENGTH]
            ciphertext_and_tag = payload_bytes[_NONCE_LENGTH:]
            key = derive_machine_file_key(license_key, fingerprint)
            plaintext = aes_gcm_decrypt(key, nonce, ciphertext_and_tag)
        else:
            plaintext = payload_bytes

        parsed = json.loads(plaintext)
        data = parsed["data"]
        attributes = data.get("attributes", {})
        return MachineResource(
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
            heartbeat_status=HeartbeatStatus(attributes.get("heartbeat_status", "NOT_STARTED")),
        )
