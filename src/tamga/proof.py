"""Machine offline proof — air-gapped verification.

A lighter-weight alternative to full machine checkout for periodic "prove
this machine is still valid" pings in air-gapped environments.
``POST /machines/{id}/actions/generate-offline-proof`` always signs with
RSA-2048 PKCS#1 v1.5 / SHA-256, **regardless of the license's ``scheme``**
(unlike checkout, there is no scheme dispatch here). Response:
``meta.proof = "v1x0.<base64 signature>"``.

⚠️ **Byte-exact serialization gotcha**: the signature covers
``{"account":{"id":...},"machine":{"id":...,"fingerprint":...},"dataset":<dataset>}``
serialized **exactly** as the server produces it — field order matters, not
just field presence/set. ``build_proof_payload`` must reproduce this via an
explicitly key-ordered structure serialized with
``json.dumps(..., separators=(",", ":"))`` and no key sorting — never rely on
incidental dict-ordering behavior matching by luck.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

PROOF_VERSION_PREFIX: str = "v1x0."
"""Prefix on every ``meta.proof`` value, stripped before base64-decoding the signature."""


def build_proof_payload(
    account_id: UUID,
    machine_id: UUID,
    fingerprint: str,
    dataset: dict[str, Any],
) -> bytes:
    """Build the exact byte sequence the server signs for an offline proof.

    Must reproduce
    ``{"account":{"id":...},"machine":{"id":...,"fingerprint":...},"dataset":<dataset>}``
    key-for-key, in this exact order, via ``json.dumps(..., separators=(",", ":"))``
    with no key sorting.

    Args:
        account_id: Owning account UUID.
        machine_id: The machine the proof is for.
        fingerprint: The machine's fingerprint.
        dataset: Arbitrary caller-supplied dataset (defaults to ``{}`` server-side).

    Returns:
        The exact UTF-8 byte sequence that was (or must be) signed.
    """
    raise NotImplementedError


@dataclass(frozen=True)
class ProofResult:
    """A parsed offline proof, holding enough to rebuild and verify the signed message.

    Attributes:
        raw: The raw ``"v1x0.<base64 sig>"`` string as returned by the server.
        signature: The base64-decoded signature bytes (prefix already stripped).
        account_id: Account UUID used to (re)build the signed payload.
        machine_id: Machine UUID used to (re)build the signed payload.
        fingerprint: Machine fingerprint used to (re)build the signed payload.
        dataset: The dataset used to (re)build the signed payload.
    """

    raw: str
    signature: bytes
    account_id: UUID
    machine_id: UUID
    fingerprint: str
    dataset: dict[str, Any]

    @classmethod
    def parse(
        cls,
        raw: str,
        *,
        account_id: UUID,
        machine_id: UUID,
        fingerprint: str,
        dataset: dict[str, Any],
    ) -> ProofResult:
        """Strip the ``v1x0.`` prefix and base64-decode the remainder.

        Args:
            raw: The raw ``meta.proof`` string.
            account_id: Account UUID (not embedded in ``raw`` — supplied by the caller).
            machine_id: Machine UUID (not embedded in ``raw`` — supplied by the caller).
            fingerprint: Machine fingerprint (not embedded in ``raw`` — supplied by the caller).
            dataset: The dataset that was sent in the generation request.

        Returns:
            A parsed ``ProofResult``, not yet verified.

        Raises:
            ValueError: If ``raw`` doesn't start with ``PROOF_VERSION_PREFIX``
                or the remainder isn't valid base64.
        """
        raise NotImplementedError

    def verify(self, public_key_pem_or_der: bytes) -> bool:
        """Verify this proof's signature against a rebuilt byte-exact payload.

        Rebuilds the signed message via ``build_proof_payload`` using this
        instance's stored fields, then verifies with
        ``tamga.crypto.rsa.verify_pkcs1v15``.

        Args:
            public_key_pem_or_der: The account's RSA-2048 public key.

        Returns:
            Whether the signature is valid for the rebuilt payload.
        """
        raise NotImplementedError
