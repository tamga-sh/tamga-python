r"""Machine offline proof — air-gapped verification.

A lighter-weight alternative to full machine checkout for periodic "prove
this machine is still valid" pings in air-gapped environments.
``POST /machines/{id}/actions/generate-offline-proof`` always signs with
RSA-2048 PKCS#1 v1.5 / SHA-256, **regardless of the license's ``scheme``**
(unlike checkout, there is no scheme dispatch here). Response:
``meta.proof = "v1x0.<base64 signature>"``.

⚠️ **Byte-exact serialization gotcha**: it is tempting to assume the signed
bytes preserve the server source code's literal field order,
``{"account":..., "machine":..., "dataset":...}``. They do not. The server
builds the payload via ``serde_json::json!(...)``, and `serde_json::Map` is
`BTreeMap`-backed
(alphabetically sorted output at every nesting level) because neither the
server nor the Rust SDK enables serde_json's `preserve_order` feature
(confirmed: no `indexmap` next to `serde_json` in either `Cargo.lock`, and
the Rust SDK carries a matching
`payload_json_field_order_is_alphabetical_not_source_order` test, which this
SDK's own test suite mirrors). So despite the server's source code literally
writing ``{"account": ..., "machine": ..., "dataset": ...}``, the actual
signed bytes are alphabetically ordered: ``{"account":...,"dataset":...,
"machine":{"fingerprint":...,"id":...}}`` — note `dataset` before `machine`,
and `fingerprint` before `id`. This module therefore builds the payload with
``json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)``,
which — like `serde_json::Value`'s `BTreeMap` — canonicalizes to alphabetical
order regardless of Python's (insertion-ordered) dict construction order.
``ensure_ascii=False`` is required too: `json.dumps`'s default would
``\uXXXX``-escape non-ASCII characters, which `serde_json` does not do — see
`build_proof_payload`'s docstring for the full explanation and the non-ASCII
regression test it points to.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from tamga.crypto.rsa import verify_pkcs1v15

PROOF_VERSION_PREFIX: str = "v1x0."
"""Prefix on every ``meta.proof`` value, stripped before base64-decoding the signature."""


def build_proof_payload(
    account_id: UUID,
    machine_id: UUID,
    fingerprint: str,
    dataset: dict[str, Any],
) -> bytes:
    r"""Build the exact byte sequence the server signs for an offline proof.

    Must reproduce the server's ``serde_json::json!``-produced bytes for
    ``{"account":{"id":...},"machine":{"id":...,"fingerprint":...},
    "dataset":<dataset>}`` — which, because neither side enables
    `serde_json`'s `preserve_order` feature, canonicalizes to **alphabetical
    key order at every nesting level**, not the object's literal
    construction order. Built here via ``json.dumps(...,
    sort_keys=True, separators=(",", ":"), ensure_ascii=False)`` to match
    that canonicalization regardless of Python dict insertion order — see
    the module docstring's deviation note.

    ⚠️ **``ensure_ascii=False`` is required, not optional** (security-review
    finding, not just a style choice): ``json.dumps``'s default
    ``ensure_ascii=True`` would ``\uXXXX``-escape every non-ASCII code
    point, but ``serde_json`` emits raw UTF-8 bytes for non-ASCII characters
    (only control characters, ``"``, and ``\`` are escaped). Since
    ``dataset`` is arbitrary caller-supplied JSON, any dataset value
    containing non-ASCII text would otherwise produce a byte sequence that
    diverges from what the server actually signed, causing verification of
    a legitimate, untampered proof to fail. See
    ``test_build_proof_payload_matches_server_bytes_for_non_ascii_dataset``
    in ``tests/test_offline_proof.py`` for the regression test.

    Args:
        account_id: Owning account UUID.
        machine_id: The machine the proof is for.
        fingerprint: The machine's fingerprint.
        dataset: Arbitrary caller-supplied dataset (defaults to ``{}`` server-side).

    Returns:
        The exact UTF-8 byte sequence that was (or must be) signed.
    """
    payload = {
        "account": {"id": str(account_id)},
        "machine": {"id": str(machine_id), "fingerprint": fingerprint},
        "dataset": dataset,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


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
        if not raw.startswith(PROOF_VERSION_PREFIX):
            raise ValueError(
                f"malformed proof: expected {PROOF_VERSION_PREFIX!r} prefix, got {raw[:10]!r}..."
            )
        sig_b64 = raw[len(PROOF_VERSION_PREFIX) :]
        try:
            signature = base64.b64decode(sig_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("malformed proof: signature is not valid base64") from exc

        return cls(
            raw=raw,
            signature=signature,
            account_id=account_id,
            machine_id=machine_id,
            fingerprint=fingerprint,
            dataset=dataset,
        )

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
        payload = build_proof_payload(
            self.account_id, self.machine_id, self.fingerprint, self.dataset
        )
        return verify_pkcs1v15(public_key_pem_or_der, payload, self.signature)
