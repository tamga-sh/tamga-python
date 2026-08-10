"""Tests for machine offline proof — byte-exact serialization + RSA verify (plan Section H).

⚠️ Crypto-bearing — this section requires a mandatory security-reviewer pass
per docs/plans/tamga-python.plan.md Section 4.

⚠️ These tests assert the **alphabetical** field order documented in
``tamga.proof``'s module docstring, which is a deliberate deviation from the
plan's literal "no key sorting" wording — see that docstring for the full
ground-truth justification (server ``serde_json::json!`` + `BTreeMap`
canonicalization, cross-checked against ``tamga-rust``'s
``payload_json_field_order_is_alphabetical_not_source_order`` test).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from uuid import UUID

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tamga.client import TamgaClient
from tamga.proof import PROOF_VERSION_PREFIX, ProofResult, build_proof_payload

ACCOUNT_ID = UUID("01926b3e-0000-7000-8000-000000000000")
MACHINE_ID = UUID("01926b3e-1111-7000-8000-000000000000")
FINGERPRINT = "fp-abc"


def test_build_proof_payload_produces_exact_expected_bytes() -> None:
    payload = build_proof_payload(ACCOUNT_ID, MACHINE_ID, FINGERPRINT, {"cores": 4})
    expected = (
        f'{{"account":{{"id":"{ACCOUNT_ID}"}},'
        f'"dataset":{{"cores":4}},'
        f'"machine":{{"fingerprint":"{FINGERPRINT}","id":"{MACHINE_ID}"}}}}'
    ).encode()
    assert payload == expected


def test_build_proof_payload_field_order_is_alphabetical_not_source_order() -> None:
    payload = build_proof_payload(ACCOUNT_ID, MACHINE_ID, FINGERPRINT, {"b": 1, "a": 2})
    text = payload.decode("utf-8")

    # Top level: account, dataset, machine (alphabetical) — NOT
    # account, machine, dataset (the literal source-code order).
    assert text.index('"account"') < text.index('"dataset"') < text.index('"machine"')

    # Nested machine object: fingerprint before id (alphabetical), not id
    # before fingerprint (the literal source-code order).
    machine_pos = text.index('"machine"')
    assert text.index('"fingerprint"', machine_pos) < text.index('"id"', machine_pos)

    # Nested dataset object's own keys also canonicalize alphabetically,
    # regardless of Python dict insertion order ("b" before "a" above).
    assert text.index('"a":2') < text.index('"b":1')


def test_build_proof_payload_matches_server_bytes_for_non_ascii_dataset() -> None:
    """Regression test for a security-review finding (Section H): Python's
    ``json.dumps`` default (``ensure_ascii=True``) would ``\\uXXXX``-escape
    non-ASCII characters, but the server's ``serde_json`` emits raw UTF-8
    bytes for them (only control chars, ``"``, and ``\\`` are escaped).
    ``build_proof_payload`` must pass ``ensure_ascii=False`` or a legitimate
    proof over a dataset containing non-ASCII text would fail to verify.
    """
    payload = build_proof_payload(ACCOUNT_ID, MACHINE_ID, FINGERPRINT, {"name": "café"})
    text = payload.decode("utf-8")

    # The raw UTF-8 characters must appear literally in the output...
    assert '"café"' in text
    # ...never as a \u-escaped sequence.
    assert "\\u00e9" not in text
    assert "\\u" not in text


def _sign_rsa_pkcs1(private_key, message: bytes) -> bytes:  # type: ignore[no-untyped-def]
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def test_proof_verification_round_trip(rsa_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = rsa_keypair
    dataset = {"cores": 4}
    payload = build_proof_payload(ACCOUNT_ID, MACHINE_ID, FINGERPRINT, dataset)
    sig_bytes = _sign_rsa_pkcs1(private_key, payload)

    raw = f"{PROOF_VERSION_PREFIX}{base64.b64encode(sig_bytes).decode('ascii')}"
    result = ProofResult.parse(
        raw, account_id=ACCOUNT_ID, machine_id=MACHINE_ID, fingerprint=FINGERPRINT, dataset=dataset
    )
    public_key_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert result.verify(public_key_der) is True


def test_tamper_detection_mutated_dataset_fails_verification(rsa_keypair) -> None:  # type: ignore[no-untyped-def]
    private_key, public_key = rsa_keypair
    signed_dataset = {"cores": 4}
    payload = build_proof_payload(ACCOUNT_ID, MACHINE_ID, FINGERPRINT, signed_dataset)
    sig_bytes = _sign_rsa_pkcs1(private_key, payload)

    raw = f"{PROOF_VERSION_PREFIX}{base64.b64encode(sig_bytes).decode('ascii')}"
    tampered_dataset = {"cores": 999}
    result = ProofResult.parse(
        raw,
        account_id=ACCOUNT_ID,
        machine_id=MACHINE_ID,
        fingerprint=FINGERPRINT,
        dataset=tampered_dataset,
    )
    public_key_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert result.verify(public_key_der) is False


def test_reordered_json_with_same_fields_fails_verification(rsa_keypair) -> None:  # type: ignore[no-untyped-def]
    """Regression test guarding the byte-exact requirement: a signature
    computed over a manually reordered (but semantically identical) JSON
    string must NOT verify against the canonically-ordered payload this SDK
    reconstructs.
    """
    private_key, public_key = rsa_keypair
    dataset = {"cores": 4}
    canonical_payload = build_proof_payload(ACCOUNT_ID, MACHINE_ID, FINGERPRINT, dataset)

    reordered_json = (
        f'{{"account":{{"id":"{ACCOUNT_ID}"}},'
        f'"machine":{{"id":"{MACHINE_ID}","fingerprint":"{FINGERPRINT}"}},'
        f'"dataset":{{"cores":4}}}}'
    ).encode()
    assert reordered_json != canonical_payload

    sig_over_reordered = _sign_rsa_pkcs1(private_key, reordered_json)

    raw = f"{PROOF_VERSION_PREFIX}{base64.b64encode(sig_over_reordered).decode('ascii')}"
    result = ProofResult.parse(
        raw, account_id=ACCOUNT_ID, machine_id=MACHINE_ID, fingerprint=FINGERPRINT, dataset=dataset
    )
    public_key_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert result.verify(public_key_der) is False


def test_v1x0_prefix_stripped_correctly() -> None:
    result = ProofResult.parse(
        "v1x0.QUJD",
        account_id=ACCOUNT_ID,
        machine_id=MACHINE_ID,
        fingerprint=FINGERPRINT,
        dataset={},
    )
    assert result.signature == b"ABC"


def test_malformed_prefix_raises_clear_parse_error() -> None:
    with pytest.raises(ValueError, match="malformed proof"):
        ProofResult.parse(
            "not-v1x0-prefixed",
            account_id=ACCOUNT_ID,
            machine_id=MACHINE_ID,
            fingerprint=FINGERPRINT,
            dataset={},
        )


def test_malformed_base64_raises_clear_parse_error() -> None:
    with pytest.raises(ValueError, match="malformed proof"):
        ProofResult.parse(
            "v1x0.not-valid-base64!!!",
            account_id=ACCOUNT_ID,
            machine_id=MACHINE_ID,
            fingerprint=FINGERPRINT,
            dataset={},
        )


def test_client_generate_offline_proof_request_shape_and_response_parsing(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    rsa_keypair,  # type: ignore[no-untyped-def]
) -> None:
    private_key, public_key = rsa_keypair
    dataset = {"cores": 4}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == (
            f"/v1/accounts/018f2f3a-0000-7000-8000-000000000001/machines/{MACHINE_ID}/actions/generate-offline-proof"
        )
        body = json.loads(request.content)
        assert body["meta"]["dataset"] == dataset

        payload = build_proof_payload(
            UUID("018f2f3a-0000-7000-8000-000000000001"), MACHINE_ID, FINGERPRINT, dataset
        )
        sig_bytes = _sign_rsa_pkcs1(private_key, payload)
        proof_str = f"{PROOF_VERSION_PREFIX}{base64.b64encode(sig_bytes).decode('ascii')}"
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": str(MACHINE_ID),
                    "type": "machines",
                    "attributes": {"fingerprint": FINGERPRINT, "heartbeat_status": "ALIVE"},
                },
                "meta": {"proof": proof_str},
            },
        )

    client = make_client(handler)
    result = client.machines.generate_offline_proof(MACHINE_ID, dataset=dataset)
    assert result.raw.startswith(PROOF_VERSION_PREFIX)
    assert result.machine_id == MACHINE_ID
    assert result.fingerprint == FINGERPRINT
    assert result.dataset == dataset

    # make_client's fixture account_id matches the one used to build the
    # server-side payload above, so this also exercises full end-to-end
    # verification through the client-returned ProofResult.
    public_key_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert result.verify(public_key_der) is True
