"""``key_id`` known-answer tests, and the ``SigningKey``/``SigningKeySet`` models.

⚠️ Crypto-bearing — changes here require a mandatory security-reviewer pass.

The vectors in ``tests/fixtures/signing_keys/signing-key-ids.json`` were produced by an
independent SHA-256 implementation, not by this SDK; see that directory's README.

The twelve ``kid`` values in ``tests/fixtures/machine_files/manifest.json`` add twelve
more known-answer pairs for the **hash rule** — valuable because two of their key shapes
are DER and a 65-byte point, which can only hash to their ``kid`` if the digest covers
the base64 text. They are **not** a second source for how the server *selects* a key: the
per-scheme spread they show is a fixture-generator artifact that
``check_out_machine.rs:127`` cannot produce. See
``test_key_id_reproduces_every_machine_file_fixture_kid``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tamga.checkout.key_set import SigningKeySet
from tamga.crypto.ed25519 import UNBACKFILLED_ACCOUNT_KEY_ID, key_id
from tamga.models.signing_key import (
    ACTIVE_STATUS,
    ED25519_ALGORITHM,
    RETIRED_STATUS,
    SigningKey,
)

VECTOR_FILE = Path(__file__).parent / "fixtures" / "signing_keys" / "signing-key-ids.json"
VECTORS: dict[str, Any] = json.loads(VECTOR_FILE.read_text())

MACHINE_FILE_MANIFEST: dict[str, dict[str, Any]] = json.loads(
    (Path(__file__).parent / "fixtures" / "machine_files" / "manifest.json").read_text()
)

VALID_KEY_A = base64.b64encode(bytes(range(32))).decode("ascii")
VALID_KEY_B = base64.b64encode(bytes(range(0x20, 0x40))).decode("ascii")


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: str(v["name"]))
def test_key_id_reproduces_every_independent_vector(vector: dict[str, Any]) -> None:
    assert key_id(vector["publicKey"]) == vector["kid"]


def test_key_id_hashes_the_base64_string_not_the_decoded_bytes() -> None:
    """The trap this whole fixture exists for.

    The positive assertion alone does not catch it in isolation, so both sides are
    pinned: the correct id must be produced, and the id an implementation that decoded
    first would produce must not be. The third assertion establishes that the "wrong"
    constant really is the decode-first answer, so the second one is not vacuous.
    """
    negative = VECTORS["negative"]
    public_key = negative["publicKey"]

    assert key_id(public_key) == negative["correctKid"]
    assert key_id(public_key) != negative["wrongKidIfDecodedFirst"]
    assert (
        hashlib.sha256(base64.b64decode(public_key)).digest()[:8].hex()
        == negative["wrongKidIfDecodedFirst"]
    )


@pytest.mark.parametrize("name", sorted(MACHINE_FILE_MANIFEST))
def test_key_id_reproduces_every_machine_file_fixture_kid(name: str) -> None:
    """Twelve more known-answer pairs for the **hash rule**, and nothing beyond it.

    Each pair is a real public-key string and a real ``kid``, and every one satisfies
    ``kid == lowercase_hex(SHA-256(public-key string)[0..8])``. Two of the four key
    shapes here are DER (RSA) and a 65-byte uncompressed point (ECDSA) rather than 32
    raw bytes, so they only hash to their ``kid`` at all because the digest covers the
    base64 *text*. That is what makes them worth asserting.

    ⚠️ **This is NOT evidence about which key the server names, and must not be read as
    any.** ``check_out_machine.rs:86-99`` selects the *signing* key by the license's
    scheme, but ``:127`` derives the ``kid`` from ``account.ed25519_public_key``
    **unconditionally** — so production emits **one** ``kid`` for a given account whatever
    scheme signed the file, and an RSA- or ECDSA-signed machine file names a published
    Ed25519 key that cannot verify it. This fixture set carries **four** distinct ``kid``
    values, one per scheme, because its *generator* paired each file with its own signing
    key. ``check_out_machine`` cannot produce that spread. It is a generator artifact.

    Reading the per-scheme pairing as a server property would say the opposite of the
    truth, and would argue for exactly the naive ``kid``-to-key lookup that reports an
    authentic RSA file as forged. The real rule is why
    ``MachineFile.verify_with_key_set`` refuses every scheme but Ed25519; see
    ``tamga.checkout.key_set`` and ``tests/fixtures/machine_files/README.md``.
    """
    entry = MACHINE_FILE_MANIFEST[name]
    assert key_id(entry["public_key_b64"]) == entry["kid"]


def test_the_machine_file_fixture_kid_spread_is_a_generator_artifact() -> None:
    """Pin the discrepancy itself, so nobody re-derives the wrong conclusion from it.

    If a future fixture refresh ever collapses these to one ``kid`` per account — what
    ``check_out_machine.rs:127`` actually produces — this test fails and the docstring
    above is what needs rewriting, rather than the caveat being quietly lost.
    """
    kids_by_scheme = {entry["scheme"]: entry["kid"] for entry in MACHINE_FILE_MANIFEST.values()}
    assert len(set(kids_by_scheme.values())) == len(kids_by_scheme) == 4, (
        "the fixtures still carry one distinct kid per scheme, which the server's "
        "unconditional key_id(account.ed25519_public_key) cannot emit"
    )


def test_key_id_is_sixteen_lowercase_hex_characters() -> None:
    """Eight *bytes* of digest, not eight characters — the other half of the trap."""
    computed = key_id(VALID_KEY_A)
    assert len(computed) == 16
    assert computed == computed.lower()
    assert all(character in "0123456789abcdef" for character in computed)


def test_unbackfilled_account_constant_is_the_empty_key_id() -> None:
    assert key_id("") == UNBACKFILLED_ACCOUNT_KEY_ID
    assert hashlib.sha256(b"").digest()[:8].hex() == UNBACKFILLED_ACCOUNT_KEY_ID


def test_key_id_is_sensitive_to_the_exact_published_string() -> None:
    """Normalizing a published key changes its id, so the published form is kept verbatim."""
    assert key_id(VALID_KEY_A) != key_id(VALID_KEY_A.rstrip("="))
    assert key_id(VALID_KEY_A) != key_id(f" {VALID_KEY_A}")


class TestSigningKey:
    def test_ed25519_factory_derives_the_kid(self) -> None:
        key = SigningKey.ed25519(VALID_KEY_A)
        assert key.kid == key_id(VALID_KEY_A)
        assert key.algorithm == ED25519_ALGORITHM
        assert key.status == ACTIVE_STATUS
        assert key.kid_is_self_consistent

    def test_public_key_bytes_decodes_the_raw_key(self) -> None:
        assert SigningKey.ed25519(VALID_KEY_A).public_key_bytes == bytes(range(32))

    @pytest.mark.parametrize(
        "public_key",
        [
            pytest.param("", id="empty"),
            pytest.param("not base64!!", id="not_base64"),
            pytest.param(base64.b64encode(b"short").decode("ascii"), id="too_short"),
            pytest.param(base64.b64encode(bytes(64)).decode("ascii"), id="too_long"),
        ],
    )
    def test_public_key_bytes_is_none_for_anything_unusable(self, public_key: str) -> None:
        assert SigningKey(kid="x", public_key=public_key).public_key_bytes is None

    def test_kid_is_self_consistent_detects_a_mislabelled_key(self) -> None:
        mislabelled = SigningKey(kid="0000000000000000", public_key=VALID_KEY_A)
        assert not mislabelled.kid_is_self_consistent
        assert mislabelled.computed_kid == key_id(VALID_KEY_A)

    def test_is_retired_and_is_ed25519_are_case_insensitive(self) -> None:
        assert SigningKey(kid="x", public_key=VALID_KEY_A, status="RETIRED").is_retired
        assert not SigningKey.ed25519(VALID_KEY_A).is_retired
        assert SigningKey(kid="x", public_key=VALID_KEY_A, algorithm="ED25519").is_ed25519
        assert not SigningKey(kid="x", public_key=VALID_KEY_A, algorithm="rsa2048").is_ed25519


class TestSigningKeySet:
    def test_from_public_keys_derives_every_kid(self) -> None:
        key_set = SigningKeySet.from_public_keys([VALID_KEY_A, VALID_KEY_B])
        assert key_set.kids == (key_id(VALID_KEY_A), key_id(VALID_KEY_B))
        assert len(key_set) == 2

    def test_from_public_keys_is_strict_about_a_typo(self) -> None:
        """A key pinned by hand must fail at startup, not report every genuine file
        as signed by an unknown key."""
        with pytest.raises(ValueError, match="index 1"):
            SigningKeySet.from_public_keys([VALID_KEY_A, "definitely-not-a-key"])

    def test_constructor_is_lenient_so_one_bad_row_strands_nothing(self) -> None:
        """The opposite policy, for the server's whole key history."""
        key_set = SigningKeySet(
            [
                SigningKey.ed25519(VALID_KEY_A),
                SigningKey(kid="future", public_key=VALID_KEY_B, algorithm="rsa2048"),
                SigningKey(kid="broken", public_key="not base64!!"),
            ]
        )
        assert len(key_set) == 3
        assert [key.kid for key in key_set.usable_keys] == [key_id(VALID_KEY_A)]

    def test_find_matches_the_published_id(self) -> None:
        key_set = SigningKeySet.from_public_keys([VALID_KEY_A])
        assert key_set.find(key_id(VALID_KEY_A)) is not None
        assert key_set.find("0000000000000000") is None

    def test_find_also_matches_a_mislabelled_keys_computed_id(self) -> None:
        """So a server that ever mislabelled a key cannot make a genuine file look forged."""
        key_set = SigningKeySet([SigningKey(kid="0000000000000000", public_key=VALID_KEY_A)])
        assert key_set.find(key_id(VALID_KEY_A)) is not None
        assert key_set.find("0000000000000000") is not None

    def test_inconsistent_keys_reports_the_mismatch(self) -> None:
        good = SigningKey.ed25519(VALID_KEY_A)
        bad = SigningKey(kid="0000000000000000", public_key=VALID_KEY_B)
        assert SigningKeySet([good, bad]).inconsistent_keys == (bad,)
        assert SigningKeySet([good]).inconsistent_keys == ()

    def test_repr_shows_ids_and_no_key_material(self) -> None:
        key_set = SigningKeySet.from_public_keys([VALID_KEY_A])
        assert key_id(VALID_KEY_A) in repr(key_set)
        assert VALID_KEY_A not in repr(key_set)

    def test_set_equality_and_iteration(self) -> None:
        first = SigningKeySet.from_public_keys([VALID_KEY_A])
        assert first == SigningKeySet.from_public_keys([VALID_KEY_A])
        assert first != SigningKeySet.from_public_keys([VALID_KEY_B])
        assert first != "not a key set"
        assert hash(first) == hash(SigningKeySet.from_public_keys([VALID_KEY_A]))
        assert [key.kid for key in first] == list(first.kids)
        assert first.keys == tuple(first)

    def test_an_empty_set_is_representable(self) -> None:
        """The normal state of an account that has never rotated."""
        assert len(SigningKeySet()) == 0
        assert SigningKeySet().usable_keys == ()

    def test_retired_keys_are_kept_and_usable(self) -> None:
        """The entire point: a retired key must still verify files signed before rotation."""
        retired = SigningKey.ed25519(VALID_KEY_A, status=RETIRED_STATUS)
        key_set = SigningKeySet([retired])
        assert retired.is_retired
        assert key_set.usable_keys == (retired,)
