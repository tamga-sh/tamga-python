"""Fingerprint canonicalisation, driven by the shared cross-SDK vectors.

The vectors in ``tests/fixtures/fingerprint/fingerprint.json`` are the
authority here, not this file. They were produced by an independent SHA-256
implementation rather than by any SDK — a fixture an SDK generated can only
prove that SDK agrees with itself, the same rule that governs
``tests/fixtures/machine_files/`` and ``tests/fixtures/signing_keys/``. Eight
ports hash against this one file, so a disagreement here is a disagreement
about which machine holds which seat.

Tests iterate the file rather than restating its contents, so a refreshed
vector set takes effect by dropping the file in. The three invariants that
matter most each have a *pair* of vectors, and each pair gets an explicit test
on top of the iteration, because iteration alone would still pass if two
vectors were quietly given the same expected digest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tamga.fingerprint import (
    ASCII_WHITESPACE,
    FINGERPRINT_DOMAIN,
    FINGERPRINT_SEPARATOR,
    FingerprintComponentError,
    canonical_form,
    machine_fingerprint,
)

VECTOR_FILE = Path(__file__).parent / "fixtures" / "fingerprint" / "fingerprint.json"
_DATA: dict[str, Any] = json.loads(VECTOR_FILE.read_text())
VECTORS: list[dict[str, Any]] = _DATA["vectors"]
REJECTED: list[dict[str, Any]] = _DATA["rejected"]


def _components(vector: dict[str, Any]) -> list[tuple[str, str]]:
    """Vectors store components as JSON arrays; the pair form preserves duplicates."""
    return [(label, value) for label, value in vector["components"]]


def _expected_canonical(vector: dict[str, Any]) -> str:
    """``<US>`` in the fixture is a display placeholder for the real U+001F byte."""
    return str(vector["canonical"]).replace("<US>", FINGERPRINT_SEPARATOR)


# --------------------------------------------------------------------------
# The vectors themselves
# --------------------------------------------------------------------------


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector_fingerprint(vector: dict[str, Any]) -> None:
    """Every positive vector's digest reproduces exactly."""
    assert machine_fingerprint(_components(vector)) == vector["fingerprint"]


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector_canonical_form(vector: dict[str, Any]) -> None:
    """The pre-hash string reproduces too.

    Worth asserting separately from the digest: a digest mismatch says only
    "wrong", while the canonical form says *which* rule — sorting, trimming,
    separator or prefix — was applied wrongly.
    """
    assert canonical_form(_components(vector)) == _expected_canonical(vector)


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector_fingerprint_is_64_lowercase_hex(vector: dict[str, Any]) -> None:
    """Fixed length, lowercase hex — no escaping needed anywhere on the wire."""
    fingerprint = machine_fingerprint(_components(vector))
    assert len(fingerprint) == 64
    assert all(c in "0123456789abcdef" for c in fingerprint)


@pytest.mark.parametrize("case", REJECTED, ids=[c["name"] for c in REJECTED])
def test_rejected_vector_raises(case: dict[str, Any]) -> None:
    """Every rejected case raises, and raises inside the documented contract.

    ``FingerprintComponentError`` subclasses ``ValueError``, so both assertions
    hold at once — the second is the one that matters to a caller written to
    this SDK's documented ``except ValueError`` convention.
    """
    with pytest.raises(FingerprintComponentError):
        machine_fingerprint(_components(case))
    with pytest.raises(ValueError):
        machine_fingerprint(_components(case))


@pytest.mark.parametrize("case", REJECTED, ids=[c["name"] for c in REJECTED])
def test_rejected_vector_is_not_silently_repaired(case: dict[str, Any]) -> None:
    """Nothing is repaired on the way through — ``canonical_form`` refuses too.

    If only ``machine_fingerprint`` validated, a caller reaching for the
    canonical form would get a string built from unvalidated input.
    """
    with pytest.raises(ValueError):
        canonical_form(_components(case))


def test_the_vector_file_has_not_shrunk() -> None:
    """Guards the guard: parametrised tests over an empty list pass vacuously."""
    assert len(VECTORS) == 9
    assert len(REJECTED) == 8


# --------------------------------------------------------------------------
# The three invariants, each pinned as a relationship between two vectors
# --------------------------------------------------------------------------


def test_component_order_does_not_change_the_fingerprint() -> None:
    """``two_sorted`` == ``two_unsorted``: ordering is caller convenience only.

    Asserted as an equality between the two vectors rather than against their
    stored digest, so it still fails if both stored digests drifted together.
    """
    sorted_vector = next(v for v in VECTORS if v["name"] == "two_sorted")
    unsorted_vector = next(v for v in VECTORS if v["name"] == "two_unsorted")
    assert _components(sorted_vector) != _components(unsorted_vector)
    assert machine_fingerprint(_components(sorted_vector)) == machine_fingerprint(
        _components(unsorted_vector)
    )


def test_surrounding_whitespace_does_not_change_the_fingerprint() -> None:
    """``whitespace_trimmed`` == ``single``: the footgun this module absorbs.

    A value read from a file or a subprocess routinely carries a trailing
    newline; without trimming that is a second seat.
    """
    plain = next(v for v in VECTORS if v["name"] == "single")
    padded = next(v for v in VECTORS if v["name"] == "whitespace_trimmed")
    assert _components(plain) != _components(padded)
    assert machine_fingerprint(_components(plain)) == machine_fingerprint(_components(padded))


def test_case_is_preserved_and_changes_the_fingerprint() -> None:
    """``case_preserved`` != ``single``: folding would corrupt base64 and hex ids."""
    lower = next(v for v in VECTORS if v["name"] == "single")
    upper = next(v for v in VECTORS if v["name"] == "case_preserved")
    assert machine_fingerprint(_components(lower)) != machine_fingerprint(_components(upper))


# --------------------------------------------------------------------------
# Python-specific traps the shared vectors cannot express
# --------------------------------------------------------------------------


def test_the_unit_separator_is_not_treated_as_trimmable_whitespace() -> None:
    """``str.strip()`` with no argument would strip U+001F itself.

    Python reports ``"\\x1f".isspace()`` as ``True``, so a bare strip turns
    ``"\\x1fabc"`` into ``"abc"`` and accepts it — while the spec says only
    space, tab, CR, LF, VT and FF are trimmed, leaving a control character that
    must be **rejected**. This is invisible in Python and would silently
    disagree with the other seven ports, which have no such notion of
    whitespace.
    """
    assert "\x1f".isspace() is True
    assert "\x1fabc".strip() == "abc"

    with pytest.raises(FingerprintComponentError, match="control character"):
        machine_fingerprint([("id", "\x1fabc")])
    with pytest.raises(FingerprintComponentError, match="control character"):
        machine_fingerprint([("id", "abc\x1f")])


def test_non_ascii_whitespace_is_not_trimmed() -> None:
    """U+00A0 is not ASCII whitespace, so it survives into the digest.

    A bare ``str.strip()`` would remove it, producing a different fingerprint
    from every other port for the same input.
    """
    assert "\xa0".isspace() is True
    assert "\xa0abc".strip() == "abc"

    assert canonical_form([("id", "\xa0abc")]) == f"{FINGERPRINT_DOMAIN}\x1fid=\xa0abc"
    assert machine_fingerprint([("id", "\xa0abc")]) != machine_fingerprint([("id", "abc")])


def test_the_trimmed_character_set_is_exactly_the_six_ascii_ones() -> None:
    """Pins the constant itself, so a "tidy-up" to ``string.whitespace`` fails here."""
    assert set(ASCII_WHITESPACE) == {" ", "\t", "\r", "\n", "\v", "\f"}
    for char in ASCII_WHITESPACE:
        assert machine_fingerprint([("id", f"{char}abc{char}")]) == machine_fingerprint(
            [("id", "abc")]
        )


def test_values_are_not_unicode_normalised() -> None:
    """Deliberately absent, even though Python could do it in one stdlib call.

    NFC needs a new dependency in Rust and Go and ICU or hand-rolled tables in
    C11. A rule eight ports cannot implement identically would give one machine
    two fingerprints depending on which SDK the application used. If someone
    "improves" this port by normalising, this test fails — which is the point.
    """
    import unicodedata

    # Written as escapes, not as literal text: an editor or a tooling pass that
    # normalised this source file would otherwise collapse the two spellings into
    # one and make the test pass vacuously.
    composed = "caf\u00e9"  # e-acute as a single code point (U+00E9)
    decomposed = "cafe\u0301"  # e + COMBINING ACUTE ACCENT (U+0301)
    assert unicodedata.normalize("NFC", decomposed) == composed
    assert composed != decomposed

    assert machine_fingerprint([("owner", composed)]) != machine_fingerprint(
        [("owner", decomposed)]
    )


def test_a_dict_is_accepted_as_well_as_pairs() -> None:
    """The ordinary call shape. A mapping cannot express a duplicate label."""
    assert machine_fingerprint({"machine-id": "abc123", "disk": "SN-9"}) == machine_fingerprint(
        [("machine-id", "abc123"), ("disk", "SN-9")]
    )


def test_dict_insertion_order_is_irrelevant() -> None:
    """Sorting happens after normalisation, so a dict's own order cannot leak in."""
    assert machine_fingerprint({"a": "1", "b": "2"}) == machine_fingerprint({"b": "2", "a": "1"})


def test_generators_are_accepted() -> None:
    """An iterable is consumed once and only once."""
    pairs = (("machine-id", "abc123"), ("disk", "SN-9"))
    assert machine_fingerprint(p for p in pairs) == machine_fingerprint(list(pairs))


# --------------------------------------------------------------------------
# Type errors stay inside the documented contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        42,
        [("id", 7)],
        [(7, "value")],
        [("id",)],
        [("id", "a", "b")],
        ["id=value"],
        [None],
        {"id": None},
        {None: "value"},
    ],
)
def test_wrong_types_raise_value_error_not_type_error(bad: Any) -> None:
    """No ``TypeError``/``KeyError``/``AttributeError`` escapes, for any input shape.

    Such an escape past the documented ``Raises`` was a HIGH finding in this
    repo before, on the two ``verify()`` paths. ``pytest.raises(ValueError)``
    would not catch a ``TypeError``, so this assertion is the guard.
    """
    with pytest.raises(ValueError):
        machine_fingerprint(bad)


def test_no_components_is_rejected() -> None:
    """An empty input has no identity to canonicalise; it must not hash to a constant."""
    for empty in ([], {}, ()):
        with pytest.raises(FingerprintComponentError, match="at least one component"):
            machine_fingerprint(empty)


def test_duplicate_labels_are_rejected_not_deduplicated() -> None:
    """Silently picking one of two values would map two inputs onto one seat."""
    with pytest.raises(FingerprintComponentError, match="repeated"):
        machine_fingerprint([("id", "a"), ("id", "b")])
    # And the message must not suggest the caller can just repeat the label.
    with pytest.raises(FingerprintComponentError, match="repeated"):
        machine_fingerprint([("id", "a"), ("id", "a")])


def test_an_empty_value_still_contributes_its_label() -> None:
    """A component that reads empty is not the same as an absent component."""
    assert machine_fingerprint([("a", ""), ("b", "x")]) != machine_fingerprint([("b", "x")])


def test_the_domain_prefix_is_present_and_versioned() -> None:
    """A v2 rule must not be able to collide with a v1 digest over the same input."""
    assert FINGERPRINT_DOMAIN == "tamga-fingerprint-v1"
    assert canonical_form([("id", "x")]).startswith(FINGERPRINT_DOMAIN + FINGERPRINT_SEPARATOR)


def test_the_separator_is_the_single_byte_0x1f() -> None:
    """One byte, not the two-character literal ``<US>`` the fixture displays."""
    assert FINGERPRINT_SEPARATOR == "\x1f"
    assert FINGERPRINT_SEPARATOR.encode("utf-8") == b"\x1f"
    assert "<US>" not in canonical_form([("id", "x")])


def test_a_label_cannot_smuggle_a_separator_or_an_equals() -> None:
    """Both would let one component forge a component boundary or an extra field."""
    with pytest.raises(FingerprintComponentError, match="printable ASCII"):
        machine_fingerprint([("a\x1fb", "x")])
    with pytest.raises(FingerprintComponentError, match="'='"):
        machine_fingerprint([("a=b", "x")])


def test_a_value_may_contain_equals_signs() -> None:
    """The split is unambiguously at the first ``=``, so a value needs no escaping."""
    assert canonical_form([("path", "a=b=c")]) == f"{FINGERPRINT_DOMAIN}\x1fpath=a=b=c"
