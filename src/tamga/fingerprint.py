"""Canonicalise caller-chosen machine identifiers into one stable fingerprint string.

**The defect this closes.** The server stores ``fingerprint TEXT NOT NULL``
with no length limit, no ``CHECK`` and no normalisation, unique per
``(license_id, fingerprint)`` — and every SDK in the family sends the caller's
string through byte-for-byte. So ``"ABC-123"``, ``"abc-123"`` and
``" ABC-123 "`` are three different machines holding three seats on one
licence, and nothing surfaces the mistake: each activation succeeds, the seat
count simply climbs.

**What this module deliberately does NOT do: read hardware identifiers.** What
identifies a machine is a product decision, not a library's. A cloned VM
template shares its identifiers, a container has none, a replaced motherboard
changes them — and no default is right for both a desktop application and a
Kubernetes sidecar. Eight independently-written implementations would also
disagree with each other, and the failure mode would be silent double-billing
rather than an error. The caller chooses the components; this module only fixes
how they are spelled.

Algorithm (``tamga-fingerprint-v1``)::

    fingerprint = lowercase_hex(SHA-256(UTF-8(canonical)))
    canonical   = "tamga-fingerprint-v1" <US> join(<US>, sorted(label + "=" + trimmed_value))

where ``<US>`` is U+001F, the ASCII unit separator, emitted as the single byte
``0x1f``. The literal prefix is a domain separator, so a future v2 rule cannot
collide with a v1 digest.

Three properties, each with a matching pair of test vectors:

- **Order-independent.** The caller's ordering is their convenience, not part
  of the machine's identity, so components are sorted before hashing.
- **Whitespace-equivalent.** Leading and trailing ASCII whitespace is trimmed.
  This is the footgun the module exists to absorb — a value read from a file or
  a command's output routinely carries a trailing newline.
- **Case-preserving.** Case folding is deliberately absent: lowercasing a
  base64 or hex identifier corrupts it.

**Values are NOT Unicode-normalised, and that is a constraint rather than an
oversight.** Python has ``unicodedata.normalize`` in its standard library, so
adding NFC here would cost nothing *in Python* — and that is exactly the trap.
NFC is unavailable without a new dependency in Rust and Go, and in C11 it would
mean ICU or hand-rolled Unicode tables inside a library whose selling point is
having none. A rule eight ports cannot implement identically is worse than no
rule: it would yield two different fingerprints for one machine depending on
which SDK the application happened to be written in, silently consuming two
seats. Do not "improve" this port by adding normalisation — it would make
Python the outlier that disagrees with the other seven. A caller whose values
can arrive in more than one normal form must normalise them *before* calling.

Rejections raise and are never silently repaired. Stripping a control character
or de-duplicating a repeated label would map two genuinely different inputs
onto one seat, which is the same class of bug as the one this module closes.

Example::

    from tamga.fingerprint import machine_fingerprint

    fp = machine_fingerprint({
        "machine-id": read_machine_id(),
        "disk": read_disk_serial(),
    })
    machine = client.machines.activate_machine(license_id, fingerprint=fp)
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Union

#: Domain separator and version marker, the first component of every canonical
#: string. Its purpose is that a future ``tamga-fingerprint-v2`` rule cannot
#: produce a digest that collides with a v1 one over the same components.
FINGERPRINT_DOMAIN: str = "tamga-fingerprint-v1"

#: U+001F, the ASCII unit separator, emitted as the single byte ``0x1f``. It
#: separates the domain prefix and each ``label=value`` component. It is
#: rejected inside a label (not printable ASCII) and inside a value (a control
#: character), so no component can forge a component boundary.
FINGERPRINT_SEPARATOR: str = "\x1f"

#: The exact set of characters trimmed from a value's ends: space, tab, CR, LF,
#: vertical tab, form feed.
#:
#: ⚠️ **Do not replace this with a bare ``str.strip()``.** Python's argument-less
#: strip removes every character for which ``str.isspace()`` is true, and that
#: set includes ``\x1c``-``\x1f`` — the unit separator itself — as well as
#: U+00A0 and other Unicode spaces. A value of ``"\x1fabc"`` must be *rejected*
#: (it contains a control character once trimmed), but a bare strip silently
#: turns it into ``"abc"`` and accepts it; U+00A0 is not ASCII whitespace at
#: all and must survive into the digest. Both divergences would be invisible in
#: Python and would disagree with the other seven ports.
ASCII_WHITESPACE: str = " \t\r\n\v\f"

_LABEL_MIN = 0x21
_LABEL_MAX = 0x7E
_DELETE = 0x7F

FingerprintComponents = Union[Mapping[str, str], Iterable[tuple[str, str]]]
"""Either a mapping of label to value, or an iterable of ``(label, value)`` pairs.

A mapping is the ordinary call shape. The pair form exists because a mapping
cannot express a duplicate label at all, and a duplicate label is a caller bug
this module is required to *report* rather than silently resolve.

Note: built with ``typing.Union`` rather than PEP 604 ``X | Y`` because this is
a runtime type-alias assignment, not an annotation — ``from __future__ import
annotations`` defers only annotations, and this SDK supports Python 3.9.
"""


class FingerprintComponentError(ValueError):
    """A component was rejected: bad label, bad value, duplicate, or none at all.

    Subclasses ``ValueError`` deliberately, matching ``SigningKeyError`` and
    the offline parsers in ``tamga.checkout``: a caller written to this SDK's
    documented ``except ValueError`` convention keeps catching it, while code
    that wants to tell a fingerprint problem from any other ``ValueError``
    still can.

    Nothing here raises ``TypeError``, ``KeyError`` or ``AttributeError``, even
    for input of the wrong type — such an escape past the documented contract
    was a HIGH finding in this repo before.
    """


def _pairs(components: FingerprintComponents) -> list[tuple[str, str]]:
    """Normalise either accepted input shape to a list of pairs, rejecting neither."""
    if isinstance(components, Mapping):
        return [(label, value) for label, value in components.items()]
    try:
        raw = list(components)
    except TypeError as exc:
        raise FingerprintComponentError(
            f"components must be a mapping or an iterable of (label, value) pairs, "
            f"got {type(components).__name__}"
        ) from exc

    pairs: list[tuple[str, str]] = []
    for index, item in enumerate(raw):
        if isinstance(item, str) or not isinstance(item, Iterable):
            raise FingerprintComponentError(
                f"component {index} must be a (label, value) pair, got {item!r}"
            )
        parts = list(item)
        if len(parts) != 2:
            raise FingerprintComponentError(
                f"component {index} must be a (label, value) pair of exactly two "
                f"items, got {len(parts)}"
            )
        pairs.append((parts[0], parts[1]))
    return pairs


def _validate_label(label: object, index: int) -> str:
    """Check one label: a non-empty run of printable ASCII, excluding ``=``.

    ``=`` is excluded so the split between label and value is unambiguously at
    the first ``=`` — which is what lets a value contain one freely. The
    printable-ASCII restriction also means a label can never itself need
    Unicode normalisation, which is the rule this module cannot implement.
    """
    if not isinstance(label, str):
        raise FingerprintComponentError(
            f"component {index}: label must be a str, got {type(label).__name__}"
        )
    if not label:
        raise FingerprintComponentError(f"component {index}: label must not be empty")
    for char in label:
        code = ord(char)
        if code < _LABEL_MIN or code > _LABEL_MAX:
            raise FingerprintComponentError(
                f"component {index}: label {label!r} must be printable ASCII "
                f"(0x21-0x7e); found {char!r}"
            )
        if char == "=":
            raise FingerprintComponentError(
                f"component {index}: label {label!r} must not contain '=', which "
                "would make the label/value split ambiguous"
            )
    return label


def _validate_value(value: object, label: str, index: int) -> str:
    """Trim a value's ASCII whitespace, then reject any remaining control character.

    Order matters and is part of the spec: trimming happens **before**
    validation, so a value that is nothing but whitespace becomes the empty
    string and is accepted, while an embedded control character is still
    refused.

    Control characters are rejected rather than stripped on purpose. Stripping
    would map two genuinely different inputs onto one canonical string, and
    therefore onto one seat — the same class of defect this module exists to
    close.
    """
    if not isinstance(value, str):
        raise FingerprintComponentError(
            f"component {index} ({label!r}): value must be a str, got {type(value).__name__}"
        )
    # Explicit character set: a bare `.strip()` would also remove U+001F and
    # U+00A0. See `ASCII_WHITESPACE`.
    trimmed = value.strip(ASCII_WHITESPACE)
    for char in trimmed:
        code = ord(char)
        if code <= 0x1F or code == _DELETE:
            raise FingerprintComponentError(
                f"component {index} ({label!r}): value contains control character "
                f"{char!r} (U+{code:04X}). Control characters are rejected, never "
                "stripped — stripping would map two different inputs onto one seat."
            )
    return trimmed


def canonical_form(components: FingerprintComponents) -> str:
    """Build the exact string that ``machine_fingerprint`` hashes.

    Exposed for diagnostics: when two installations that should agree produce
    different fingerprints, comparing their canonical forms shows *which*
    component differs, which the digest cannot.

    **Do not send this to the server as the fingerprint.** It contains raw
    U+001F bytes, it is unbounded in length, and it puts the caller's component
    values in plain text into a column that appears in list responses. Send
    ``machine_fingerprint`` output.

    Args:
        components: A mapping of label to value, or an iterable of
            ``(label, value)`` pairs. At least one component is required.

    Returns:
        ``"tamga-fingerprint-v1"`` followed by each ``label=trimmed_value``,
        all joined by U+001F, with the components sorted bytewise.

    Raises:
        FingerprintComponentError: If there are no components, a label is
            empty, non-printable-ASCII or contains ``=``, a value contains a
            control character after trimming, a label is repeated, or either
            is not a ``str``. Always a subclass of ``ValueError``.
    """
    pairs = _pairs(components)
    if not pairs:
        raise FingerprintComponentError("at least one component is required to build a fingerprint")

    seen: set[str] = set()
    encoded: list[str] = []
    for index, (raw_label, raw_value) in enumerate(pairs):
        label = _validate_label(raw_label, index)
        if label in seen:
            # Rejected, not de-duplicated: two values for one label is a caller
            # bug, and silently picking one of them hides it.
            raise FingerprintComponentError(
                f"component {index}: label {label!r} is repeated. Duplicate labels "
                "are rejected rather than de-duplicated — picking one of two values "
                "would hide the mistake."
            )
        seen.add(label)
        encoded.append(f"{label}={_validate_value(raw_value, label, index)}")

    # Bytewise ascending on the UTF-8 bytes of the whole `label=value` string —
    # not locale-aware, and written against the encoded bytes rather than
    # Python's default code-point ordering. The two coincide for UTF-8, but the
    # spec is stated in bytes because eight ports implement it and only the
    # byte rule is unambiguous in all of them.
    encoded.sort(key=lambda component: component.encode("utf-8"))
    return FINGERPRINT_SEPARATOR.join([FINGERPRINT_DOMAIN, *encoded])


def machine_fingerprint(components: FingerprintComponents) -> str:
    """Canonicalise labelled components into a stable 64-character fingerprint.

    A pure function: it reads no hardware, no environment and no files. The
    caller decides what identifies a machine — see this module's docstring for
    why that decision cannot live in a library.

    The result is suitable for ``MachinesClient.activate_machine``,
    ``find_by_fingerprint`` and the machine-file HKDF ``info``. It is
    lowercase hex, fixed length, and contains no character that needs escaping
    anywhere on the wire.

    Example::

        fp = machine_fingerprint({"machine-id": "abc123", "disk": "SN-9"})
        # -> "00a1635fd5cd0485076d26b0b3a32ae1ca56285db6244c756980ec07d02774d3"

    Args:
        components: A mapping of label to value, or an iterable of
            ``(label, value)`` pairs. At least one component is required.
            Values are trimmed of ASCII whitespace; case is preserved; nothing
            is Unicode-normalised.

    Returns:
        Lowercase hex SHA-256 of the canonical form: exactly 64 characters.

    Raises:
        FingerprintComponentError: On any rejected component; see
            ``canonical_form``. Always a subclass of ``ValueError``.
    """
    return hashlib.sha256(canonical_form(components).encode("utf-8")).hexdigest()
