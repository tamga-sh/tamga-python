"""Ed25519 signature verification, and the ``kid`` derived from a public key.

Used for: the license checkout signature (always Ed25519, independent of the
license's own ``scheme``), and as one of the four machine checkout
verification schemes (``LicenseScheme.ED25519_SIGN``).

``key_id`` lives here rather than under ``tamga.checkout`` because it is a
primitive — a fixed truncation of a SHA-256 digest — and because every key it
is ever applied to is an Ed25519 public key: the server publishes no other kind
(``signing_keys.rs`` hardcodes ``'ed25519'`` in both of its inserts) and both
checkout handlers compute the ``kid`` claim from the account's Ed25519 key
whatever scheme actually signed the file.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


def verify(public_key_bytes: bytes, message_bytes: bytes, signature_bytes: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key.
        message_bytes: The exact bytes that were signed. Callers in this SDK
            must be careful about *which* bytes that is — see the
            signing-message gotcha documented in
            ``tamga.checkout.license_file``.
        signature_bytes: The raw signature bytes (already base64-decoded by
            the caller).

    Returns:
        ``True`` if the signature is valid for the given key and message,
        ``False`` otherwise. Does not raise on an invalid signature.
    """
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message_bytes)
        return True
    except (InvalidSignature, ValueError):
        # ValueError: malformed key/signature bytes (wrong length, etc.) —
        # treated as a verification failure, not an error, since a caller
        # feeding an untrusted/corrupt certificate should get a uniform
        # "not valid" answer rather than a crash.
        return False


UNBACKFILLED_ACCOUNT_KEY_ID: str = "e3b0c44298fc1c14"
"""The ``kid`` an account with no published Ed25519 public key signs with.

Both checkout handlers build the claim as
``key_id(account.ed25519_public_key.as_deref().unwrap_or_default())``
(``check_out_license.rs:95``, ``check_out_machine.rs:127``), so an account whose
``ed25519_public_key`` column was never populated hashes the **empty string** —
which is this constant, SHA-256's well-known digest of nothing, truncated to
eight bytes.

Worth recognizing rather than reporting as just another unknown ``kid``, and
worth dating: it is a **pre-patch** artifact. Before the API patch
``account_signing_keys`` was written only by a rotation, so an account that had
never rotated signed with this id; the patched server publishes every account's
key from creation, backfills existing accounts at startup, repairs the Ed25519
public half so new files carry a real ``kid``, and refuses check-out with
``422 SIGNING_KEY_MISSING`` (``tamga.errors.SigningKeyMissingError``) rather
than signing with nothing. A file stamped with this id therefore predates the
patch: refetching the key set will not help, and a fresh checkout will — which
is why it is its own error, ``SigningKeyNotPublishedError``.

A published key can never carry this id: ``backfill_active_key`` returns early
when the column is ``NULL``, so no row is written for a key that does not exist.
"""


def key_id(public_key_base64: str) -> str:
    """The ``kid`` an offline file names, computed from a public key.

    The server's rule (``tamga-api/src/shared/crypto/license_file.rs:70-77``) is
    the first **eight bytes** of ``SHA-256`` over the public key, lowercase hex
    — a sixteen-character string, not an eight-character one. Because it is a
    pure function of the key, a client holding any public key can compute the id
    a file signed with it would name, which is what makes key rotation solvable
    offline.

    ⚠️ **The hash covers the base64 STRING, not the 32 decoded key bytes.** The
    server stores and publishes the Ed25519 public half as standard base64 and
    hands that same ``&str`` straight to ``key_id``; ``as_bytes()`` on a Rust
    ``&str`` is its UTF-8 bytes, so the digest is over the ASCII of
    ``"AAAA…="``. Decoding first produces a different, wrong id — the same
    shape of trap as the checkout signature covering ``enc``'s base64 string
    rather than its decoded bytes (see ``tamga.checkout.license_file``). Pinned
    from both directions in ``tests/test_signing_key_ids.py``.

    Args:
        public_key_base64: The public key exactly as the server publishes it —
            standard base64 of the raw key bytes. Passing the decoded bytes'
            base64 re-encoding is the same string; passing anything normalized
            (re-wrapped, trimmed, PEM-armored) is not, and yields a different
            id.

    Returns:
        Sixteen lowercase hex characters.
    """
    return hashlib.sha256(public_key_base64.encode("utf-8")).digest()[:8].hex()
