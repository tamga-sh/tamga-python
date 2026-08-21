"""``SigningKey`` — one public key an account has held, current or retired.

The resource behind ``GET /v1/accounts/{account_id}/signing-keys``, which
publishes an account's **whole** signing-key history. Retired keys are included
on purpose: a client holding an offline file signed before the last rotation
needs the key that signed it, and without one its only options are to fail
verification or to accept any key at all — the second of which defeats signing
entirely (``list_signing_keys.rs``).

Pair this with ``tamga.checkout.key_set.SigningKeySet`` to verify a ``.lic`` or
machine file against the whole set rather than one embedded key.

⚠️ **``publicKey`` is the one camelCase attribute here.** ``SigningKeyAttributes``
(``accounts/serializer.rs:108-117``) is otherwise a snake_case struct —
``algorithm``, ``status``, ``created``, ``retired`` — with an explicit
``#[serde(rename = "publicKey")]`` on the public key alone. This SDK has already
shipped one bug of exactly this shape (``productId`` on the release resource,
read as ``product_id``), which is why ``tests/fixtures/signing_keys/`` carries a
response body whose keys were derived from the Rust struct rather than from
these field names.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime

from tamga.crypto.ed25519 import key_id

ED25519_ALGORITHM: str = "ed25519"
"""The ``algorithm`` value the server writes for every key it publishes.

``account_signing_keys``'s ``CHECK`` constraint also admits ``rsa2048`` and
``ecdsa_p256``, but ``rotate_ed25519`` is the only code path that ever writes a
row and it hardcodes ``'ed25519'`` in both of its inserts
(``signing_keys.rs:95-99,150-154``). So the published set is Ed25519-only in
practice — key selection filters on this value rather than assuming it, so a
future non-Ed25519 row cannot be handed to an Ed25519 verifier.
"""

ACTIVE_STATUS: str = "active"
"""``status`` of the key currently signing new files. At most one per algorithm."""

RETIRED_STATUS: str = "retired"
"""``status`` of a key kept for verification only."""

ED25519_PUBLIC_KEY_LENGTH: int = 32
"""Raw byte length of an Ed25519 public key, once base64-decoded."""


@dataclass(frozen=True)
class SigningKey:
    """One published signing key.

    Constructible by hand on purpose. ``TamgaClient.accounts.list_signing_keys``
    is one source, but the route needs ``account.read``, which a license-key
    credential does not hold — so the embedded client doing offline
    verification is exactly the one that gets ``403`` from it. Pinning keys at
    build time with :meth:`ed25519` is the supported answer; an offline
    verifier that only works while it has a network is not offline.

    Attributes:
        kid: The key's id — the JSON:API resource ``id``, and the value an
            offline file's signed ``kid`` claim names. The server sets it from
            ``PublishedSigningKey.kid`` (``accounts/serializer.rs:119-123``:
            "The ``kid`` doubles as the resource id — it is what an offline file
            names"), so a fetched key needs no local hashing to be matched.
        algorithm: ``"ed25519"`` on every row the server publishes today.
        public_key: The public key **exactly as published** — standard base64
            of the raw key bytes. Kept as the published string rather than
            decoded bytes because the string is what ``kid`` hashes: re-encoding,
            trimming or PEM-armoring it changes the hash and breaks the match.
            Use :attr:`public_key_bytes` for the decoded form.
        status: ``"active"`` or ``"retired"``. Deliberately a ``str`` and not an
            ``Enum``: the column's ``CHECK`` admits exactly those two today, but
            a future status must not fail the decode of a whole key set (the
            same leniency ``PolicyResource`` applies to its own enums).
        created: When the key was created. Wire name ``created``.
        retired: When the key was retired, or ``None`` while it is active. Wire
            name ``retired``, and **absent rather than null** when unset — the
            server skips the field entirely
            (``#[serde(skip_serializing_if = "Option::is_none")]``).
    """

    kid: str
    public_key: str
    algorithm: str = ED25519_ALGORITHM
    status: str = ACTIVE_STATUS
    created: datetime | None = None
    retired: datetime | None = None

    @classmethod
    def ed25519(cls, public_key: str, *, status: str = ACTIVE_STATUS) -> SigningKey:
        """Build an Ed25519 key record from the published public key alone.

        The intended way to pin a key into an application: a caller who has the
        public key does not also need to be told its id, because the id is a
        pure function of the key (:func:`tamga.crypto.ed25519.key_id`).

        Args:
            public_key: The public key as the server publishes it — standard
                base64 of the raw 32 bytes.
            status: Defaults to ``"active"``. Pass ``RETIRED_STATUS`` when
                pinning a key you know has since been rotated out; nothing in
                verification depends on it, but
                :attr:`tamga.checkout.key_set.SigningKeySet` reports it back so
                a caller can tell a file issued before the last rotation from a
                current one.

        Returns:
            The key record, with ``kid`` derived locally.
        """
        return cls(
            kid=key_id(public_key),
            public_key=public_key,
            algorithm=ED25519_ALGORITHM,
            status=status,
        )

    @property
    def computed_kid(self) -> str:
        """This key's id as derived locally from :attr:`public_key`."""
        return key_id(self.public_key)

    @property
    def kid_is_self_consistent(self) -> bool:
        """Whether the published ``kid`` matches the one derived from the key.

        A cross-check, not a requirement — the served resource ``id`` **is** the
        ``kid``, so matching a fetched key never needs local hashing. Key
        selection accepts either spelling precisely so that a server which
        somehow mislabelled a key could not turn a file legitimately signed with
        it into a reported forgery. ``False`` here is worth reporting upstream;
        it is not something a client can fix.
        """
        return self.computed_kid == self.kid

    @property
    def public_key_bytes(self) -> bytes | None:
        """The decoded raw public key, or ``None`` if it is unusable for Ed25519.

        ``None`` for anything that is not standard base64 of exactly
        :data:`ED25519_PUBLIC_KEY_LENGTH` bytes — including the empty string an
        unpopulated column would produce. Returning ``None`` rather than raising
        lets a key set drop one unusable row without stranding every file the
        account has already signed; :meth:`tamga.checkout.key_set.SigningKeySet.from_public_keys`
        is the strict counterpart, for keys pinned by hand where a typo must
        fail at startup.
        """
        try:
            decoded = base64.b64decode(self.public_key, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(decoded) != ED25519_PUBLIC_KEY_LENGTH:
            return None
        return decoded

    @property
    def is_ed25519(self) -> bool:
        """Whether this key is an Ed25519 key, compared case-insensitively."""
        return self.algorithm.lower() == ED25519_ALGORITHM

    @property
    def is_retired(self) -> bool:
        """Whether this key is retired — verification only, no longer signing.

        A file that verifies under a retired key is **authentic**. Nothing is
        wrong with it; it was simply issued before the account's last rotation,
        and whatever hands these out is due a fresh checkout.
        """
        return self.status.lower() == RETIRED_STATUS
