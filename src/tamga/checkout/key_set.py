"""``SigningKeySet`` — the trusted keys an offline file is allowed to have been signed by.

**The defect this closes.** Verifying against one embedded public key collapses
two completely different outcomes into one error. A ``.lic`` or machine file
signed last month, before the account rotated its signing key, is authentic and
its license may well still be valid — but against the current key it fails with
exactly the error a forgery produces. The caller cannot tell "my key set is
stale" from "this file was tampered with", and the two call for opposite
responses: fetch the key set or ship an update, versus refuse the customer.
Every signed file already names the key that signed it, in the ``kid`` claim
``LicenseFileClaims`` has always parsed and nothing has ever used.

**Where the keys come from.** ``GET /v1/accounts/{account_id}/signing-keys``
publishes an account's whole key history, retired keys included
(``list_signing_keys.rs``) — reachable through
``TamgaClient.accounts.signing_key_set()``. But that route needs
``account.read``, which ``Role::LicenseToken`` does not hold
(``shared/authz/mod.rs:241-267``), so an embedded client authenticating with a
license key gets ``403`` — and that client is precisely the one doing offline
verification. :meth:`SigningKeySet.from_public_keys` therefore takes public keys
directly, so a set can be pinned into a binary, shipped in a config file, or
handed over by a build step that used a privileged token.

**An empty set is the ordinary state of a healthy account, not an error.**
``account_signing_keys`` is written only by ``rotate_ed25519``, which backfills
the account's current key on its way through (``signing_keys.rs``), so an
account that has never rotated has no rows at all and the endpoint answers
``{"data": []}``. Pin the account's published key with
``SigningKey.ed25519(...)`` and verification works before the first rotation as
well as after it.

**Order of operations, and why it is this way round.** The obvious
implementation reads the file's ``kid`` first and uses it to look a key up. That
inverts the one rule the rest of this package is built on — verify the
signature before interpreting anything inside ``enc`` (see
``tamga.checkout.machine_file``'s module docstring: "never decode
attacker-controlled bytes before authenticating them") — because the claim lives
*inside* the signed, possibly encrypted payload. So :func:`_resolve_signing_key`
does the opposite: every candidate key is tried against the signature first, and
the happy path never touches the payload unverified. The claim is read only
after every key has failed, at which point the file is already known not to be
authentic under anything we hold and the only remaining question is which of two
errors to report. Its value picks an error label and is used for nothing else —
no ``LicenseResource`` or ``MachineResource`` is ever built from an unverified
payload. The cost is at most one Ed25519 verification per key the account has
ever held, which is microseconds each.

(``tamga-rust`` resolves by ``kid`` first instead. Both reach the same verdict
on every file; this ordering is the one that holds this SDK's own stated
invariant, and it additionally survives a server that ever mislabelled a key.)

**Ed25519 only.** Every key the server publishes is Ed25519, and ``.lic`` files
are always Ed25519-signed regardless of the license's own ``scheme``. A machine
file signed under an RSA or ECDSA scheme cannot go through this path at all —
its key is not published, is never rotated, and its ``kid`` claim names the
account's *Ed25519* key rather than the key that signed it
(``check_out_machine.rs:86-99`` picks the signing key by scheme;
``:125-129`` computes the claim from ``account.ed25519_public_key``
unconditionally). Those files raise :class:`SigningKeyNotApplicableError`; verify
them with ``MachineFile.verify(public_key, scheme, ...)`` and the account's own
key for that algorithm. Nothing is lost: ``rotate_ed25519`` rotates the Ed25519
key alone, so no other scheme has a rotation to survive.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator

from cryptography.exceptions import InvalidSignature

from tamga.crypto.ed25519 import UNBACKFILLED_ACCOUNT_KEY_ID
from tamga.models.signing_key import ED25519_PUBLIC_KEY_LENGTH, SigningKey


class SigningKeyError(ValueError):
    """Base class for every key-set selection failure.

    Subclasses ``ValueError`` deliberately. Both ``verify()`` methods in this
    package document ``ValueError`` as the catch-all for a file that cannot be
    accepted, and a caller written as the documented
    ``except (ValueError, LicenseFileExpired):`` must keep catching every
    rejection the new entry points can produce. A bare ``KeyError`` or
    ``AttributeError`` escaping that contract has been a review finding in this
    repo before.
    """


class NoUsableSigningKeyError(SigningKeyError):
    """The key set held nothing that could verify anything.

    It was empty, every entry was for another algorithm, or none of them decoded
    as base64 of a 32-byte Ed25519 key. Raised **before** any signature check,
    so it says nothing about the file — only about the set.

    An empty set is the normal state of an account that has never rotated; see
    the module docstring. Pin the account's published key rather than treating
    it as a failure.

    Attributes:
        available: The ``kid`` of every key that was present but unusable, in
            the order supplied.
    """

    def __init__(self, available: Iterable[str]) -> None:
        """Initialize with the ids of the present-but-unusable keys."""
        self.available: tuple[str, ...] = tuple(available)
        detail = (
            "the key set was empty"
            if not self.available
            else f"none of {list(self.available)} is a usable Ed25519 key"
        )
        super().__init__(f"no usable Ed25519 signing key was supplied ({detail})")


class UnknownSigningKeyError(SigningKeyError):
    """The file names a signing key the set does not hold.

    **This is the case that is not a forgery**, and telling it apart from one is
    the entire point of this module. The file says which key signed it and that
    key is simply absent: a set fetched before the last rotation, a pinned key
    that has since been superseded, or a key an operator deleted outright (which
    is how a *compromised* key is retired, and which does invalidate every
    legitimate file signed with it). Refetch the key set — or ship one — before
    treating the file as suspect.

    Never raised while the named key is present: a file whose ``kid`` matches a
    key in the set and still fails verification raises
    ``cryptography.exceptions.InvalidSignature`` exactly as it always did.

    The ``kid`` is read from the payload **after** every known key has failed,
    and is used only to choose between this error and ``InvalidSignature``. It
    is unverified input and nothing else is derived from it.

    Attributes:
        kid: The ``kid`` the file claims, verbatim and unverified.
        available: The ids of the usable keys that were tried.
    """

    def __init__(self, kid: str, available: Iterable[str], message: str | None = None) -> None:
        """Initialize with the file's claimed key id and the ids that were tried.

        Args:
            kid: The ``kid`` the file claims.
            available: The ids of the usable keys that were tried.
            message: Overrides the default message. Only
                :class:`SigningKeyNotPublishedError` passes one, because "not in
                the key set" is true there but points support at the client's
                key set, which is not the problem.
        """
        self.kid = kid
        self.available: tuple[str, ...] = tuple(available)
        super().__init__(
            message
            if message is not None
            else (
                f"the file is signed by key {kid!r}, which is not in the key set "
                f"(had: {list(self.available)})"
            )
        )


class SigningKeyNotPublishedError(UnknownSigningKeyError):
    """The file was signed by an account that has published no signing key at all.

    A distinguishable case rather than a generic unknown ``kid``, because the
    remedy is a different one and refetching the key set will never help. The
    file's claim is exactly
    :data:`tamga.crypto.ed25519.UNBACKFILLED_ACCOUNT_KEY_ID` — SHA-256 of the
    empty string — which the server emits whenever ``account.ed25519_public_key``
    is unset, since both checkout handlers build the claim as
    ``key_id(account.ed25519_public_key.as_deref().unwrap_or_default())``.

    So: the client's key set is not stale, and no key it could obtain would
    verify this file. Somebody has to rotate the account's signing key
    server-side (which backfills the column on its way through). Subclasses
    :class:`UnknownSigningKeyError` so a caller that only wants "not verifiable
    with the keys I have" still catches it with one ``except``.
    """

    def __init__(self, kid: str, available: Iterable[str]) -> None:
        """Initialize with the empty-key ``kid`` and the ids that were tried."""
        super().__init__(
            kid,
            available,
            message=(
                f"the file names key {kid!r}, which is the id of the EMPTY key — the "
                "signing account has no published Ed25519 public key, so no key set "
                "can verify this file. The account's signing key must be rotated "
                "server-side (which backfills it). Refetching the key set will not help."
            ),
        )


class SigningKeyNotApplicableError(SigningKeyError):
    """This file's ``kid`` does not name the key that signed it, so no set can match it.

    **A server property, not a client limitation**, and worth stating precisely
    because the natural assumption is wrong. A machine file's signing key is
    chosen by the license's ``scheme`` (``check_out_machine.rs:86-99``), while
    its ``kid`` claim is computed from ``account.ed25519_public_key`` whatever
    the scheme (``:125-129``). For an RSA- or ECDSA-signed machine file the claim
    therefore names a key that had no part in the signature — and
    ``/signing-keys`` publishes Ed25519 keys only in any case.

    Verify those with ``MachineFile.verify(public_key, scheme, ...)`` and the
    account's own key for that algorithm. Nothing is lost:
    ``/actions/rotate-signing-key`` rotates the Ed25519 key alone, so there is no
    rotation for those schemes to survive. License files are unaffected — they
    are always Ed25519-signed, so their ``kid`` always names their signing key.

    Attributes:
        scheme: The offending scheme's wire value.
    """

    def __init__(self, scheme: str) -> None:
        """Initialize with the scheme whose ``kid`` claim names a different key."""
        self.scheme = scheme
        super().__init__(
            f"a {scheme} machine file's 'kid' claim names the account's Ed25519 key, "
            "not the key that signed it, so it cannot be matched against a key set — "
            "verify it with MachineFile.verify(public_key, scheme, ...) instead"
        )


class SigningKeySet:
    """The trusted keys an offline file is allowed to have been signed by.

    Build one from the account's published set with
    ``TamgaClient.accounts.signing_key_set()``, from
    :meth:`from_public_keys` for keys pinned by hand, or directly from
    ``SigningKey`` values. Then pass it to
    ``LicenseFile.verify_with_key_set`` or ``MachineFile.verify_with_key_set``.

    Iterable and sized; iteration yields every key supplied, usable or not, in
    the order given.
    """

    __slots__ = ("_keys",)

    def __init__(self, keys: Iterable[SigningKey] = ()) -> None:
        """Build a set from any iterable of keys.

        Lenient by design — see :meth:`from_public_keys` for the strict
        counterpart and why the two differ. Nothing is validated here: an entry
        for a future non-Ed25519 algorithm, or one whose ``public_key`` does not
        decode, is kept and simply never selected. This input is typically the
        server's whole key history, and one unusable row must not strand every
        file the account has already signed.

        Args:
            keys: The keys to trust, in any order.
        """
        self._keys: tuple[SigningKey, ...] = tuple(keys)

    @classmethod
    def from_public_keys(cls, public_keys: Iterable[str]) -> SigningKeySet:
        """Build a set from public keys the caller holds, deriving each ``kid`` locally.

        The offline path: no network access, and no need to be told each key's
        id, since the id is a pure function of the key. Each entry is marked
        ``ACTIVE_STATUS``, which nothing in verification reads.

        **Strict, unlike the constructor**, and for the opposite reason: a key
        pinned into an application binary or a config file is hand-entered, so a
        typo must fail loudly at startup rather than silently produce a set that
        reports every genuine file as signed by an unknown key.

        Args:
            public_keys: Standard base64 of the raw 32 bytes, exactly as the
                server publishes each key.

        Returns:
            The key set.

        Raises:
            ValueError: If any entry is not valid base64 of exactly 32 bytes.
                Reported with the offending entry's index, since the value
                itself may be long and near-identical to its neighbours.
        """
        keys = []
        for index, public_key in enumerate(public_keys):
            key = SigningKey.ed25519(public_key)
            if key.public_key_bytes is None:
                raise ValueError(
                    f"signing key at index {index} is not standard base64 of exactly "
                    f"{ED25519_PUBLIC_KEY_LENGTH} bytes, so it cannot be an Ed25519 "
                    "public key"
                )
            keys.append(key)
        return cls(keys)

    @property
    def keys(self) -> tuple[SigningKey, ...]:
        """Every key supplied, usable or not, in the order given."""
        return self._keys

    @property
    def kids(self) -> tuple[str, ...]:
        """The published ``kid`` of every key supplied."""
        return tuple(key.kid for key in self._keys)

    @property
    def usable_keys(self) -> tuple[SigningKey, ...]:
        """The keys that could actually verify an Ed25519 signature.

        Filters out entries for another algorithm and entries whose
        ``public_key`` does not decode to 32 bytes. Compare ``len`` against
        ``len(self)`` to detect that something was dropped.
        """
        return tuple(
            key for key in self._keys if key.is_ed25519 and key.public_key_bytes is not None
        )

    @property
    def inconsistent_keys(self) -> tuple[SigningKey, ...]:
        """Keys whose published ``kid`` disagrees with the one derived from the key.

        Always empty against a correct server: the resource ``id`` the endpoint
        serves *is* the ``kid``, computed from the same public key it publishes
        alongside it. Non-empty means the server labelled a key inconsistently,
        which is worth reporting upstream and is not something a client can fix.
        Selection tolerates it either way — it matches on the published id **or**
        the computed one, so a mislabelled key cannot turn a file legitimately
        signed with it into a reported forgery.
        """
        return tuple(key for key in self._keys if not key.kid_is_self_consistent)

    def find(self, kid: str) -> SigningKey | None:
        """The key this set holds under ``kid``, if any.

        Matches the published ``kid`` or the locally computed one — see
        :attr:`inconsistent_keys`. Exact and case-sensitive: the server emits
        lowercase hex on both sides, in the resource ``id`` and in the file's
        claim alike.

        Args:
            kid: The key id to look up.

        Returns:
            The key, or ``None``.
        """
        for key in self._keys:
            if kid in (key.kid, key.computed_kid):
                return key
        return None

    def __iter__(self) -> Iterator[SigningKey]:
        """Iterate every key supplied, in the order given."""
        return iter(self._keys)

    def __len__(self) -> int:
        """The number of keys supplied, usable or not."""
        return len(self._keys)

    def __eq__(self, other: object) -> bool:
        """Compare by the keys held, in order."""
        if not isinstance(other, SigningKeySet):
            return NotImplemented
        return self._keys == other._keys

    def __hash__(self) -> int:
        """Hash by the keys held, in order."""
        return hash(self._keys)

    def __repr__(self) -> str:
        """Show the ids held, never the key material."""
        return f"SigningKeySet(kids={list(self.kids)})"


def _resolve_signing_key(
    key_set: SigningKeySet,
    verify: Callable[[bytes], bool],
    unverified_kid: Callable[[], str | None],
) -> tuple[SigningKey, bytes]:
    """Pick the key an offline file was actually signed with, out of a trusted set.

    See the module docstring for why the signature check runs before the ``kid``
    is read rather than after.

    Args:
        key_set: The keys the caller trusts, in any order.
        verify: Runs the file's signature check against one candidate's decoded
            public key. Must not raise: ``alg``/scheme validation belongs before
            this call, not once per key.
        unverified_kid: Reads the file's own ``kid`` claim without verifying it,
            returning ``None`` if it cannot be read at all. Called at most once,
            and only after every candidate has already failed.

    Returns:
        ``(key, public_key_bytes)`` — the key that verified and its already-decoded
        public key, so the caller does not have to re-narrow an ``Optional`` that
        ``usable_keys`` has already excluded.

    Raises:
        NoUsableSigningKeyError: If the set holds no usable Ed25519 key.
        SigningKeyNotPublishedError: If nothing verified and the file names the
            empty key — the signing account published no key at all.
        UnknownSigningKeyError: If nothing verified and the file names a key the
            set does not hold.
        cryptography.exceptions.InvalidSignature: If nothing verified and the
            file either names a key that *is* in the set, or carries no readable
            ``kid`` at all. Both mean forged or corrupt, not rotated.
    """
    candidates = key_set.usable_keys
    if not candidates:
        raise NoUsableSigningKeyError(key_set.kids)

    for candidate in candidates:
        public_key_bytes = candidate.public_key_bytes
        # The `is not None` is type narrowing, not a check: `usable_keys` has
        # already excluded that case. It is written as a plain `if` rather than an
        # `assert` because `python -O` strips asserts, and nothing on a
        # verification path may depend on one.
        if public_key_bytes is not None and verify(public_key_bytes):
            return candidate, public_key_bytes

    available = tuple(candidate.kid for candidate in candidates)

    # Nothing verified. Only now is the payload worth looking at, and only for
    # the one field that separates the two failures.
    claimed = unverified_kid()
    if claimed is None:
        raise InvalidSignature("signature verification failed against every key in the set")
    if key_set.find(claimed) is not None:
        # The key it names is right here and the signature still fails. That is
        # tampering, not rotation.
        raise InvalidSignature(
            f"signature verification failed against key {claimed!r}, which is in the key set"
        )
    if claimed == UNBACKFILLED_ACCOUNT_KEY_ID:
        raise SigningKeyNotPublishedError(claimed, available)
    raise UnknownSigningKeyError(claimed, available)
