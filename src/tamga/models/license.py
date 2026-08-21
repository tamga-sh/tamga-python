"""License-related resource and scope models.

``LicenseResource`` is intentionally generic (JSON:API `type`/`id`/`attributes`/
`relationships` only) rather than a fully-typed attribute schema, because the
full license attribute set is not enumerated in the Tamga API protocol
specification — this is documented as deliberate pending a published OpenAPI
schema, not an oversight.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from tamga.models.policy import Entitlement


@dataclass(frozen=True)
class LicenseScope:
    """The ``meta.scope`` object accepted by ``POST .../licenses/{id}/actions/validate``.

    Six of the eight fields are enforced. ``version`` and ``checksum`` are
    **rejected**: the server refuses the whole call with ``422
    SCOPE_NOT_SUPPORTED`` (pointer ``/meta/scope``) the moment either key is
    present, before any validation runs, so the caller gets no ``meta.valid``
    at all. Both are therefore deprecated and this SDK **does not send them**
    — setting one degrades to a working validate rather than a hard failure.
    They remain on the dataclass because removing a public field would be a
    breaking change.

    Attributes:
        product: Enforced. Product UUID to scope validation to.
        policy: Enforced. Policy UUID to scope validation to.
        user: Enforced. User UUID to scope validation to.
        environment: Enforced. Environment UUID to scope validation to.
        entitlements: **Enforced.** Entitlement *codes* (the developer-facing
            strings — not the UUIDs used by attach/detach). Compared
            case-insensitively and de-duplicated, and satisfied by both direct
            and policy-inherited entitlements. An empty list asserts nothing.
            A shortfall yields ``ValidationCode.ENTITLEMENTS_MISSING``.
        fingerprint: **Enforced.** Matches against *any* machine registered to
            the license, regardless of that machine's heartbeat status. A
            mismatch yields ``ValidationCode.FINGERPRINT_SCOPE_MISMATCH``.
            This is the anti-key-sharing check — pass the activating machine's
            fingerprint here.
        version: **Deprecated, not sent.** Setting it has no effect; the
            server would reject the entire call with ``SCOPE_NOT_SUPPORTED``.
        checksum: **Deprecated, not sent.** Same as ``version``.
    """

    product: UUID | None = None
    policy: UUID | None = None
    user: UUID | None = None
    environment: UUID | None = None
    entitlements: list[str] | None = None
    fingerprint: str | None = None
    version: str | None = None
    checksum: str | None = None


@dataclass(frozen=True)
class LicenseResource:
    """Generic JSON:API license resource.

    Attributes:
        id: Resource UUID.
        type: JSON:API resource type, always ``"licenses"``.
        attributes: Raw attribute dict as returned by the server. Left
            untyped pending a published OpenAPI schema for licenses.
        relationships: Raw relationships dict as returned by the server.
    """

    id: UUID
    type: str
    attributes: dict[str, Any]
    relationships: dict[str, Any] = field(default_factory=dict)
    _entitlements_fetcher: Callable[[], list[Entitlement]] | None = field(
        default=None, repr=False, compare=False
    )
    _entitlements_cache: list[Entitlement] | None = field(default=None, repr=False, compare=False)

    def has_entitlement(self, code: str) -> bool:
        """Check whether this license carries an entitlement with the given ``code``.

        Fetches (and caches, per-instance) the license's entitlement list via
        ``GET /licenses/{id}/entitlements`` and matches on ``code`` — the
        stable, developer-facing identifier. Never matches on ``name``
        (display label only, not stable).

        Args:
            code: The entitlement code to check for.

        Returns:
            Whether an entitlement with this code is present.
        """
        entitlements = self._entitlements_cache
        if entitlements is None:
            entitlements = self.refresh_entitlements()
        return any(e.code == code for e in entitlements)

    def refresh_entitlements(self) -> list[Entitlement]:
        """Force a re-fetch of this license's cached entitlement list.

        Returns:
            The freshly-fetched list of entitlements.

        Raises:
            RuntimeError: If this ``LicenseResource`` wasn't constructed via
                ``TamgaClient`` (e.g. built directly by a caller/test) and so
                has no entitlements fetcher attached.
        """
        if self._entitlements_fetcher is None:
            raise RuntimeError(
                "This LicenseResource has no entitlements fetcher attached "
                "(it wasn't returned by TamgaClient) — call "
                "client.entitlements.list(license.id) directly instead."
            )
        entitlements = self._entitlements_fetcher()
        object.__setattr__(self, "_entitlements_cache", entitlements)
        return entitlements


@dataclass(frozen=True)
class LicenseFileResource:
    """The JSON:API ``license-files`` resource returned by the ``POST`` checkout variant.

    Wire-casing note: this resource's attributes carry ``rename_all =
    "camelCase"`` server-side, like ``releases`` — but unlike ``releases`` it
    makes no difference here, because every field is a single word. Should a
    multi-word field ever be added to it, it will arrive camelCased. Do not
    "correct" the existing six to snake_case, and do not assume the next one is
    snake_case by analogy with ``machines``/``licenses``/``policies``, which are.

    Attributes:
        certificate: The full ``.lic`` PEM-style wrapper string. Parse and
            verify it with ``tamga.checkout.license_file.LicenseFile``.
        algorithm: One of ``"base64+ed25519+v2"`` or
            ``"aes-256-gcm+ed25519+v2"`` — file format v2 is the only
            accepted form.
        includes: Always ``[]`` today — there is no working ``include[]``
            param despite the field existing server-side. Do not build a
            "checkout with embedded relationships" feature around this.
        ttl: TTL in seconds, as requested. Echoed back here outside the
            signature; the enforced copy is the ``exp`` claim inside the
            certificate's signed ``meta``.
        expiry: Computed expiry timestamp, same caveat as ``ttl`` — this
            field is advisory, ``LicenseFile.verify`` enforces the signed
            ``exp``.
        issued: Issuance timestamp.
    """

    certificate: str
    algorithm: str
    includes: list[Any]
    ttl: int | None
    expiry: str | None
    issued: str
