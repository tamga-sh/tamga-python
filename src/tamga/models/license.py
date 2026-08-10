"""License-related resource and scope models.

``LicenseResource`` is intentionally generic (JSON:API `type`/`id`/`attributes`/
`relationships` only) rather than a fully-typed attribute schema, because the
full license attribute set is not enumerated in docs/sdk.md — this is
documented as deliberate pending a published OpenAPI schema, not an oversight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from tamga.models.policy import Entitlement


@dataclass(frozen=True)
class LicenseScope:
    """The ``meta.scope`` object accepted by ``POST .../licenses/{id}/actions/validate``.

    All 8 fields are optional. Only ``product``, ``policy``, ``user``, and
    ``environment`` are actually enforced by the server today —
    ``entitlements``, ``fingerprint``, ``version``, and ``checksum`` are
    parsed but silently ignored server-side. They're modeled here for
    forward-compatibility (and because the request builder needs to be able
    to send them once the server catches up), but must not be advertised as
    functioning constraints yet.

    Attributes:
        product: Enforced. Product UUID to scope validation to.
        policy: Enforced. Policy UUID to scope validation to.
        user: Enforced. User UUID to scope validation to.
        environment: Enforced. Environment UUID to scope validation to.
        entitlements: Not enforced server-side yet. Entitlement codes.
        fingerprint: Not enforced server-side yet. Machine fingerprint.
        version: Not enforced server-side yet. Client/app version string.
        checksum: Not enforced server-side yet. Client-computed checksum.
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
        raise NotImplementedError

    def refresh_entitlements(self) -> list[Entitlement]:
        """Force a re-fetch of this license's cached entitlement list.

        Returns:
            The freshly-fetched list of entitlements.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class LicenseFileResource:
    """The JSON:API ``license-files`` resource returned by the ``POST`` checkout variant.

    Attributes:
        certificate: The full ``.lic`` PEM-style wrapper string.
        algorithm: One of ``"base64+ed25519"`` or ``"aes-256-gcm+ed25519"``.
        includes: Always ``[]`` today — there is no working ``include[]``
            param despite the field existing server-side. Do not build a
            "checkout with embedded relationships" feature around this.
        ttl: TTL in seconds, as requested. Metadata only — not embedded in
            the signed payload and not re-checked by the server later.
        expiry: Computed expiry timestamp. Metadata only, same caveat as ``ttl``.
        issued: Issuance timestamp.
    """

    certificate: str
    algorithm: str
    includes: list[Any]
    ttl: int | None
    expiry: str | None
    issued: str
