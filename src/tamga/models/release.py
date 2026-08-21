"""The ``releases`` resource returned by the auto-update check.

Only the *read* half of the release surface is modelled: this SDK asks the
server "is there a newer build I may have?" and reads back the answer. Creating,
publishing, yanking or downloading a release are console/CI operations that need
a privileged token, and none of them is exposed here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class ReleaseResource:
    """A published release, as returned by ``ReleasesClient.check_for_upgrade``.

    The server emits no JSON:API ``relationships`` object for this resource;
    ``product_id`` is a plain attribute, which is the only link back to the
    product a release belongs to.

    Attributes:
        id: Resource UUID.
        product_id: The owning product's UUID.
        version: The release's version string. Compare it against the caller's
            own current version to decide whether to act — the SDK does not
            parse or order version strings, because the ordering that matters is
            the server's and it already applied it before answering.
        channel: Release channel (e.g. ``"stable"``).
        status: Release status string as stored server-side.
        name: Optional display name.
        tag: Optional tag. **Omitted entirely from the wire when unset**, not
            sent as ``null``, so absence and an explicit null are the same thing
            here.
        metadata: Arbitrary metadata attached to the release.
        created: Creation timestamp.
        updated: Last-update timestamp.
    """

    id: UUID
    product_id: UUID
    version: str
    channel: str
    status: str
    name: str | None = None
    tag: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created: datetime | None = None
    updated: datetime | None = None
