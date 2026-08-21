"""The ``artifacts`` resource — the downloadable payload a release ships.

Only the *read* half is modelled, and that is a permission boundary rather
than a stylistic choice: ``Role::LicenseToken`` carries ``artifact.read`` and
``artifact.download`` and stops there (``shared/authz/mod.rs:262-265``).
``artifact.create``/``update``/``delete`` are absent from that role, so
creating, replacing or uploading an artifact is a console/CI operation with a
privileged token and is deliberately not exposed here.

Wire-casing note: ``ArtifactAttributes`` (``artifacts/serializer.rs:19-38``)
carries ``rename_all = "camelCase"``, so ``redirect_url`` arrives as
``redirectUrl`` — but ``created_at``/``updated_at`` each carry an explicit
``#[serde(rename)]`` that overrides it, so they are ``created``/``updated``,
**not** ``createdAt``/``updatedAt``. Applying camelCase uniformly here yields
two null timestamps. Same exception-inside-the-exception as
``ReleaseResource``; this SDK has already shipped the mirror-image bug once,
on ``productId``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class ArtifactResource:
    """One artifact belonging to a release.

    The server emits no JSON:API ``relationships`` object for this resource
    and no ``release_id`` attribute — ``ArtifactAttributes`` simply does not
    carry one, though the column exists. So an artifact read on its own cannot
    be attributed back to its release from the response alone; the caller
    already knows the release id if it reached the artifact through
    ``ArtifactsClient.list``, and ``ArtifactsClient.get`` takes only the
    artifact's own id. Same shape as ``MachineResource``, which likewise
    carries no ``license_id``.

    Attributes:
        id: Resource UUID.
        filename: The artifact's file name. The only always-present string
            attribute besides ``status``.
        status: One of ``"WAITING"``, ``"PROCESSING"``, ``"UPLOADED"`` or
            ``"FAILED"`` — a closed vocabulary, pinned by the column's own
            ``CHECK`` constraint
            (``migrations/20240101000010_create_releases_and_artifacts.sql:114-115``)
            and defaulting to ``"WAITING"``. Kept as ``str`` rather than an
            enum, matching ``ReleaseResource.status``, which has the same shape
            of constraint. Only ``"UPLOADED"`` means bytes exist: the status is
            advanced by the multipart upload route and nothing else, so
            presigning a ``"WAITING"`` artifact yields a URL to an object that
            was never written.
        filetype: File type/extension, e.g. ``"dmg"``. Spelled one word
            server-side, matching the ``filetype`` query parameter on the
            upgrade check.
        filesize: Size in **bytes** — unlike a machine's ``memory``/``disk``,
            which are megabytes.
        checksum: Lowercase-hex SHA-256 over the uploaded bytes, computed
            server-side. Not caller-supplied: ``confirm_upload``
            (``artifacts/queries.rs:188-210``) is the only writer of this
            column, and neither create nor update touches it — so it is
            ``None`` until the upload completes. This SDK does not verify it
            against the downloaded bytes; the caller should, and it is the
            reason to prefer ``get_download_url`` over ``download`` for a large
            artifact.
        platform: Target platform string, e.g. ``"darwin-arm64"``.
        arch: Target architecture string.
        signature: Detached signature over the artifact, as published. Not
            verified by this SDK — this is the release publisher's own
            signature over the payload, unrelated to the Ed25519 signature on
            a ``.lic`` or machine file, and the key that would check it is not
            published by ``GET /signing-keys``.
        redirect_url: The short-lived presigned storage URL. **Absent on list
            and show** (``skip_serializing_if = "Option::is_none"``); populated
            only by ``ArtifactsClient.get_download_url``. Treat it as a
            credential: anyone holding it can fetch the bytes until it expires.
        metadata: Arbitrary metadata attached to the artifact.
        created: Creation timestamp. Wire key ``created``, not ``createdAt``.
        updated: Last-update timestamp. Wire key ``updated``, not ``updatedAt``.
    """

    id: UUID
    filename: str
    status: str
    filetype: str | None = None
    filesize: int | None = None
    checksum: str | None = None
    platform: str | None = None
    arch: str | None = None
    signature: str | None = None
    redirect_url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created: datetime | None = None
    updated: datetime | None = None
