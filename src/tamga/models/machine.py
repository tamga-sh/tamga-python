"""Machine, component, and process resource models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID


class HeartbeatStatus(str, Enum):
    """Machine heartbeat state machine.

    Transitions: ``NOT_STARTED`` (never pinged) -> ``ALIVE`` (pinged within
    window) -> ``DEAD`` (window elapsed) -> ``RESURRECTED`` (a new ping
    arrived after a death event was already recorded).

    The window is the license policy's ``heartbeat_duration``, falling back to
    600 seconds only when that column is unset — it is not a fixed constant, so
    a ping interval sized against 600s is unsafe under a shorter policy.

    **``DEAD`` cannot be observed through any call this SDK makes.** It is a
    real server-side state, but every route this SDK exposes returns a machine
    that is definitionally not in it:

    - ``ping_heartbeat`` sets ``last_heartbeat_at = NOW()`` and then derives
      the status from that same timestamp, so the age is ~0 → ``ALIVE`` or
      ``RESURRECTED``.
    - ``reset_heartbeat`` nulls the timestamp → ``NOT_STARTED``.
    - ``machines.create`` never sets it → ``NOT_STARTED``.
    - License validation never emits ``ValidationCode.HEARTBEAT_DEAD``.

    ``DEAD`` becomes visible only from a machine *read* (``GET /machines/{id}``
    or the machine list), which this SDK version does not offer. So do not
    write code that waits for ``DEAD``, and above all do not treat it as a stop
    condition — see ``tamga.client.HeartbeatScheduler``, where exactly that
    branch was both unreachable and, had it fired, unrecoverable.

    When ``DEAD`` does become readable, it will still mean only "the last ping
    is older than the window" — never "the row was deleted". The culling worker
    skips any policy with ``require_heartbeat: false``, which is the default,
    so under a default policy nothing is culled and a machine past its window
    keeps its row and its seat indefinitely; the ping is an unconditional
    ``last_heartbeat_at`` write that revives it. A ``404`` on the ping is the
    only signal that the row is genuinely gone. Cull/resurrection behavior,
    where enabled, is described by ``HeartbeatCullStrategy`` and
    ``HeartbeatResurrectionStrategy`` in ``tamga.models.policy``.
    """

    NOT_STARTED = "NOT_STARTED"
    ALIVE = "ALIVE"
    DEAD = "DEAD"
    RESURRECTED = "RESURRECTED"


@dataclass(frozen=True)
class MachineResource:
    """A machine activated against a license.

    Attributes:
        id: Resource UUID.
        fingerprint: Unique within the policy's machine-uniqueness scope —
            per license by default, but a policy may widen that to per policy
            or per account.
        name: Optional display name.
        ip: Optional IP address.
        hostname: Optional hostname.
        platform: Optional platform string.
        cores: Optional core count.
        memory: Optional memory, in **megabytes** — not bytes. The server
            sums this column across the license's machines and checks it
            against the policy limit, so reporting bytes inflates the total by
            ~1e6 and trips ``MEMORY_LIMIT_EXCEEDED`` on the next activation.
        disk: Optional disk, in **megabytes** — same caveat as ``memory``.
        metadata: Arbitrary caller-supplied metadata.
        heartbeat_status: Current heartbeat state; see ``HeartbeatStatus``.
        last_heartbeat_at: When the machine last pinged, if ever. The only
            client-side basis for a liveness decision that does not re-derive
            ``heartbeat_status``.
        next_heartbeat_at: Server's own estimate of the next ping deadline.
            Trustworthy on the machine *read* routes, which join the policy —
            **not** on the ping response, which does not.
        last_check_out_at: When a machine file was last checked out.
        created: Creation timestamp.
        updated: Last-update timestamp.
    """

    id: UUID
    fingerprint: str
    name: str | None = None
    ip: str | None = None
    hostname: str | None = None
    platform: str | None = None
    cores: int | None = None
    memory: int | None = None
    disk: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    heartbeat_status: HeartbeatStatus = HeartbeatStatus.NOT_STARTED
    last_heartbeat_at: datetime | None = None
    next_heartbeat_at: datetime | None = None
    last_check_out_at: datetime | None = None
    created: datetime | None = None
    updated: datetime | None = None


@dataclass(frozen=True)
class ComponentResource:
    """A component belonging to a machine.

    Attributes:
        id: Resource UUID.
        machine_id: Owning machine UUID.
        fingerprint: Unique per ``(account_id, machine_id, fingerprint)``.
        name: Required display name.
        metadata: Arbitrary caller-supplied metadata.
        created: Creation timestamp.
        updated: Last-update timestamp.
    """

    id: UUID
    machine_id: UUID
    fingerprint: str
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created: datetime | None = None
    updated: datetime | None = None


@dataclass(frozen=True)
class ProcessResource:
    """A monitored process belonging to a machine.

    Attributes:
        id: Resource UUID.
        machine_id: Owning machine UUID.
        pid: Process ID. **Typed as a string on the wire, not an integer** —
            mirror the server's typing exactly; do not silently coerce int
            input to str at the call boundary (see ``processes.create``).
        metadata: Arbitrary caller-supplied metadata.
        last_heartbeat_at: When the process last pinged. Always present on
            the wire — a process is ``ALIVE`` from creation.
        created: Creation timestamp.
        updated: Last-update timestamp.

    Note:
        Unlike machines (which start ``NOT_STARTED``), processes start
        ``ALIVE`` immediately at creation — the heartbeat timestamp is set
        then. The process heartbeat window is a hardcoded **30 seconds**
        (much shorter than the machine window) with no resurrection
        grace period.
    """

    id: UUID
    machine_id: UUID
    pid: str
    metadata: dict[str, Any] = field(default_factory=dict)
    last_heartbeat_at: datetime | None = None
    created: datetime | None = None
    updated: datetime | None = None


@dataclass(frozen=True)
class MachineFileResource:
    """The JSON:API ``machine-files`` resource returned by the ``POST`` checkout variant.

    Mirrors ``tamga.models.license.LicenseFileResource`` field-for-field —
    the server's ``machine_file_response`` serializer emits the identical
    shape (``certificate``/``algorithm``/``includes``/``ttl``/``expiry``/
    ``issued``), just wrapping a machine-file certificate instead of a
    license-file one.

    Attributes:
        certificate: The full machine-file PEM-style wrapper string. Parse
            and verify it with ``tamga.checkout.machine_file.MachineFile``,
            passing the license's own ``scheme``.
        algorithm: An encryption prefix (``base64`` or ``aes-256-gcm``) plus
            a signing suffix (``ed25519``, ``rsa-sha256``,
            ``rsa-pss-sha256``, or ``ecdsa-p256``), e.g.
            ``"aes-256-gcm+ecdsa-p256"``. Unlike license files, machine
            files carry no ``+v2`` suffix — see
            ``tamga.checkout.machine_file.VALID_ALGORITHMS``.
        includes: Always ``[]`` today, same caveat as license checkout.
        ttl: TTL in seconds, as requested. Metadata only.
        expiry: Computed expiry timestamp. Metadata only.
        issued: Issuance timestamp.
    """

    certificate: str
    algorithm: str
    includes: list[Any]
    ttl: int | None
    expiry: str | None
    issued: str
