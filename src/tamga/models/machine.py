"""Machine, component, and process resource models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import UUID


class HeartbeatStatus(str, Enum):
    """Machine heartbeat state machine.

    Transitions: ``NOT_STARTED`` (never pinged) -> ``ALIVE`` (pinged within
    window) -> ``DEAD`` (window elapsed) -> ``RESURRECTED`` (a new ping
    arrived after a death event was already recorded).

    The heartbeat window is a **hardcoded 600 seconds (10 min)** server-side,
    not driven by ``policy.heartbeat_duration`` (see docs/sdk.md "Known
    Server-Side Gaps" item 8). Dead-machine handling beyond that depends on
    the license's policy — see ``HeartbeatCullStrategy`` and
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
        fingerprint: Unique per ``(account_id, license_id, fingerprint)``.
        name: Optional display name.
        ip: Optional IP address.
        hostname: Optional hostname.
        platform: Optional platform string.
        cores: Optional core count.
        memory: Optional memory (bytes or policy-defined unit).
        disk: Optional disk usage.
        metadata: Arbitrary caller-supplied metadata.
        heartbeat_status: Current heartbeat state; see ``HeartbeatStatus``.
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


@dataclass(frozen=True)
class ComponentResource:
    """A component belonging to a machine.

    Attributes:
        id: Resource UUID.
        machine_id: Owning machine UUID.
        fingerprint: Unique per ``(account_id, machine_id, fingerprint)``.
        name: Required display name.
        metadata: Arbitrary caller-supplied metadata.
    """

    id: UUID
    machine_id: UUID
    fingerprint: str
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)


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

    Note:
        Unlike machines (which start ``NOT_STARTED``), processes start
        ``ALIVE`` immediately at creation — the heartbeat timestamp is set
        then. The process heartbeat window is a hardcoded **30 seconds**
        (much shorter than the 600s machine window) with no resurrection
        grace period: a dead process row is deleted immediately.
    """

    id: UUID
    machine_id: UUID
    pid: str
    metadata: dict[str, Any] = field(default_factory=dict)
