"""``TamgaClient`` façade and namespaced sub-clients for every endpoint group.

``TamgaClient`` wraps an ``httpx.Client`` and exposes namespaced sub-clients
(``.licenses``, ``.machines``, ``.components``, ``.processes``,
``.entitlements``) rather than one flat method namespace, mirroring the
resource grouping in docs/sdk.md.

Auth note: server-side auth enforcement is **not currently active** on the
license or machine endpoints (see docs/sdk.md "Known Server-Side Gaps" item
3) — this SDK still always sends proper credentials (default: ``Authorization:
License <key>`` for license-key-based flows) for forward-compatibility, not
because the server currently checks them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Generic, TypeVar
from uuid import UUID

import httpx  # noqa: F401

from tamga.models.license import LicenseFileResource, LicenseResource, LicenseScope
from tamga.models.machine import ComponentResource, MachineResource, ProcessResource
from tamga.models.policy import Entitlement
from tamga.models.validation import ValidationResult
from tamga.transport import DEFAULT_TIMEOUT_SECONDS, AuthTransport

T = TypeVar("T")

#: Recommended machine heartbeat ping interval — roughly 1/3 of the
#: server's hardcoded 600s heartbeat window (see docs/sdk.md section 5).
MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL: timedelta = timedelta(seconds=200)

#: Recommended process heartbeat ping interval — well inside the server's
#: hardcoded 30s process heartbeat window, which has no resurrection grace
#: period (see docs/sdk.md section 8).
PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL: timedelta = timedelta(seconds=10)


@dataclass(frozen=True)
class TamgaConfig:
    """Configuration for a ``TamgaClient``.

    Attributes:
        account_id: Required in both singleplayer and multiplayer server
            modes — in singleplayer mode it must equal the server's
            configured account, or the request resolves as unauthenticated.
        host: API host, without scheme (e.g. ``"api.tamga.sh"``).
        api_version: Sent as the ``Tamga-Version`` request header on every
            request. Should be pinned per SDK major version so server-side
            API evolution doesn't silently change response shapes underneath
            a released SDK version.
        default_auth: The default auth transport used when a per-call auth
            override isn't supplied.
        timeout_seconds: Connect/read timeout for the underlying
            ``httpx.Client``. No retry-on-429 is configured, since the
            server never sends 429 today.
        user_agent: Optional courtesy ``User-Agent`` header (e.g.
            ``"tamga-python/<version>"``). The server has no requirement or
            handling for this header.
    """

    account_id: str
    host: str
    api_version: str = "1"
    default_auth: AuthTransport | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    user_agent: str | None = None


@dataclass(frozen=True)
class Page(Generic[T]):
    """A keyset-paginated page of resources.

    Attributes:
        items: The resources on this page.
        next_after: The cursor to pass as ``after`` to fetch the next page,
            or ``None`` if this is the last page.
    """

    items: list[T]
    next_after: str | None


@dataclass
class LicensesClient:
    """Namespaced client for ``/licenses`` endpoints. Access via ``TamgaClient.licenses``."""

    _http: httpx.Client
    _config: TamgaConfig

    def validate_by_key(self, key: str) -> ValidationResult:
        """``POST /licenses/actions/validate-key``. No scope support on this endpoint."""
        raise NotImplementedError

    def validate_by_id(
        self,
        license_id: UUID,
        scope: LicenseScope | None = None,
        skip_touch: bool = False,
    ) -> ValidationResult:
        """``POST /licenses/{license_id}/actions/validate``.

        ``skip_touch`` (default ``False``) suppresses the
        ``last_validated_at`` side effect — useful for a client polling
        validity without affecting check-in/telemetry timestamps.
        """
        raise NotImplementedError

    def quick_validate(self, license_id: UUID) -> ValidationResult:
        """``GET /licenses/{license_id}/actions/validate``.

        Parses the flat plain-JSON response (no ``data`` envelope) via
        ``tamga.transport.parse_response(..., is_quick_validate=True)``.
        """
        raise NotImplementedError

    def check_in(self, license_id: UUID) -> LicenseResource:
        """``POST /licenses/{license_id}/actions/check-in``, no body.

        Raises:
            tamga.errors.CheckInNotRequiredError: On ``422
                CHECK_IN_NOT_REQUIRED`` — check ``policy.require_check_in``
                before scheduling periodic check-ins rather than retrying
                through this.
        """
        raise NotImplementedError

    def check_out(
        self, license_id: UUID, encrypt: bool = False, ttl: int | None = None
    ) -> bytes | LicenseFileResource:
        """``GET``/``POST /licenses/{license_id}/actions/check-out``.

        The ``GET`` variant (used when the caller wants raw bytes) returns
        the raw ``.lic`` file contents; the ``POST`` variant returns a
        structured ``LicenseFileResource``. ``id``/certificate content is a
        fresh UUIDv7 per call — **not idempotent**, repeat calls yield
        different certificates.

        Raises:
            tamga.errors.LicenseNotEncryptedError: On ``422
                LICENSE_NOT_ENCRYPTED`` if ``encrypt=True`` but the license
                has no key set.
        """
        raise NotImplementedError


@dataclass
class MachinesClient:
    """Namespaced client for ``/machines`` endpoints. Access via ``TamgaClient.machines``."""

    _http: httpx.Client
    _config: TamgaConfig

    def create(
        self,
        license_id: UUID,
        fingerprint: str,
        name: str | None = None,
        ip: str | None = None,
        hostname: str | None = None,
        platform: str | None = None,
        cores: int | None = None,
        memory: int | None = None,
        disk: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MachineResource:
        """``POST /machines``.

        No machine/core/etc. limit is checked at creation time — those
        limits only surface later via license validation. Prefer
        ``activate_machine`` for the documented create-then-validate flow.

        Raises:
            tamga.errors.FingerprintTakenError: On ``409 FINGERPRINT_TAKEN``
                for a duplicate ``(account_id, license_id, fingerprint)``.
        """
        raise NotImplementedError

    def delete(self, machine_id: UUID) -> None:
        """Standard resource deletion. Used by ``activate_machine``'s rollback path."""
        raise NotImplementedError

    def activate_machine(self, license_id: UUID, fingerprint: str, **attrs: Any) -> MachineResource:
        """Create a machine, then validate the license, rolling back on over-limit.

        Implements the documented flow: create machine -> validate license ->
        on ``TOO_MANY_MACHINES``/``TOO_MANY_CORES``/``TOO_MUCH_MEMORY``/
        ``TOO_MUCH_DISK``/``TOO_MANY_PROCESSES``, delete the just-created
        machine and raise, since the machine row may already have been
        created even though the license is over its limit.

        Args:
            license_id: The license to activate the machine against.
            fingerprint: The machine's unique fingerprint.
            **attrs: Additional optional machine attributes (``name``,
                ``ip``, ``hostname``, ``platform``, ``cores``, ``memory``,
                ``disk``, ``metadata``).

        Returns:
            The created (and license-validated) ``MachineResource``.
        """
        raise NotImplementedError

    def ping_heartbeat(self, machine_id: UUID) -> MachineResource:
        """``POST /machines/{id}/actions/ping-heartbeat``, no body. Sets ``last_heartbeat_at``."""
        raise NotImplementedError

    def reset_heartbeat(self, machine_id: UUID) -> MachineResource:
        """``POST /machines/{id}/actions/reset-heartbeat``, no body. Rewinds to ``NOT_STARTED``."""
        raise NotImplementedError

    def check_out(
        self, machine_id: UUID, encrypt: bool = False, ttl: int | None = None
    ) -> bytes | Any:
        """``GET``/``POST /machines/{id}/actions/check-out``.

        Client-side ``ttl`` pre-check mirrors server validation (``> 0`` and
        ``<= 31536000``) before sending, though the server remains
        authoritative and still returns ``422 TTL_INVALID`` on violation.

        Raises:
            tamga.errors.TtlInvalidError: If ``ttl`` fails the client-side
                pre-check (or the server rejects it anyway).
        """
        raise NotImplementedError

    def generate_offline_proof(
        self, machine_id: UUID, dataset: dict[str, Any] | None = None
    ) -> Any:
        """``POST /machines/{id}/actions/generate-offline-proof``.

        Always signed with RSA-2048 PKCS#1 v1.5 / SHA-256 server-side,
        regardless of the license's ``scheme``. Returns a
        ``tamga.proof.ProofResult``.
        """
        raise NotImplementedError


@dataclass
class ComponentsClient:
    """Namespaced client for ``/components`` endpoints. Access via ``TamgaClient.components``."""

    _http: httpx.Client
    _config: TamgaConfig

    def create(
        self,
        machine_id: UUID,
        fingerprint: str,
        name: str,
        metadata: dict[str, Any] | None = None,
    ) -> ComponentResource:
        """``POST /components``.

        Raises:
            tamga.errors.FingerprintTakenError: On ``409 FINGERPRINT_TAKEN``
                for a duplicate ``(account_id, machine_id, fingerprint)``.
        """
        raise NotImplementedError

    def list(
        self, machine_id: UUID, limit: int | None = None, after: str | None = None
    ) -> Page[ComponentResource]:
        """``GET /machines/{id}/components``, keyset-paginated (``limit``/``page[after]``)."""
        raise NotImplementedError


@dataclass
class ProcessesClient:
    """Namespaced client for ``/processes`` endpoints. Access via ``TamgaClient.processes``."""

    _http: httpx.Client
    _config: TamgaConfig

    def create(
        self, machine_id: UUID, pid: str, metadata: dict[str, Any] | None = None
    ) -> ProcessResource:
        """``POST /processes``.

        ``pid`` must be a ``str`` on the wire — reject non-string input at
        this boundary rather than silently ``str()``-coercing it, so callers
        don't accidentally build the wrong wire type upstream.

        Raises:
            TypeError: If ``pid`` is not a ``str`` (e.g. an ``int`` was passed).
            tamga.errors.PidTakenError: On ``409 PID_TAKEN`` for a duplicate
                PID on this machine.
        """
        raise NotImplementedError

    def ping(self, process_id: UUID) -> ProcessResource:
        """``POST /processes/{id}/actions/ping``, no body."""
        raise NotImplementedError


@dataclass
class EntitlementsClient:
    """Namespaced client for ``/entitlements`` endpoints. Access via ``TamgaClient.entitlements``."""  # noqa: E501

    _http: httpx.Client
    _config: TamgaConfig

    def list(
        self, license_id: UUID, limit: int | None = None, after: str | None = None
    ) -> Page[Entitlement]:
        """``GET /licenses/{license_id}/entitlements``, keyset-paginated.

        No auth/permission check is applied on this license-scoped read
        endpoint beyond the license existing.
        """
        raise NotImplementedError

    def get(self, license_id: UUID, entitlement_id: UUID) -> Entitlement:
        """``GET /licenses/{license_id}/entitlements/{entitlement_id}``.

        Despite the URL shape, returns a full ``Entitlement`` resource, not
        a lightweight junction record.
        """
        raise NotImplementedError


@dataclass
class HeartbeatScheduler:
    """Background-safe machine heartbeat ping loop.

    Recommends pinging at roughly 1/3 of the server's hardcoded 600s
    heartbeat window (~200s) to stay safely inside it.
    ``DEAD`` is treated as "machine likely deleted server-side —
    re-activate rather than retry ping", not as a transient error to retry
    through.

    Attributes:
        machine_id: The machine to ping.
        interval: Ping interval; defaults to
            ``MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL``.
    """

    machines: MachinesClient
    machine_id: UUID
    interval: timedelta = field(default=MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL)

    def run_forever(self) -> None:
        """Ping on ``self.interval`` until stopped/cancelled by the caller's runtime."""
        raise NotImplementedError


@dataclass
class ProcessHeartbeatScheduler:
    """Background-safe process heartbeat ping loop.

    Separate from ``HeartbeatScheduler`` since the interval (~10s) and
    dead-state semantics (immediate deletion, no resurrection grace period)
    differ substantially from the machine-level 600s window.

    Attributes:
        process_id: The process to ping.
        interval: Ping interval; defaults to
            ``PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL``.
    """

    processes: ProcessesClient
    process_id: UUID
    interval: timedelta = field(default=PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL)

    def run_forever(self) -> None:
        """Ping on ``self.interval`` until stopped/cancelled by the caller's runtime."""
        raise NotImplementedError


class TamgaClient:
    """Top-level façade wrapping ``httpx.Client``.

    Exposes namespaced sub-clients: ``.licenses``, ``.machines``,
    ``.components``, ``.processes``, ``.entitlements``.

    Example (illustrative — implementation is currently a stub):
        >>> client = TamgaClient(TamgaConfig(account_id="acct_123", host="api.tamga.sh"))
        >>> result = client.licenses.validate_by_key("MY-LICENSE-KEY")
        >>> result.meta.valid
        True
    """

    licenses: LicensesClient
    machines: MachinesClient
    components: ComponentsClient
    processes: ProcessesClient
    entitlements: EntitlementsClient

    def __init__(self, config: TamgaConfig) -> None:
        """Build the underlying ``httpx.Client`` and every namespaced sub-client.

        Args:
            config: Client configuration, including account ID, host, auth,
                and timeout.
        """
        raise NotImplementedError

    def close(self) -> None:
        """Close the underlying ``httpx.Client``."""
        raise NotImplementedError

    def __enter__(self) -> TamgaClient:
        raise NotImplementedError

    def __exit__(self, *exc_info: object) -> None:
        raise NotImplementedError
