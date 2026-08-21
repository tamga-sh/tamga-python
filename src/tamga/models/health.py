"""The unauthenticated liveness-probe payload returned by ``GET /v1/health``.

Deliberately **not** a JSON:API resource. The handler returns a bare object with
no ``data`` envelope and no ``type``/``id``, so it must not be routed through
the envelope-unwrapping response parser the rest of the surface uses.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HealthStatus:
    """The server's liveness report.

    Attributes:
        status: Literal health string; the handler hardcodes ``"ok"``, so
            reaching this object at all is the signal — there is no failing
            value to branch on. A server that is down answers with a transport
            error or a non-2xx status instead.
        version: The server's own package version. This is the *server* build,
            not the API version negotiated through the ``Tamga-Version`` header,
            and the two move independently.
        uptime_seconds: Seconds since the server process started. Wire name is
            ``uptime_secs``; renamed here to match this SDK's spelling of
            duration fields.
    """

    status: str
    version: str
    uptime_seconds: int
