"""Official Python SDK for Tamga.

Integrate license activation, offline verification, and machine management
into your Python applications. See:

- Package README: https://github.com/tamga-sh/tamga-python
- Protocol reference: docs/plans/tamga-python.plan.md (this repo) and
  ``tamga-api``'s ``docs/sdk.md`` (upstream server spec).

This package is currently a scaffold — public symbols are importable and
fully typed/documented, but method bodies raise ``NotImplementedError``
pending task-by-task implementation (see docs/plans/tamga-python.plan.md).
"""

from __future__ import annotations

from tamga.client import TamgaClient, TamgaConfig
from tamga.errors import (
    CheckInNotRequiredError,
    DatasetInvalidError,
    FingerprintTakenError,
    ForbiddenError,
    InternalServerError,
    KeyTakenError,
    LicenseKeyMissingError,
    LicenseNotEncryptedError,
    NotFoundError,
    PidTakenError,
    SchemeNotSupportedError,
    TamgaError,
    TtlInvalidError,
    UnauthorizedError,
    UnknownTamgaError,
)

__version__ = "0.1.0"

__all__ = [
    "CheckInNotRequiredError",
    "DatasetInvalidError",
    "FingerprintTakenError",
    "ForbiddenError",
    "InternalServerError",
    "KeyTakenError",
    "LicenseKeyMissingError",
    "LicenseNotEncryptedError",
    "NotFoundError",
    "PidTakenError",
    "SchemeNotSupportedError",
    "TamgaClient",
    "TamgaConfig",
    "TamgaError",
    "TtlInvalidError",
    "UnauthorizedError",
    "UnknownTamgaError",
    "__version__",
]
