"""Official Python SDK for Tamga.

Integrate license activation, offline verification, and machine management
into your Python applications.

Distributed on PyPI as ``tamga-sdk``; the importable package is ``tamga``.

Start with :class:`tamga.client.TamgaClient` for the HTTP surface (license
validation, check-in/checkout, machine and process management, entitlements)
and :mod:`tamga.checkout` for offline verification of ``.lic`` license files
and machine files. ``.lic`` files must be format v2 — see
:mod:`tamga.checkout.license_file` for what that enforces and why v1 files
are refused.

- Package README: https://github.com/tamga-sh/tamga-python
- Product documentation: https://tamga.sh
"""

from __future__ import annotations

from tamga.client import TamgaClient, TamgaConfig
from tamga.errors import (
    CheckInNotRequiredError,
    CoreLimitExceededError,
    DatasetInvalidError,
    DiskLimitExceededError,
    FingerprintTakenError,
    ForbiddenError,
    InternalServerError,
    KeyTakenError,
    LicenseExpiredError,
    LicenseKeyMissingError,
    LicenseNotAllowedError,
    LicenseNotEncryptedError,
    LicenseSuspendedError,
    MachineLimitExceededError,
    MemoryLimitExceededError,
    NotFoundError,
    PidTakenError,
    SchemeNotSupportedError,
    TamgaError,
    TooManyProcessesError,
    TtlInvalidError,
    UnauthorizedError,
    UnknownTamgaError,
)

__version__ = "0.2.0"

__all__ = [
    "CheckInNotRequiredError",
    "CoreLimitExceededError",
    "DatasetInvalidError",
    "DiskLimitExceededError",
    "FingerprintTakenError",
    "ForbiddenError",
    "InternalServerError",
    "KeyTakenError",
    "LicenseExpiredError",
    "LicenseKeyMissingError",
    "LicenseNotAllowedError",
    "LicenseNotEncryptedError",
    "LicenseSuspendedError",
    "MachineLimitExceededError",
    "MemoryLimitExceededError",
    "NotFoundError",
    "PidTakenError",
    "SchemeNotSupportedError",
    "TamgaClient",
    "TamgaConfig",
    "TamgaError",
    "TooManyProcessesError",
    "TtlInvalidError",
    "UnauthorizedError",
    "UnknownTamgaError",
    "__version__",
]
