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
    ArtifactDownloadError,
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
    MachineOverLimitError,
    MemoryLimitExceededError,
    NotFoundError,
    PidTakenError,
    PresignTtlInvalidError,
    SchemeNotSupportedError,
    StorageUnavailableError,
    TamgaError,
    TooManyProcessesError,
    TtlInvalidError,
    UnauthorizedError,
    UnknownTamgaError,
)
from tamga.fingerprint import (
    FingerprintComponentError,
    canonical_form,
    machine_fingerprint,
)

# Kept in sync by release-please via the `generic` updater and the annotation below.
# The `python` updater was configured here previously and silently never fired, so this
# was stranded at 0.2.0 across the 1.0.0, 1.0.1, 1.0.2 and 1.0.3 releases.
__version__ = "1.1.0"  # x-release-please-version

__all__ = [
    "ArtifactDownloadError",
    "CheckInNotRequiredError",
    "CoreLimitExceededError",
    "DatasetInvalidError",
    "DiskLimitExceededError",
    "FingerprintComponentError",
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
    "MachineOverLimitError",
    "MemoryLimitExceededError",
    "NotFoundError",
    "PidTakenError",
    "PresignTtlInvalidError",
    "SchemeNotSupportedError",
    "StorageUnavailableError",
    "TamgaClient",
    "TamgaConfig",
    "TamgaError",
    "TooManyProcessesError",
    "TtlInvalidError",
    "UnauthorizedError",
    "UnknownTamgaError",
    "__version__",
    "canonical_form",
    "machine_fingerprint",
]
