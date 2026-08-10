"""Offline verification: ``.lic`` license files and machine files.

Both formats share the same outer ``{enc, sig, alg}`` envelope but differ in
signing scheme dispatch and encryption key derivation — see
``tamga.checkout.license_file`` and ``tamga.checkout.machine_file``.
"""

from __future__ import annotations

from tamga.checkout.license_file import LicenseFile
from tamga.checkout.machine_file import MachineFile

__all__ = ["LicenseFile", "MachineFile"]
