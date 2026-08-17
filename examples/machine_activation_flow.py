"""Create a machine, then validate the license, handling an over-limit rollback.

This is the documented activation flow (Tamga API protocol specification
section 5): the server does not check machine/core/memory/disk/process limits
at *creation* time — only later, on license validation. `activate_machine` implements
create -> validate -> delete-and-raise-on-over-limit so a caller doesn't
have to hand-roll the rollback themselves.

Run:
    TAMGA_ACCOUNT_ID=... TAMGA_HOST=api.tamga.sh TAMGA_LICENSE_ID=... \
        TAMGA_MACHINE_FINGERPRINT=... python examples/machine_activation_flow.py
"""

from __future__ import annotations

import os
import platform
from uuid import UUID

from tamga import TamgaClient, TamgaConfig


def main() -> None:
    account_id = os.environ["TAMGA_ACCOUNT_ID"]
    host = os.environ.get("TAMGA_HOST", "api.tamga.sh")
    license_id = UUID(os.environ["TAMGA_LICENSE_ID"])
    fingerprint = os.environ["TAMGA_MACHINE_FINGERPRINT"]

    with TamgaClient(TamgaConfig(account_id=account_id, host=host)) as client:
        try:
            machine = client.machines.activate_machine(
                license_id,
                fingerprint,
                name=platform.node(),
                platform=platform.system(),
                cores=os.cpu_count(),
            )
        except ValueError as exc:
            # activate_machine already deleted the just-created machine row
            # before raising — no manual cleanup needed here.
            print("Activation rejected (machine row rolled back):", exc)
            return

        print("Machine activated:", machine.id, machine.heartbeat_status)


if __name__ == "__main__":
    main()
