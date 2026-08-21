"""Machine and process heartbeat scheduling side by side.

Machines and processes have very different heartbeat windows:
- Machines: the window is the license policy's `heartbeat_duration`, defaulting
  to 600s (10 min) when unset; ping every ~1/3 of it (~200s against the
  default). Never stop the loop on a heartbeat status — a ping response reports
  the timestamp it just wrote, so it is always ALIVE or RESURRECTED, and DEAD
  is not reachable from any call this SDK makes. The one signal that the
  machine is really gone is a 404 from the ping itself, which propagates out of
  `run_forever` for the caller to re-activate on.
- Processes: 30s window with NO resurrection grace period, ping every ~10s.
  Nothing reaps process rows server-side, so stopping the loop does not free
  the process slot.

Run:
    TAMGA_ACCOUNT_ID=... TAMGA_HOST=api.tamga.sh TAMGA_MACHINE_ID=... \
        TAMGA_PROCESS_ID=... python examples/heartbeat_scheduler.py
"""

from __future__ import annotations

import os
import threading
from uuid import UUID

from tamga import TamgaClient, TamgaConfig
from tamga.client import HeartbeatScheduler, ProcessHeartbeatScheduler


def main() -> None:
    account_id = os.environ["TAMGA_ACCOUNT_ID"]
    host = os.environ.get("TAMGA_HOST", "api.tamga.sh")
    machine_id = UUID(os.environ["TAMGA_MACHINE_ID"])
    process_id = UUID(os.environ["TAMGA_PROCESS_ID"])

    client = TamgaClient(TamgaConfig(account_id=account_id, host=host))

    machine_scheduler = HeartbeatScheduler(machines=client.machines, machine_id=machine_id)
    process_scheduler = ProcessHeartbeatScheduler(processes=client.processes, process_id=process_id)

    print(f"Machine heartbeat interval: {machine_scheduler.interval}")
    print(f"Process heartbeat interval: {process_scheduler.interval}")

    # Each scheduler blocks in its own loop — run them on separate threads
    # (or separate processes/async tasks in a real application).
    machine_thread = threading.Thread(target=machine_scheduler.run_forever, daemon=True)
    process_thread = threading.Thread(target=process_scheduler.run_forever, daemon=True)
    machine_thread.start()
    process_thread.start()

    try:
        machine_thread.join()
        process_thread.join()
    except KeyboardInterrupt:
        machine_scheduler.stop()
        process_scheduler.stop()
        client.close()


if __name__ == "__main__":
    main()
