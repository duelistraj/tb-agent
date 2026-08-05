"""Profile-local, restart-safe port range allocation for execution workers."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from uuid import UUID

from tether_agent.state import PortReservation, StateStore

PORT_RANGE_START = 20_000
PORT_RANGE_END = 49_999
PORTS_PER_RUN = 32


@dataclass(frozen=True, slots=True)
class RunNamespace:
    run_id: UUID
    worker_slot: int
    port_start: int
    port_end: int

    def environment(self) -> dict[str, str]:
        short_id = self.run_id.hex[:12]
        return {
            "TB_AGENT_RUN_ID": str(self.run_id),
            "TB_AGENT_RUN_NAMESPACE": f"tb-agent-{short_id}",
            "TB_AGENT_PORT_BASE": str(self.port_start),
            "TB_AGENT_PORT_END": str(self.port_end),
            "TB_AGENT_WORKER_SLOT": str(self.worker_slot),
        }


class PortAllocator:
    def __init__(self, store: StateStore) -> None:
        self.store = store

    @staticmethod
    def _range_available(port_start: int, port_end: int) -> bool:
        sockets: list[socket.socket] = []
        try:
            for port in range(port_start, port_end + 1):
                candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                candidate.bind(("127.0.0.1", port))
                sockets.append(candidate)
        except OSError:
            return False
        finally:
            for candidate in sockets:
                candidate.close()
        return True

    @staticmethod
    def _namespace(reservation: PortReservation) -> RunNamespace:
        return RunNamespace(
            run_id=reservation.run_id,
            worker_slot=reservation.worker_slot,
            port_start=reservation.port_start,
            port_end=reservation.port_end,
        )

    def allocate(self, *, run_id: UUID, worker_slot: int) -> RunNamespace:
        existing = self.store.port_reservation(run_id)
        if existing is not None:
            if existing.state == "released":
                raise RuntimeError("A terminal run cannot reserve ports again")
            if not self._range_available(existing.port_start, existing.port_end):
                raise RuntimeError(
                    "The persisted port reservation is no longer available"
                )
            return self._namespace(existing)

        active = self.store.active_port_reservations()
        occupied = {
            port
            for reservation in active
            for port in range(reservation.port_start, reservation.port_end + 1)
        }
        block_count = (PORT_RANGE_END - PORT_RANGE_START + 1) // PORTS_PER_RUN
        first_block = int.from_bytes(run_id.bytes[:4], "big") % block_count
        for offset in range(block_count):
            block = (first_block + offset) % block_count
            port_start = PORT_RANGE_START + block * PORTS_PER_RUN
            port_end = port_start + PORTS_PER_RUN - 1
            if any(port in occupied for port in range(port_start, port_end + 1)):
                continue
            if not self._range_available(port_start, port_end):
                continue
            reservation = self.store.reserve_port_range(
                run_id=run_id,
                worker_slot=worker_slot,
                port_start=port_start,
                port_end=port_end,
            )
            return self._namespace(reservation)
        raise RuntimeError("No collision-free tb-agent port range is available")

    def release(self, run_id: UUID) -> None:
        self.store.release_port_reservation(run_id)
