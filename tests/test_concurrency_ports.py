from pathlib import Path
from uuid import uuid4

from tether_agent.ports import PORTS_PER_RUN, PortAllocator
from tether_agent.state import StateStore


def test_port_ranges_are_persisted_distinct_and_recoverable(tmp_path: Path) -> None:
    state_path = tmp_path / "state" / "state.sqlite3"
    store = StateStore(state_path)
    allocator = PortAllocator(store)
    first_run = uuid4()
    second_run = uuid4()

    first = allocator.allocate(run_id=first_run, worker_slot=0)
    second = allocator.allocate(run_id=second_run, worker_slot=1)

    assert first.port_end - first.port_start + 1 == PORTS_PER_RUN
    assert second.port_end - second.port_start + 1 == PORTS_PER_RUN
    assert first.port_end < second.port_start or second.port_end < first.port_start

    restarted = PortAllocator(StateStore(state_path))
    recovered = restarted.allocate(run_id=first_run, worker_slot=0)
    assert recovered == first

    restarted.release(first_run)
    assert StateStore(state_path).port_reservation(first_run).state == "released"


def test_worker_environment_is_run_specific(tmp_path: Path) -> None:
    allocator = PortAllocator(StateStore(tmp_path / "state" / "state.sqlite3"))
    run_id = uuid4()
    namespace = allocator.allocate(run_id=run_id, worker_slot=3)

    environment = namespace.environment()

    assert environment["TB_AGENT_RUN_ID"] == str(run_id)
    assert environment["TB_AGENT_WORKER_SLOT"] == "3"
    assert environment["TB_AGENT_PORT_BASE"] == str(namespace.port_start)
    assert environment["TB_AGENT_PORT_END"] == str(namespace.port_end)
