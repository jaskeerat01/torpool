"""CircuitPool managing N Tor circuits, per-circuit SOCKS listeners, states, and replacement."""

import asyncio
from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Optional

from torpool.config import TorPoolConfig
from torpool.events import EventBus, EventType
from torpool.metrics import MetricsWindow
from torpool.tor_controller import CircuitSocksListener, RelayInfo, TorController, TorError


class CircuitState(str, Enum):
    """Lifecycle states of a managed Tor circuit."""

    WARMING = "warming"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DEAD = "dead"
    RETIRING = "retiring"


@dataclass
class ManagedCircuit:
    """State, dedicated SOCKS listener, and performance metadata for a pooled Tor circuit."""

    circuit_id: str
    created_at: float
    relay_path: list[RelayInfo]
    socks_user: str
    socks_pass: str
    proxy_url: str
    socks_listener: Optional[CircuitSocksListener] = field(default=None, repr=False)
    listener_port: int = 0
    state: CircuitState = CircuitState.WARMING
    latency_s: float = 0.0
    throughput_bps: float = 0.0
    consecutive_failures: int = 0
    error_count: int = 0
    in_use: int = 0
    failed_at: Optional[float] = None

    @property
    def path_str(self) -> str:
        return " -> ".join(r.short_str for r in self.relay_path) if self.relay_path else "AUTO"

    async def kill_socks_listener(self) -> None:
        """Stop this circuit's dedicated SOCKS listener (used on retirement or fault injection)."""
        if self.socks_listener:
            await self.socks_listener.stop()
            self.socks_listener = None


class CircuitPool:
    """
    Holds N circuit objects and exposes acquire(), release(), and replace(circuit_id, reason).
    Each circuit gets its own dedicated local SOCKS listener and IsolateSOCKSAuth credentials.
    Replaces dead circuits asynchronously without blocking active downloads.
    """

    def __init__(
        self,
        config: TorPoolConfig,
        controller: TorController,
        event_bus: EventBus,
        metrics: MetricsWindow,
    ) -> None:
        self.config = config
        self.controller = controller
        self.event_bus = event_bus
        self.metrics = metrics
        self._circuits: dict[str, ManagedCircuit] = {}
        self._lock = asyncio.Lock()
        self._unavailable_slots: int = 0
        self._replacing_ids: set[str] = set()

    @property
    def circuits(self) -> list[ManagedCircuit]:
        return list(self._circuits.values())

    def healthy_circuits(self) -> list[ManagedCircuit]:
        """Return circuits eligible for work (HEALTHY or DEGRADED), sorted fastest first."""
        eligible = [
            c for c in self._circuits.values()
            if c.state in (CircuitState.HEALTHY, CircuitState.DEGRADED)
        ]
        eligible.sort(
            key=lambda c: (
                0 if c.state == CircuitState.HEALTHY else 1,
                -self.metrics.get_circuit_throughput(c.circuit_id),
                c.latency_s,
            )
        )
        return eligible

    def healthy_count(self) -> int:
        return sum(1 for c in self._circuits.values() if c.state == CircuitState.HEALTHY)

    async def initialize_pool(self) -> None:
        """Build N initial circuits for the download job."""
        tasks = [self._build_slot() for _ in range(self.config.circuits)]
        await asyncio.gather(*tasks)
        if self.healthy_count() == 0:
            raise TorError("Failed to build any healthy Tor circuits. Aborting.")

    async def _build_slot(self, failed_at: Optional[float] = None) -> Optional[ManagedCircuit]:
        """Attempt to build a single circuit and start its dedicated SOCKS listener (up to 3 retries)."""
        for attempt in range(1, 4):
            try:
                cid, path, duration, s_user, s_pass = await asyncio.to_thread(
                    self.controller.build_circuit, attempt
                )
                listener = CircuitSocksListener(
                    circuit_id=cid,
                    socks_user=s_user,
                    tor_socks_host="127.0.0.1",
                    tor_socks_port=self.config.socks_port_base,
                    controller=self.controller,
                )
                local_port = await listener.start()
                proxy_url = self.controller.get_socks_proxy_url(s_user, s_pass, listener_port=local_port)

                mc = ManagedCircuit(
                    circuit_id=cid,
                    created_at=time.monotonic(),
                    relay_path=path,
                    socks_user=s_user,
                    socks_pass=s_pass,
                    proxy_url=proxy_url,
                    socks_listener=listener,
                    listener_port=local_port,
                    state=CircuitState.HEALTHY,
                    latency_s=duration,
                    failed_at=failed_at,
                )
                async with self._lock:
                    self._circuits[cid] = mc
                    h_count = self.healthy_count()

                self.event_bus.emit(
                    EventType.CIRCUIT_BUILT,
                    circuit_id=cid,
                    attempt=attempt,
                    path_str=mc.path_str,
                    duration_s=duration,
                    healthy_count=h_count,
                )
                return mc
            except Exception as exc:
                async with self._lock:
                    h_count = self.healthy_count()
                self.event_bus.emit(
                    EventType.CIRCUIT_FAILED,
                    circuit_id="NONE",
                    attempt=attempt,
                    path_str="AUTO",
                    duration_s=0.0,
                    reason=str(exc),
                    healthy_count=h_count,
                )
                await asyncio.sleep(0.2 * attempt)

        async with self._lock:
            self._unavailable_slots += 1
        self.event_bus.emit(
            EventType.ERROR,
            message="Circuit slot marked unavailable after 3 build timeouts",
            reason="BUILD_TIMEOUT_EXHAUSTED",
        )
        return None

    async def acquire(self) -> Optional[ManagedCircuit]:
        """Acquire the best available healthy circuit for a chunk transfer."""
        async with self._lock:
            candidates = self.healthy_circuits()
            if not candidates:
                return None
            candidates.sort(
                key=lambda c: (
                    c.in_use,
                    0 if c.state == CircuitState.HEALTHY else 1,
                    -self.metrics.get_circuit_throughput(c.circuit_id),
                )
            )
            chosen = candidates[0]
            chosen.in_use += 1
            chosen.throughput_bps = self.metrics.get_circuit_throughput(chosen.circuit_id)
            return chosen

    async def release(self, circuit_id: str) -> None:
        """Release a circuit after chunk transfer completes or aborts."""
        async with self._lock:
            c = self._circuits.get(circuit_id)
            if c and c.in_use > 0:
                c.in_use -= 1
                c.throughput_bps = self.metrics.get_circuit_throughput(circuit_id)

    def transition_state(self, circuit_id: str, new_state: CircuitState, reason: str = "NONE") -> None:
        """Transition a circuit's state and emit CIRCUIT_STATE_CHANGE."""
        c = self._circuits.get(circuit_id)
        if not c or c.state == new_state:
            return
        old_state = c.state
        c.state = new_state
        if new_state in (CircuitState.DEAD, CircuitState.RETIRING) and c.failed_at is None:
            c.failed_at = time.monotonic()
        self.event_bus.emit(
            EventType.CIRCUIT_STATE_CHANGE,
            circuit_id=circuit_id,
            old_state=old_state.value,
            new_state=new_state.value,
            reason=reason,
            healthy_count=self.healthy_count(),
        )

    async def replace(self, circuit_id: str, reason: str, reassigned_chunks: int = 0) -> Optional[ManagedCircuit]:
        """
        Retire a dead/failed circuit, stop its dedicated SOCKS listener, close it via
        CLOSECIRCUIT, and build a fresh replacement without blocking active transfers.
        """
        async with self._lock:
            if circuit_id in self._replacing_ids:
                return None
            self._replacing_ids.add(circuit_id)
            old_c = self._circuits.get(circuit_id)
            fail_ts = old_c.failed_at if old_c and old_c.failed_at else time.monotonic()
            if old_c:
                self.transition_state(circuit_id, CircuitState.RETIRING, reason=reason)

        if old_c:
            await old_c.kill_socks_listener()
        await asyncio.to_thread(self.controller.close_circuit, circuit_id)
        new_c = await self._build_slot(failed_at=fail_ts)

        async with self._lock:
            self._circuits.pop(circuit_id, None)
            self._replacing_ids.discard(circuit_id)

        if new_c:
            recovery_s = max(0.0, time.monotonic() - fail_ts)
            self.event_bus.emit(
                EventType.CIRCUIT_REPLACED,
                old_circuit_id=circuit_id,
                new_circuit_id=new_c.circuit_id,
                reason=reason,
                reassigned_chunks=reassigned_chunks,
                recovery_s=recovery_s,
            )
        return new_c

    async def close_all(self) -> None:
        """Cleanly tear down all circuits and their dedicated SOCKS listeners."""
        async with self._lock:
            circuits = list(self._circuits.values())
            self._circuits.clear()
        for c in circuits:
            await c.kill_socks_listener()
            await asyncio.to_thread(self.controller.close_circuit, c.circuit_id)

