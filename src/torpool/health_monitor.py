"""HealthMonitor background task probing circuits and triggering non-blocking replacements."""

import asyncio
import statistics
import time
from typing import Callable, Optional

import httpx

from torpool.circuit_pool import CircuitPool, CircuitState, ManagedCircuit
from torpool.config import TOR_BROWSER_USER_AGENT, TorPoolConfig
from torpool.events import EventBus, EventType


class HealthMonitor:
    """
    Probes each circuit every health_interval.
    Marks a circuit DEGRADED after 2 consecutive failures or latency > 3x pool median.
    Marks a circuit DEAD after 3 consecutive failures or timeout, and replaces it.
    """

    def __init__(
        self,
        config: TorPoolConfig,
        pool: CircuitPool,
        event_bus: EventBus,
        probe_func: Optional[Callable[[ManagedCircuit], asyncio.Future[tuple[bool, float, str]]]] = None,
    ) -> None:
        self.config = config
        self.pool = pool
        self.event_bus = event_bus
        self._probe_func = probe_func
        self._running = False
        self._task: Optional[asyncio.Task[None]] = None

    async def start(self) -> None:
        """Start periodic health probe background task."""
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Stop background health probing."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self) -> None:
        while self._running:
            await asyncio.sleep(self.config.health_interval)
            if not self._running:
                break
            await self.run_probe_cycle()

    async def run_probe_cycle(self) -> None:
        """Execute a single health check cycle across all active circuits."""
        active = [
            c for c in self.pool.circuits
            if c.state in (CircuitState.HEALTHY, CircuitState.DEGRADED, CircuitState.WARMING)
        ]
        if not active:
            return

        results = await asyncio.gather(*(self._probe_single(c) for c in active), return_exceptions=True)

        latencies = [
            c.latency_s for c in active
            if c.consecutive_failures == 0 and c.latency_s > 0
        ]
        median_latency = statistics.median(latencies) if latencies else 1.0

        replacement_tasks = []
        for c, res in zip(active, results):
            if isinstance(res, Exception):
                ok, lat, reason = False, self.config.circuit_timeout, str(res)
            else:
                ok, lat, reason = res

            if ok:
                c.consecutive_failures = 0
                c.latency_s = lat
                if len(latencies) >= 2 and lat > 3.0 * median_latency:
                    self.pool.transition_state(c.circuit_id, CircuitState.DEGRADED, reason="HIGH_LATENCY")
                else:
                    self.pool.transition_state(c.circuit_id, CircuitState.HEALTHY, reason="PROBE_OK")
            else:
                c.consecutive_failures += 1
                c.error_count += 1
                if c.consecutive_failures >= 3 or reason == "TIMEOUT":
                    self.pool.transition_state(c.circuit_id, CircuitState.DEAD, reason=reason)
                    replacement_tasks.append(
                        asyncio.create_task(self.pool.replace(c.circuit_id, reason=reason))
                    )
                elif c.consecutive_failures == 2:
                    self.pool.transition_state(c.circuit_id, CircuitState.DEGRADED, reason=reason)

            self.event_bus.emit(
                EventType.HEALTH_PROBE,
                circuit_id=c.circuit_id,
                status="OK" if ok else reason,
                latency_s=lat,
                state=c.state.value,
            )

        if replacement_tasks:
            await asyncio.gather(*replacement_tasks, return_exceptions=True)

    async def _probe_single(self, circuit: ManagedCircuit) -> tuple[bool, float, str]:
        """Probe a single circuit and return (is_ok, latency_s, reason)."""
        if self._probe_func is not None:
            return await self._probe_func(circuit)

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(
                proxy=circuit.proxy_url,
                timeout=httpx.Timeout(self.config.circuit_timeout),
                headers={"User-Agent": TOR_BROWSER_USER_AGENT},
                follow_redirects=False,
                trust_env=False,
            ) as client:
                resp = await client.head(self.config.health_probe_url)
                lat = time.monotonic() - t0
                if resp.status_code < 500:
                    return True, lat, "OK"
                return False, lat, f"HTTP_{resp.status_code}"
        except httpx.TimeoutException:
            return False, time.monotonic() - t0, "TIMEOUT"
        except Exception as exc:
            return False, time.monotonic() - t0, type(exc).__name__.upper()
