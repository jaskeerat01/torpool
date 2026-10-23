"""MetricsWindow: Rolling-window throughput sampler and global bandwidth token-bucket limiter."""

import asyncio
from collections import deque
import threading
import time
from typing import Optional


class MetricsWindow:
    """
    Rolling-window sampler recording per-circuit and aggregate throughput at a fixed tick.
    Single source of truth for throughput numbers across Scheduler, Status, and Dashboard.
     Also records control-port verified Tor circuit IDs and CIRC_BW byte counters.
    Samples live in memory only and are never written to disk.
    """

    def __init__(self, graph_window_seconds: int = 120, rolling_avg_seconds: int = 10) -> None:
        self.graph_window_seconds = graph_window_seconds
        self.rolling_avg_seconds = rolling_avg_seconds
        self._lock = threading.Lock()

        # Raw byte deliveries: circuit_id -> deque of (timestamp, byte_count)
        self._raw_circuit_bytes: dict[str, deque[tuple[float, int]]] = {}
        self._raw_aggregate_bytes: deque[tuple[float, int]] = deque()

        # Control-port verified Tor CIRC_BW byte totals per slot circuit_id
        self._control_port_bytes: dict[str, int] = {}

        # Sampled 1-second tick history for sparklines and charts
        self._circuit_history: dict[str, deque[float]] = {}
        self._aggregate_history: deque[float] = deque(maxlen=graph_window_seconds)

        self._peak_aggregate_bps: float = 0.0
        self._total_bytes_completed: int = 0
        self._total_bytes_target: int = 0

    def set_target_size(self, total_bytes: int, initial_completed: int = 0) -> None:
        """Initialize target file size and resumed byte count."""
        with self._lock:
            self._total_bytes_target = total_bytes
            self._total_bytes_completed = initial_completed

    def record_bytes(self, circuit_id: str, num_bytes: int, now: Optional[float] = None) -> None:
        """Record transferred bytes for a specific circuit."""
        ts = now if now is not None else time.monotonic()
        with self._lock:
            if circuit_id not in self._raw_circuit_bytes:
                self._raw_circuit_bytes[circuit_id] = deque()
                self._circuit_history[circuit_id] = deque(maxlen=self.graph_window_seconds)
            self._raw_circuit_bytes[circuit_id].append((ts, num_bytes))
            self._raw_aggregate_bytes.append((ts, num_bytes))
            self._total_bytes_completed += num_bytes
            self._prune_locked(ts)

    def record_control_port_bw(self, circuit_id: str, read_bytes: int) -> None:
        """Record Tor control-port CIRC_BW / STREAM_BW verified bytes for a circuit."""
        with self._lock:
            self._control_port_bytes[circuit_id] = self._control_port_bytes.get(circuit_id, 0) + read_bytes

    def get_control_port_bytes(self, circuit_id: str) -> int:
        """Return total bytes reported directly by Tor control-port events for circuit_id."""
        with self._lock:
            return self._control_port_bytes.get(circuit_id, 0)

    def _prune_locked(self, now: float) -> None:
        cutoff = now - max(self.graph_window_seconds, self.rolling_avg_seconds) - 5.0
        while self._raw_aggregate_bytes and self._raw_aggregate_bytes[0][0] < cutoff:
            self._raw_aggregate_bytes.popleft()
        for dq in self._raw_circuit_bytes.values():
            while dq and dq[0][0] < cutoff:
                dq.popleft()

    def tick_sample(self, now: Optional[float] = None) -> float:
        """
        Compute rolling throughput for each circuit and aggregate at a fixed tick (default 1s).
        Returns current aggregate rolling throughput in bytes/sec.
        """
        ts = now if now is not None else time.monotonic()
        with self._lock:
            self._prune_locked(ts)
            agg_rate = self._compute_rate_locked(self._raw_aggregate_bytes, ts, self.rolling_avg_seconds)
            self._aggregate_history.append(agg_rate)
            if agg_rate > self._peak_aggregate_bps:
                self._peak_aggregate_bps = agg_rate

            for cid, dq in self._raw_circuit_bytes.items():
                c_rate = self._compute_rate_locked(dq, ts, self.rolling_avg_seconds)
                self._circuit_history[cid].append(c_rate)

            return agg_rate

    @staticmethod
    def _compute_rate_locked(dq: deque[tuple[float, int]], now: float, window_s: int) -> float:
        cutoff = now - window_s
        total = sum(b for t, b in dq if t >= cutoff)
        return float(total) / float(window_s)

    def get_circuit_throughput(self, circuit_id: str, now: Optional[float] = None) -> float:
        """Return rolling throughput (bytes/sec) for a circuit over the rolling window."""
        ts = now if now is not None else time.monotonic()
        with self._lock:
            dq = self._raw_circuit_bytes.get(circuit_id)
            if not dq:
                return 0.0
            return self._compute_rate_locked(dq, ts, self.rolling_avg_seconds)

    def get_aggregate_throughput(self, now: Optional[float] = None) -> float:
        """Return rolling aggregate throughput (bytes/sec) over the rolling window."""
        ts = now if now is not None else time.monotonic()
        with self._lock:
            return self._compute_rate_locked(self._raw_aggregate_bytes, ts, self.rolling_avg_seconds)

    def get_snapshot(self) -> dict[str, object]:
        """Return a thread-safe snapshot for the Dashboard or status command."""
        now = time.monotonic()
        with self._lock:
            current_bps = self._compute_rate_locked(self._raw_aggregate_bytes, now, self.rolling_avg_seconds)
            hist = list(self._aggregate_history)
            avg_bps = sum(hist) / len(hist) if hist else current_bps
            remaining = max(0, self._total_bytes_target - self._total_bytes_completed)
            eta_s = (remaining / current_bps) if current_bps > 0 else -1.0
            circuit_snaps = {cid: list(chist) for cid, chist in self._circuit_history.items()}

            return {
                "current_bps": current_bps,
                "peak_bps": max(self._peak_aggregate_bps, current_bps),
                "avg_bps": avg_bps,
                "completed_bytes": self._total_bytes_completed,
                "total_bytes": self._total_bytes_target,
                "eta_s": eta_s,
                "aggregate_history": hist,
                "circuit_histories": circuit_snaps,
            }


class BandwidthLimiter:
    """Async token-bucket rate limiter enforcing max_bandwidth in bytes/sec."""

    def __init__(self, max_bandwidth_bps: int = 0) -> None:
        self.max_bandwidth_bps = max_bandwidth_bps
        self._tokens: float = float(max_bandwidth_bps)
        self._last_check: float = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, num_bytes: int) -> None:
        """Wait until enough bandwidth tokens are available for num_bytes."""
        if self.max_bandwidth_bps <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_check
                self._last_check = now
                self._tokens = min(
                    float(self.max_bandwidth_bps),
                    self._tokens + elapsed * self.max_bandwidth_bps,
                )
                if self._tokens >= num_bytes:
                    self._tokens -= num_bytes
                    return
                needed = num_bytes - self._tokens
                wait_time = needed / float(self.max_bandwidth_bps)
                await asyncio.sleep(min(wait_time, 0.25))
