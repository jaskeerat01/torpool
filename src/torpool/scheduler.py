"""ChunkScheduler distributing chunks across healthy circuits with work-stealing and adaptive sizing."""

import asyncio
from collections import deque
from pathlib import Path
import random
import time
from typing import Optional

from torpool.circuit_pool import CircuitPool, ManagedCircuit
from torpool.config import TorPoolConfig
from torpool.downloader import DownloadError, RangeDownloader
from torpool.events import EventBus, EventType
from torpool.metrics import MetricsWindow
from torpool.state_store import ChunkRecord, StateStore


class SchedulerError(Exception):
    """Raised when a download cannot complete due to permanent chunk failures or security alerts."""


class ChunkScheduler:
    """
    Splits file into byte-range chunks, assigns chunks to fastest healthy circuits via work-stealing,
    adapts chunk size downward for slow circuits, handles exponential backoff with jitter on 429/503,
    and reassigns chunks when a circuit fails mid-transfer.
    """

    MIN_ADAPTIVE_CHUNK_SIZE = 256 * 1024  # 256 KiB floor for adaptive splitting

    def __init__(
        self,
        config: TorPoolConfig,
        pool: CircuitPool,
        downloader: RangeDownloader,
        state_store: StateStore,
        event_bus: EventBus,
        metrics: MetricsWindow,
    ) -> None:
        self.config = config
        self.pool = pool
        self.downloader = downloader
        self.state_store = state_store
        self.event_bus = event_bus
        self.metrics = metrics

        self._queue: deque[ChunkRecord] = deque()
        self._all_chunks: dict[int, ChunkRecord] = {}
        self._next_chunk_id: int = 0
        self._lock = asyncio.Lock()
        self._paused_error: Optional[str] = None
        self._permanent_failures: list[ChunkRecord] = []

    def trigger_emergency_pause(self, reason: str) -> None:
        """Fail-closed pause triggered on unexpected exit relay change or Tor disconnect."""
        self._paused_error = reason
        self.event_bus.emit(EventType.SECURITY_ALERT, message=f"Transfer paused: {reason}", reason="FAIL_CLOSED")

    @staticmethod
    def build_initial_chunks(total_size: int, chunk_size: int) -> list[ChunkRecord]:
        """Partition total_size into byte-range ChunkRecords."""
        if total_size <= 0:
            return []
        chunks: list[ChunkRecord] = []
        cid = 0
        offset = 0
        while offset < total_size:
            end = min(offset + chunk_size - 1, total_size - 1)
            chunks.append(ChunkRecord(chunk_id=cid, start_byte=offset, end_byte=end))
            cid += 1
            offset = end + 1
        return chunks

    async def execute_download(
        self,
        url: str,
        target_file: Path,
        resume: bool = False,
    ) -> int:
        """
        Coordinate full download of url into target_file.
        Returns total bytes downloaded.
        """
        first_circuit = await self.pool.acquire()
        if not first_circuit:
            raise SchedulerError("No healthy circuits available to probe target URL.")

        try:
            total_size, supports_ranges = await self.downloader.probe_target(url, first_circuit)
        finally:
            await self.pool.release(first_circuit.circuit_id)

        # Fallback to single-circuit streaming if server does not support byte ranges
        if not supports_ranges or total_size <= 0:
            self.event_bus.emit(
                EventType.FALLBACK_STREAMING,
                message="Server does not support ranged requests; falling back to single-circuit streaming download.",
            )
            stream_circuit = await self.pool.acquire()
            if not stream_circuit:
                raise SchedulerError("No healthy circuit available for streaming fallback.")
            try:
                written = await self.downloader.download_streaming_fallback(url, stream_circuit, target_file)
                return written
            finally:
                await self.pool.release(stream_circuit.circuit_id)

        # Initialize or resume chunk state
        loaded = self.state_store.load_job() if resume else None
        if loaded and loaded[0] == total_size and target_file.exists():
            _, chunks = loaded
        else:
            chunks = self.build_initial_chunks(total_size, self.config.chunk_size)
            self.downloader.preallocate_file(target_file, total_size)
            self.state_store.initialize_job(url, total_size, chunks)

        self._all_chunks = {c.chunk_id: c for c in chunks}
        self._next_chunk_id = (max(self._all_chunks.keys()) + 1) if self._all_chunks else 0
        self._queue = deque(c for c in chunks if not c.completed)

        already_done_bytes = sum(c.length for c in chunks if c.completed)
        self.metrics.set_target_size(total_size, initial_completed=already_done_bytes)

        if not self._queue:
            return total_size

        # Enforce global concurrency cap = min(healthy_circuits, per_host_concurrency)
        healthy_cap = max(1, len(self.pool.healthy_circuits()))
        concurrency = (
            min(healthy_cap, self.config.per_host_concurrency)
            if self.config.per_host_concurrency > 0
            else healthy_cap
        )

        workers = [
            asyncio.create_task(self._worker_loop(url, target_file))
            for _ in range(concurrency)
        ]
        summary_task = asyncio.create_task(self._summary_ticker())

        try:
            await asyncio.gather(*workers)
        finally:
            summary_task.cancel()
            try:
                await summary_task
            except asyncio.CancelledError:
                pass

        if self._paused_error:
            raise SchedulerError(f"Download aborted due to fail-closed condition: {self._paused_error}")

        if self._permanent_failures:
            raise SchedulerError(
                f"{len(self._permanent_failures)} chunk(s) permanently failed after max retries."
            )

        return total_size

    async def _summary_ticker(self) -> None:
        """Emit 1-second throughput ticks and 10-second summary lines."""
        ticks = 0
        while True:
            await asyncio.sleep(1.0)
            agg_bps = self.metrics.tick_sample()
            self.event_bus.emit(EventType.THROUGHPUT_SAMPLE, throughput_bps=agg_bps)
            ticks += 1
            if ticks % 10 == 0:
                snap = self.metrics.get_snapshot()
                self.event_bus.emit(
                    EventType.SUMMARY_TICK,
                    completed_bytes=snap["completed_bytes"],
                    total_bytes=snap["total_bytes"],
                    throughput_bps=snap["current_bps"],
                    healthy_count=self.pool.healthy_count(),
                )

    async def _maybe_adapt_chunk_downward(self, chunk: ChunkRecord, circuit: ManagedCircuit) -> ChunkRecord:
        """
        Adapt chunk size downward if the assigned circuit is slower than half the pool average
        and the chunk is at least 2x MIN_ADAPTIVE_CHUNK_SIZE.
        """
        if chunk.length < 2 * self.MIN_ADAPTIVE_CHUNK_SIZE:
            return chunk

        c_rate = self.metrics.get_circuit_throughput(circuit.circuit_id)
        agg_rate = self.metrics.get_aggregate_throughput()
        healthy_n = max(1, len(self.pool.healthy_circuits()))
        avg_per_circ = agg_rate / healthy_n

        if c_rate > 0 and avg_per_circ > 0 and c_rate < 0.5 * avg_per_circ:
            mid = chunk.start_byte + (chunk.length // 2) - 1
            second_half = ChunkRecord(
                chunk_id=self._next_chunk_id,
                start_byte=mid + 1,
                end_byte=chunk.end_byte,
                completed=False,
                retries=0,
            )
            self._next_chunk_id += 1
            chunk.end_byte = mid
            self._all_chunks[second_half.chunk_id] = second_half
            self._queue.appendleft(second_half)
            self.state_store.update_chunk_split(chunk, second_half)
            self.event_bus.emit(
                EventType.DEBUG_SCHEDULER,
                decision="ADAPT_CHUNK_SPLIT",
                detail=f"Split chunk {chunk.chunk_id} into {chunk.chunk_id} and {second_half.chunk_id} for slow circuit {circuit.circuit_id}",
            )
        return chunk

    async def _worker_loop(self, url: str, target_file: Path) -> None:
        """Work-stealing worker pulling unassigned chunks and executing ranged requests."""
        while not self._paused_error:
            async with self._lock:
                if not self._queue:
                    return
                chunk = self._queue.popleft()

            circuit = await self.pool.acquire()
            if not circuit:
                async with self._lock:
                    self._queue.appendleft(chunk)
                await asyncio.sleep(0.25)
                continue

            async with self._lock:
                chunk = await self._maybe_adapt_chunk_downward(chunk, circuit)

            self.event_bus.emit(
                EventType.CHUNK_ASSIGNED,
                chunk_id=chunk.chunk_id,
                start_byte=chunk.start_byte,
                end_byte=chunk.end_byte,
                circuit_id=circuit.circuit_id,
                retries=chunk.retries,
            )

            try:
                t_start = time.monotonic()
                rate_bps = await self.downloader.download_chunk(url, chunk, circuit, target_file)
                elapsed = time.monotonic() - t_start

                chunk.completed = True
                self.state_store.mark_chunk_done(chunk.chunk_id, chunk.retries)

                self.event_bus.emit(
                    EventType.CHUNK_DONE,
                    chunk_id=chunk.chunk_id,
                    start_byte=chunk.start_byte,
                    end_byte=chunk.end_byte,
                    bytes=chunk.length,
                    circuit_id=circuit.circuit_id,
                    tor_circuit_id=self.pool.controller.get_verified_tor_circuit(circuit.circuit_id),
                    throughput_bps=rate_bps,
                    retries=chunk.retries,
                )
                self.event_bus.emit(
                    EventType.DEBUG_TIMING,
                    phase=f"chunk_{chunk.chunk_id}",
                    duration_s=elapsed,
                )
                async with self._lock:
                    done_count = sum(1 for c in self._all_chunks.values() if c.completed)
                    total_count = len(self._all_chunks)
                self.event_bus.emit(
                    EventType.STATE_SAVED,
                    completed_chunks=done_count,
                    total_chunks=total_count,
                )
            except DownloadError as exc:
                if exc.disk_full:
                    async with self._lock:
                        self._queue.appendleft(chunk)
                    self.trigger_emergency_pause("DISK_FULL")
                    return

                chunk.retries += 1
                if chunk.retries > self.config.max_retries_per_chunk:
                    async with self._lock:
                        self._permanent_failures.append(chunk)
                    self.event_bus.emit(
                        EventType.CHUNK_FAILED,
                        chunk_id=chunk.chunk_id,
                        start_byte=chunk.start_byte,
                        end_byte=chunk.end_byte,
                        reason=exc.reason,
                        retries=chunk.retries,
                    )
                else:
                    # Exponential backoff with jitter for HTTP 429 / 503
                    if exc.status_code in (429, 503):
                        backoff_s = min(30.0, (2 ** (chunk.retries - 1)) * 0.5 + random.uniform(0.05, 0.25))
                        self.event_bus.emit(
                            EventType.CHUNK_RETRY,
                            chunk_id=chunk.chunk_id,
                            start_byte=chunk.start_byte,
                            end_byte=chunk.end_byte,
                            circuit_id=circuit.circuit_id,
                            reason=exc.reason,
                            retries=chunk.retries,
                            backoff_s=backoff_s,
                        )
                        async with self._lock:
                            self._queue.append(chunk)
                        await asyncio.sleep(backoff_s)
                    else:
                        # Mid-transfer disconnect or timeout: return chunk to queue and replace circuit
                        self.event_bus.emit(
                            EventType.CHUNK_RETRY,
                            chunk_id=chunk.chunk_id,
                            start_byte=chunk.start_byte,
                            end_byte=chunk.end_byte,
                            circuit_id=circuit.circuit_id,
                            reason=exc.reason,
                            retries=chunk.retries,
                            backoff_s=0.0,
                        )
                        async with self._lock:
                            self._queue.appendleft(chunk)
                        asyncio.create_task(
                            self.pool.replace(circuit.circuit_id, reason=exc.reason, reassigned_chunks=1)
                        )
            finally:
                await self.pool.release(circuit.circuit_id)
