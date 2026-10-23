"""EventBus with bounded non-blocking buffer, priority debug dropping, and subscribers."""

import asyncio
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable, Optional

from torpool.sanitizer import sanitize_log_text


class EventType(str, Enum):
    """Typed operational events emitted across TorPool."""

    CIRCUIT_BUILD_START = "CIRCUIT_BUILD_START"
    CIRCUIT_BUILT = "CIRCUIT_BUILT"
    CIRCUIT_FAILED = "CIRCUIT_FAILED"
    CIRCUIT_REPLACED = "CIRCUIT_REPLACED"
    CIRCUIT_STATE_CHANGE = "CIRCUIT_STATE_CHANGE"
    CHUNK_ASSIGNED = "CHUNK_ASSIGNED"
    CHUNK_DONE = "CHUNK_DONE"
    CHUNK_RETRY = "CHUNK_RETRY"
    CHUNK_FAILED = "CHUNK_FAILED"
    HEALTH_PROBE = "HEALTH_PROBE"
    THROUGHPUT_SAMPLE = "THROUGHPUT_SAMPLE"
    STATE_SAVED = "STATE_SAVED"
    NEW_IDENTITY = "NEW_IDENTITY"
    FALLBACK_STREAMING = "FALLBACK_STREAMING"
    SECURITY_ALERT = "SECURITY_ALERT"
    SUMMARY_TICK = "SUMMARY_TICK"
    DEBUG_TIMING = "DEBUG_TIMING"
    DEBUG_SCHEDULER = "DEBUG_SCHEDULER"
    DEBUG_STEM = "DEBUG_STEM"
    JOB_COMPLETE = "JOB_COMPLETE"
    ERROR = "ERROR"


DEBUG_EVENT_TYPES = {
    EventType.DEBUG_TIMING,
    EventType.DEBUG_SCHEDULER,
    EventType.DEBUG_STEM,
}


@dataclass
class Event:
    """Immutable operational event payload."""

    event_type: EventType
    timestamp: float = field(default_factory=time.time)
    data: dict[str, Any] = field(default_factory=dict)
    is_debug: bool = False

    def __post_init__(self) -> None:
        if self.event_type in DEBUG_EVENT_TYPES:
            self.is_debug = True


class EventBus:
    """
    Bounded, non-blocking event bus.
    If the buffer fills, the oldest debug event is dropped first and dropped_events_count increments.
    """

    def __init__(self, max_size: int = 1000) -> None:
        self.max_size = max_size
        self._buffer: deque[Event] = deque()
        self._lock = threading.Lock()
        self._subscribers: list[Callable[[Event], None]] = []
        self.dropped_events_count: int = 0
        self._running = False
        self._worker_task: Optional[asyncio.Task[None]] = None

    def subscribe(self, callback: Callable[[Event], None]) -> None:
        """Register a synchronous subscriber callback."""
        with self._lock:
            self._subscribers.append(callback)

    def emit(self, event_type: EventType, **data: Any) -> None:
        """
        Enqueue an event without blocking the caller.
        If full, drops the oldest debug event first; if no debug events exist, drops the oldest event.
        """
        ev = Event(event_type=event_type, data=data)
        with self._lock:
            if len(self._buffer) >= self.max_size:
                dropped = False
                for idx, existing in enumerate(self._buffer):
                    if existing.is_debug:
                        del self._buffer[idx]
                        dropped = True
                        break
                if not dropped:
                    self._buffer.popleft()
                self.dropped_events_count += 1
            self._buffer.append(ev)

    def flush_sync(self) -> None:
        """Synchronously dispatch all queued events to subscribers."""
        while True:
            with self._lock:
                if not self._buffer:
                    break
                ev = self._buffer.popleft()
                subs = list(self._subscribers)
            for sub in subs:
                try:
                    sub(ev)
                except Exception:
                    pass

    async def start(self) -> None:
        """Start background async consumer loop."""
        self._running = True
        self._worker_task = asyncio.create_task(self._consume_loop())

    async def stop(self) -> None:
        """Stop background loop and flush remaining events."""
        self._running = False
        if self._worker_task:
            await self._worker_task
        self.flush_sync()

    async def _consume_loop(self) -> None:
        while self._running:
            self.flush_sync()
            await asyncio.sleep(0.02)


class SanitizedLogWriter:
    """Subscriber that writes strictly sanitized operational events to a log file."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()

    def __call__(self, event: Event) -> None:
        d = event.data
        et = event.event_type

        # Log file records circuit IDs, timing, status codes, and byte counts only.
        msg = f"ts={event.timestamp:.3f} event={et.value}"
        for allowed_key in (
            "circuit_id", "tor_circuit_id", "old_circuit_id", "new_circuit_id",
            "attempt", "duration_s", "reason", "healthy_count", "reassigned_chunks",
            "recovery_s", "chunk_id", "start_byte", "end_byte", "bytes",
            "throughput_bps", "retries", "status_code", "latency_s",
            "backoff_s", "completed_bytes", "total_bytes",
        ):
            if allowed_key in d:
                val = d[allowed_key]
                if isinstance(val, float):
                    msg += f" {allowed_key}={val:.3f}"
                else:
                    msg += f" {allowed_key}={val}"

        clean_line = sanitize_log_text(msg) + "\n"
        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(clean_line)


class TerminalVerboseRenderer:
    """
    Formats and prints real-time events to stderr according to the configured verbosity level:
    -1 (--quiet): errors and final result only
     0 (default): circuit state changes, replacements, and 10s summary lines
     1 (-v): every circuit build step, chunk assignment/completion, health probe, state save
     2 (-vv): phase timings, retry backoff values, scheduler decisions, stem lifecycle events
    """

    def __init__(self, verbosity: int = 0, stream: Any = None) -> None:
        self.verbosity = verbosity
        self.stream = stream or sys.stderr

    def format_event(self, event: Event) -> Optional[str]:
        """Return formatted line for stderr if permitted by current verbosity, else None."""
        et = event.event_type
        d = event.data

        if et in (EventType.ERROR, EventType.SECURITY_ALERT):
            return f"[ERROR] {d.get('message', 'Unknown error')} (reason={d.get('reason', 'N/A')})"

        if et == EventType.JOB_COMPLETE:
            return (
                f"[COMPLETE] status={d.get('status')} bytes={d.get('bytes', 0)} "
                f"sha256={d.get('sha256', 'N/A')} duration={d.get('duration_s', 0.0):.2f}s"
            )

        if self.verbosity < 0:
            return None

        # Level 0 (Default) events
        if et == EventType.CIRCUIT_STATE_CHANGE:
            return (
                f"[CIRCUIT] id={d.get('circuit_id')} state={d.get('old_state')}->{d.get('new_state')} "
                f"reason={d.get('reason', 'NONE')} healthy={d.get('healthy_count', 0)}"
            )
        if et == EventType.CIRCUIT_REPLACED:
            return (
                f"[REPLACE] old_id={d.get('old_circuit_id')} new_id={d.get('new_circuit_id')} "
                f"reason={d.get('reason')} reassigned_chunks={d.get('reassigned_chunks', 0)} "
                f"recovery_time={d.get('recovery_s', 0.0):.2f}s"
            )
        if et == EventType.SUMMARY_TICK:
            return (
                f"[SUMMARY] completed={d.get('completed_bytes', 0)}/{d.get('total_bytes', 0)} B "
                f"rate={d.get('throughput_bps', 0.0) / 1024:.1f} KiB/s "
                f"healthy_circuits={d.get('healthy_count', 0)}"
            )
        if et == EventType.FALLBACK_STREAMING:
            return f"[WARN] {d.get('message')}"

        if self.verbosity < 1:
            return None

        # Level 1 (-v) events
        if et == EventType.CIRCUIT_BUILD_START:
            return f"[BUILD_START] attempt={d.get('attempt')} path={d.get('path_str')}"
        if et == EventType.CIRCUIT_BUILT:
            return (
                f"[ACQUIRED] id={d.get('circuit_id')} attempt={d.get('attempt')} "
                f"path={d.get('path_str')} duration={d.get('duration_s', 0.0):.2f}s "
                f"reason=NONE healthy={d.get('healthy_count', 0)}"
            )
        if et == EventType.CIRCUIT_FAILED:
            return (
                f"[BUILD_FAIL] id={d.get('circuit_id', 'NONE')} attempt={d.get('attempt')} "
                f"path={d.get('path_str', 'N/A')} duration={d.get('duration_s', 0.0):.2f}s "
                f"reason={d.get('reason', 'UNKNOWN')} healthy={d.get('healthy_count', 0)}"
            )
        if et == EventType.CHUNK_ASSIGNED:
            return (
                f"[CHUNK_ASSIGN] chunk={d.get('chunk_id')} "
                f"range={d.get('start_byte')}-{d.get('end_byte')} "
                f"circuit={d.get('circuit_id')} retries={d.get('retries', 0)}"
            )
        if et == EventType.CHUNK_DONE:
            tor_cid = d.get("tor_circuit_id") or d.get("circuit_id")
            return (
                f"[CHUNK_DONE] chunk={d.get('chunk_id')} "
                f"range={d.get('start_byte')}-{d.get('end_byte')} "
                f"circuit={d.get('circuit_id')} tor_circ={tor_cid} "
                f"rate={d.get('throughput_bps', 0.0) / 1024:.1f} KiB/s "
                f"retries={d.get('retries', 0)}"
            )
        if et == EventType.CHUNK_RETRY:
            return (
                f"[CHUNK_RETRY] chunk={d.get('chunk_id')} "
                f"range={d.get('start_byte')}-{d.get('end_byte')} "
                f"circuit={d.get('circuit_id')} reason={d.get('reason')} "
                f"retries={d.get('retries', 0)} backoff={d.get('backoff_s', 0.0):.2f}s"
            )
        if et == EventType.CHUNK_FAILED:
            return (
                f"[CHUNK_FAIL] chunk={d.get('chunk_id')} "
                f"range={d.get('start_byte')}-{d.get('end_byte')} "
                f"reason={d.get('reason')} retries={d.get('retries', 0)}"
            )
        if et == EventType.HEALTH_PROBE:
            return (
                f"[HEALTH] circuit={d.get('circuit_id')} status={d.get('status')} "
                f"latency={d.get('latency_s', 0.0):.3f}s state={d.get('state')}"
            )
        if et == EventType.STATE_SAVED:
            return f"[STATE] saved completed_chunks={d.get('completed_chunks')}/{d.get('total_chunks')}"
        if et == EventType.NEW_IDENTITY:
            return "[IDENTITY] Issued SIGNAL NEWNYM and rebuilt circuit pool"

        if self.verbosity < 2:
            return None

        # Level 2 (-vv) debug events
        if et == EventType.DEBUG_TIMING:
            return f"[DEBUG:TIMING] phase={d.get('phase')} elapsed={d.get('duration_s', 0.0):.4f}s"
        if et == EventType.DEBUG_SCHEDULER:
            return f"[DEBUG:SCHED] decision={d.get('decision')} detail={d.get('detail')}"
        if et == EventType.DEBUG_STEM:
            return (
                f"[DEBUG:STEM] circuit={d.get('circuit_id')} "
                f"status={d.get('status')} reason={d.get('reason')}"
            )

        return None

    def __call__(self, event: Event) -> None:
        line = self.format_event(event)
        if line is not None:
            print(line, file=self.stream, flush=True)
