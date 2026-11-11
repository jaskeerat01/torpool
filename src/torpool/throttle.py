"""Circuit build rate limiting with injectable clock/sleep for deterministic tests."""

import asyncio
import time
from typing import Awaitable, Callable, Optional

from torpool.events import EventBus, EventType


class CircuitBuildThrottle:
    """
    Serialize circuit-build requests and enforce a minimum delay between them.

    Tor does not publish a hard minimum interval for EXTENDCIRCUIT. Flooding the
    control port and circuit-build queue is still harmful, so TorPool enforces a
    mandatory conservative delay. Every enforced wait emits
    CIRCUIT_CREATION_THROTTLED.
    """

    def __init__(
        self,
        delay: float,
        event_bus: EventBus,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if delay <= 0:
            raise ValueError("Circuit creation delay must be positive and non-disableable")
        self.delay = float(delay)
        self.event_bus = event_bus
        self._clock = clock
        self._sleep = sleep
        self._lock = asyncio.Lock()
        self._next_allowed_at: Optional[float] = None

    async def wait(self, reason: str = "CIRCUIT_BUILD") -> float:
        """
        Wait until the next circuit-build slot is available.

        Returns the number of seconds slept (0.0 when no wait was required).
        """
        async with self._lock:
            now = self._clock()
            wait_s = 0.0
            if self._next_allowed_at is not None:
                wait_s = max(0.0, self._next_allowed_at - now)
            if wait_s > 0.0:
                self.event_bus.emit(
                    EventType.CIRCUIT_CREATION_THROTTLED,
                    reason=reason,
                    wait_s=wait_s,
                    delay_s=self.delay,
                )
                await self._sleep(wait_s)
            self._next_allowed_at = self._clock() + self.delay
            return wait_s
