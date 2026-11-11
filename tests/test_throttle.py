"""Tests for circuit-build throttling, NEWNYM limiting, and config bounds."""

import asyncio
import time
from unittest.mock import MagicMock

import pytest

from torpool.config import ConfigError, TorPoolConfig
from torpool.events import Event, EventBus, EventType
from torpool.throttle import CircuitBuildThrottle
from torpool.tor_controller import TorController


class FakeClock:
    """A manually advanced monotonic clock."""

    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


@pytest.mark.asyncio
async def test_throttle_enforces_delay_and_emits_event() -> None:
    bus = EventBus()
    events: list[Event] = []
    bus.subscribe(events.append)
    clock = FakeClock(100.0)
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock.value += seconds

    throttle = CircuitBuildThrottle(1.0, bus, clock=clock, sleep=fake_sleep)
    assert await throttle.wait("first") == 0.0
    assert await throttle.wait("second") == pytest.approx(1.0)
    assert sleeps == [pytest.approx(1.0)]
    bus.flush_sync()
    assert any(e.event_type == EventType.CIRCUIT_CREATION_THROTTLED for e in events)


@pytest.mark.asyncio
async def test_throttle_serializes_concurrent_callers() -> None:
    bus = EventBus()
    clock = FakeClock()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock.value += seconds

    throttle = CircuitBuildThrottle(2.0, bus, clock=clock, sleep=fake_sleep)

    async def worker() -> None:
        await throttle.wait("build")

    await asyncio.gather(*(worker() for _ in range(3)))
    assert len(sleeps) == 2
    assert all(seconds == pytest.approx(2.0) for seconds in sleeps)


def test_config_circuit_bounds() -> None:
    TorPoolConfig(circuits=100).validate()
    with pytest.raises(ConfigError):
        TorPoolConfig(circuits=101).validate()
    with pytest.raises(ConfigError):
        TorPoolConfig(circuit_creation_delay=0.0).validate()
    with pytest.raises(ConfigError):
        TorPoolConfig(circuit_creation_delay=0.49).validate()


def test_config_rejects_dht_and_lsd() -> None:
    with pytest.raises(ConfigError, match="DHT"):
        TorPoolConfig(dht_enabled=True).validate()
    with pytest.raises(ConfigError, match="local peer discovery"):
        TorPoolConfig(lsd_enabled=True).validate()
    with pytest.raises(ConfigError, match="loopback interface"):
        TorPoolConfig(torrent_bind_interface="eth0").validate()


def test_newnym_rate_limit_is_enforced() -> None:
    bus = EventBus()
    events: list[Event] = []
    bus.subscribe(events.append)
    sleeps: list[float] = []
    clock = FakeClock(100.0)

    ctrl = TorController(
        TorPoolConfig(),
        bus,
        newnym_interval=10.0,
        clock=clock,
        sleep=lambda seconds: sleeps.append(seconds),
    )
    ctrl._controller = MagicMock()
    ctrl._last_newnym_at = 95.0
    ctrl.new_identity()
    assert sleeps == [pytest.approx(5.0)]
    assert ctrl._controller.signal.called
    bus.flush_sync()
    waits = [e for e in events if e.event_type == EventType.CIRCUIT_CREATION_THROTTLED]
    assert waits and waits[0].data["reason"] == "NEWNYM"


def test_config_forbids_torrent_max_uploads(tmp_path) -> None:
    from torpool.config import ConfigLoader

    config_file = tmp_path / "config.toml"
    config_file.write_text("[torrent]\ntorrent_max_uploads = 4\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="uploading and seeding"):
        ConfigLoader.load(config_path=config_file)


def test_circuit_creation_delay_is_not_optional() -> None:
    cfg = TorPoolConfig(circuit_creation_delay=0.5)
    cfg.validate()
    assert cfg.circuit_creation_delay == 0.5
    assert time.monotonic() > 0
