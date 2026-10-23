"""Offline unit tests for TorPool."""

import asyncio
import json
import hashlib
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from torpool import __version__
from torpool.cli import parse_size
from torpool.circuit_pool import CircuitPool, CircuitState, ManagedCircuit
from torpool.config import (
    ConfigError,
    ConfigLoader,
    TOR_BROWSER_USER_AGENT,
    TorPoolConfig,
)
from torpool.dashboard import Dashboard
from torpool.downloader import RangeDownloader
from torpool.events import (
    Event,
    EventBus,
    EventType,
    SanitizedLogWriter,
    TerminalVerboseRenderer,
)
from torpool.metrics import BandwidthLimiter, MetricsWindow
from torpool.sanitizer import (
    clear_proxy_env,
    sanitize_log_text,
    sanitize_url_for_manifest,
)
from torpool.scheduler import ChunkScheduler
from torpool.state_store import ChunkRecord, StateStore
from torpool.tor_controller import CircuitSocksListener, RelayInfo, TorController, TorError
from torpool.verifier import IntegrityVerifier


def test_version() -> None:
    assert __version__ == "0.1.0"


# --------------------------------------------------------------------------- config


def test_config_defaults_are_valid() -> None:
    cfg = TorPoolConfig()
    cfg.validate()
    assert cfg.circuits == 4
    assert cfg.chunk_size == 10 * 1024 * 1024
    assert cfg.output_dir == Path("./quarantine")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"circuits": 0},
        {"circuits": 17},
        {"chunk_size": 1024},
        {"health_interval": 0.5},
        {"circuit_timeout": 0.5},
        {"graph_refresh": 0.1},
        {"graph_window": 5},
        {"max_bandwidth": -1},
        {"per_host_concurrency": -1},
    ],
)
def test_config_validation_rejects_out_of_range(kwargs: dict) -> None:
    cfg = TorPoolConfig(**kwargs)
    with pytest.raises(ConfigError):
        cfg.validate()


def test_config_loads_sections_and_paths(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[tor]
circuits = 3
control_port = 9151

[download]
chunk_size = 1048576
output_dir = "/tmp/torpool-out"
encrypt = true

[ui]
verbosity = 1
graph = false
""",
        encoding="utf-8",
    )
    cfg = ConfigLoader.load(config_path=config_file)
    assert cfg.circuits == 3
    assert cfg.control_port == 9151
    assert cfg.chunk_size == 1048576
    assert cfg.output_dir == Path("/tmp/torpool-out")
    assert cfg.encrypt is True
    assert cfg.verbosity == 1


def test_config_rejects_forbidden_password_keys(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text('[tor]\npassword = "hunter2"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="Forbidden key"):
        ConfigLoader.load(config_path=config_file)


def test_control_password_only_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TOR_CONTROL_PASSWORD", raising=False)
    with pytest.raises(ConfigError, match="TOR_CONTROL_PASSWORD"):
        TorPoolConfig.get_control_password()

    monkeypatch.setenv("TOR_CONTROL_PASSWORD", "s3cret")
    assert TorPoolConfig.get_control_password() == "s3cret"


def test_save_authorization_sets_flag_and_permissions(tmp_path: Path) -> None:
    config_file = tmp_path / "nested" / "config.toml"
    ConfigLoader.save_authorization(config_file)
    assert "authorized_confirmed = true" in config_file.read_text(encoding="utf-8")
    assert (config_file.stat().st_mode & 0o777) == 0o600

    cfg = ConfigLoader.load(config_path=config_file)
    assert cfg.authorized_confirmed is True


# ------------------------------------------------------------------------ sanitizer


def test_sanitize_url_strips_credentials_and_tokens() -> None:
    cleaned = sanitize_url_for_manifest(
        "https://user:pass@example.onion/path?token=abc&file=1#frag"
    )
    assert "user" not in cleaned
    assert "pass" not in cleaned
    assert "abc" not in cleaned
    assert "token=%5BREDACTED%5D" in cleaned or "token=[REDACTED]" in cleaned
    assert "file=1" in cleaned
    assert "#frag" not in cleaned


def test_sanitize_log_text_redacts_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOR_CONTROL_PASSWORD", "super-secret-pw")
    monkeypatch.setenv("USER", "jaskeerat")
    raw = (
        "pw=super-secret-pw url=https://abc.onion/x?token=1 "
        "fp=$ABCDEF0123456789ABCDEF0123456789ABCDEF01 "
        "ip=192.168.1.10 path=/home/jaskeerat/file token=zzz"
    )
    clean = sanitize_log_text(raw)
    assert "super-secret-pw" not in clean
    assert "https://abc.onion" not in clean
    assert "ABCDEF0123456789" not in clean
    assert "192.168.1.10" not in clean
    assert "/jaskeerat/" not in clean
    assert "zzz" not in clean


def test_clear_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("all_proxy", "socks5://127.0.0.1:1080")
    clear_proxy_env()
    assert "HTTP_PROXY" not in os.environ
    assert "all_proxy" not in os.environ


# --------------------------------------------------------------------------- events


def test_event_bus_drops_oldest_debug_event_first() -> None:
    bus = EventBus(max_size=2)
    received: list[Event] = []
    bus.subscribe(received.append)

    bus.emit(EventType.DEBUG_TIMING, phase="a")
    bus.emit(EventType.CIRCUIT_BUILT, circuit_id="1")
    bus.emit(EventType.CIRCUIT_BUILT, circuit_id="2")
    bus.flush_sync()

    assert bus.dropped_events_count == 1
    assert [e.event_type for e in received] == [
        EventType.CIRCUIT_BUILT,
        EventType.CIRCUIT_BUILT,
    ]


def test_event_bus_drops_oldest_when_no_debug() -> None:
    bus = EventBus(max_size=1)
    received: list[Event] = []
    bus.subscribe(received.append)
    bus.emit(EventType.CIRCUIT_BUILT, circuit_id="1")
    bus.emit(EventType.CIRCUIT_FAILED, circuit_id="NONE")
    bus.flush_sync()
    assert received[0].data["circuit_id"] == "NONE"
    assert bus.dropped_events_count == 1


def test_sanity_log_writer_redacts_and_whitelists(tmp_path: Path) -> None:
    log_path = tmp_path / "ops.log"
    writer = SanitizedLogWriter(log_path)
    writer(
        Event(
            event_type=EventType.CHUNK_RETRY,
            data={
                "chunk_id": 3,
                "reason": "https://secret.onion/a?token=leak",
                "circuit_id": "5",
                "secret_field": "must-not-appear",
            },
        )
    )
    text = log_path.read_text(encoding="utf-8")
    assert "chunk_id=3" in text
    assert "secret.onion" not in text
    assert "leak" not in text
    assert "must-not-appear" not in text


def test_terminal_renderer_verbosity_levels() -> None:
    quiet = TerminalVerboseRenderer(verbosity=-1)
    default = TerminalVerboseRenderer(verbosity=0)
    verbose = TerminalVerboseRenderer(verbosity=1)
    debug = TerminalVerboseRenderer(verbosity=2)

    state_event = Event(
        event_type=EventType.CIRCUIT_STATE_CHANGE,
        data={
            "circuit_id": "7",
            "old_state": "warming",
            "new_state": "healthy",
            "reason": "PROBE_OK",
            "healthy_count": 2,
        },
    )
    assert quiet.format_event(state_event) is None
    assert "CIRCUIT" in default.format_event(state_event)
    assert "CIRCUIT" in verbose.format_event(state_event)

    build_event = Event(
        event_type=EventType.CIRCUIT_BUILD_START,
        data={"attempt": 1, "path_str": "A -> B -> C"},
    )
    assert default.format_event(build_event) is None
    assert "BUILD_START" in verbose.format_event(build_event)

    timing_event = Event(
        event_type=EventType.DEBUG_TIMING,
        data={"phase": "chunk_1", "duration_s": 1.5},
    )
    assert verbose.format_event(timing_event) is None
    assert "DEBUG:TIMING" in debug.format_event(timing_event)

    error_event = Event(event_type=EventType.ERROR, data={"message": "boom"})
    assert "boom" in quiet.format_event(error_event)


# -------------------------------------------------------------------------- metrics


def test_metrics_rolling_rates_and_snapshot() -> None:
    metrics = MetricsWindow(graph_window_seconds=10, rolling_avg_seconds=2)
    metrics.set_target_size(1000, initial_completed=100)
    metrics.record_bytes("c1", 200, now=100.0)

    assert metrics.get_circuit_throughput("c1", now=100.0) == pytest.approx(100.0)
    assert metrics.get_aggregate_throughput(now=100.0) == pytest.approx(100.0)
    assert metrics.tick_sample(now=100.0) == pytest.approx(100.0)

    snap = metrics.get_snapshot()
    assert snap["completed_bytes"] == 300
    assert snap["total_bytes"] == 1000
    assert snap["peak_bps"] >= 0.0
    assert "c1" in snap["circuit_histories"]


@pytest.mark.asyncio
async def test_bandwidth_limiter_unlimited_is_noop() -> None:
    limiter = BandwidthLimiter(max_bandwidth_bps=0)
    started = time.monotonic()
    await limiter.consume(10 * 1024 * 1024)
    assert time.monotonic() - started < 0.5


@pytest.mark.asyncio
async def test_bandwidth_limiter_allows_within_bucket() -> None:
    limiter = BandwidthLimiter(max_bandwidth_bps=1000)
    started = time.monotonic()
    await limiter.consume(500)
    assert time.monotonic() - started < 0.5


# ---------------------------------------------------------------------- state store


def test_state_store_roundtrip_and_resume(tmp_path: Path) -> None:
    state_path = StateStore.state_path_for_url(tmp_path, "http://example.onion/f")
    store = StateStore(state_path)

    chunks = [
        ChunkRecord(0, 0, 9),
        ChunkRecord(1, 10, 19),
    ]
    store.initialize_job("http://example.onion/f?token=x", 20, chunks)
    store.mark_chunk_done(0, retries=1)

    loaded = store.load_job()
    assert loaded is not None
    total, records = loaded
    assert total == 20
    assert records[0].completed is True
    assert records[0].retries == 1
    assert records[1].completed is False

    split = ChunkRecord(2, 15, 19)
    updated = records[1]
    updated.end_byte = 14
    store.update_chunk_split(updated, split)
    _, after_split = store.load_job()
    assert [c.chunk_id for c in after_split] == [0, 1, 2]
    assert after_split[2].start_byte == 15

    store.record_circuit_meta("circ-1", "healthy")
    assert (state_path.stat().st_mode & 0o777) == 0o600

    store.remove()
    assert not state_path.exists()


def test_state_path_is_deterministic(tmp_path: Path) -> None:
    a = StateStore.state_path_for_url(tmp_path, "http://example.onion/a")
    b = StateStore.state_path_for_url(tmp_path, "http://example.onion/a")
    c = StateStore.state_path_for_url(tmp_path, "http://example.onion/b")
    assert a == b
    assert a != c


# ------------------------------------------------------------------ scheduler/chunks


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("512K", 512 * 1024),
        ("10M", 10 * 1024**2),
        ("2G", 2 * 1024**3),
        ("10485760", 10485760),
        ("1 KB", 1024),
    ],
)
def test_parse_size(raw: str, expected: int) -> None:
    assert parse_size(raw) == expected


def test_build_initial_chunks_covers_file_exactly() -> None:
    chunks = ChunkScheduler.build_initial_chunks(25, 10)
    assert [(c.start_byte, c.end_byte) for c in chunks] == [
        (0, 9),
        (10, 19),
        (20, 24),
    ]
    assert sum(c.length for c in chunks) == 25
    assert [c.chunk_id for c in chunks] == [0, 1, 2]


def test_build_initial_chunks_empty_for_zero_size() -> None:
    assert ChunkScheduler.build_initial_chunks(0, 10) == []


def test_url_opsec_rejects_unsafe_inputs() -> None:
    TorController.validate_url_opsec("https://example.onion/file")
    TorController.validate_url_opsec("http://example.com/file")

    for bad in ("file:///etc/passwd", "ftp://example.com/x", "http://localhost/x", "http://127.0.0.1/x", "http://[::1]/x", "http:///nohost"):
        with pytest.raises(TorError):
            TorController.validate_url_opsec(bad)


# ------------------------------------------------------------------------- downloader


def test_preallocate_file_creates_sized_private_file(tmp_path: Path) -> None:
    target = tmp_path / "quarantine" / "artifact.bin"
    RangeDownloader.preallocate_file(target, 4096)
    assert target.exists()
    assert target.stat().st_size == 4096
    assert (target.stat().st_mode & 0o777) == 0o600
    assert (target.parent.stat().st_mode & 0o777) == 0o700


def test_shred_file_removes_file(tmp_path: Path) -> None:
    target = tmp_path / "tmp" / "partial.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x" * 1024)
    RangeDownloader.shred_file(target)
    assert not target.exists()


# --------------------------------------------------------------------------- verifier


def test_compute_sha256(tmp_path: Path) -> None:
    target = tmp_path / "file.bin"
    target.write_bytes(b"torpool")
    digest = IntegrityVerifier.compute_sha256(target)
    assert len(digest) == 64
    assert digest == hashlib.sha256(b"torpool").hexdigest()


def test_verify_and_record_writes_sanitized_manifest(tmp_path: Path) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"payload")
    digest = IntegrityVerifier.compute_sha256(target)
    manifest = tmp_path / "manifest.json"

    passed, actual, final_path = IntegrityVerifier.verify_and_record(
        file_path=target,
        url="https://example.onion/artifact.bin?token=secret",
        expected_sha256=digest,
        manifest_path=manifest,
    )
    assert passed is True
    assert actual == digest
    assert final_path == target

    entries = json.loads(manifest.read_text(encoding="utf-8"))
    assert entries[0]["status"] == "VERIFIED"
    assert "secret" not in entries[0]["source_url"]
    assert entries[0]["sha256"] == digest


def test_verify_failure_renames_artifact(tmp_path: Path) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"payload")
    passed, _, final_path = IntegrityVerifier.verify_and_record(
        file_path=target,
        url="https://example.onion/artifact.bin",
        expected_sha256="0" * 64,
        manifest_path=tmp_path / "manifest.json",
    )
    assert passed is False
    assert ".failed." in final_path.name
    assert not target.exists()
    assert final_path.exists()


def test_encrypt_file_aes_gcm_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "secret.bin"
    payload = b"highly sensitive bytes" * 100
    target.write_bytes(payload)

    enc_path = IntegrityVerifier.encrypt_file_aes_gcm(target, "correct horse")
    assert not target.exists()
    assert enc_path.suffix == ".enc"
    assert (enc_path.stat().st_mode & 0o777) == 0o600

    blob = enc_path.read_bytes()
    salt, nonce, ciphertext = blob[:16], blob[16:28], blob[28:]
    key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(b"correct horse")
    assert AESGCM(key).decrypt(nonce, ciphertext, None) == payload


# -------------------------------------------------------------------------- dashboard


def test_dashboard_sparkline_dimensions() -> None:
    cfg = TorPoolConfig()
    metrics = MetricsWindow(graph_window_seconds=10)
    dash = Dashboard(cfg, metrics, force_ascii=True)

    assert len(dash.render_sparkline([], 10)) == 10
    line = dash.render_sparkline([1.0, 2.0, 3.0], 8)
    assert len(line) == 8
    assert set(line) <= set(" ._,-=+*#")


def test_dashboard_chart_and_compact_frame() -> None:
    cfg = TorPoolConfig()
    metrics = MetricsWindow(graph_window_seconds=10)
    metrics.set_target_size(1000, initial_completed=250)
    metrics.record_bytes("c1", 500)
    metrics.tick_sample()
    dash = Dashboard(cfg, metrics)

    chart = dash.render_aggregate_chart([0.0, 100.0, 500.0], width=20, height=4)
    assert len(chart.splitlines()) == 4

    compact = dash.render_frame(width=40, height=10)
    assert compact.title == "TorPool"

    full = dash.render_frame(width=100, height=30)
    assert full.title == "TorPool Live Bandwidth Monitor"


# ------------------------------------------------------------------------ rendering

def test_tor_browser_user_agent_is_generic() -> None:
    assert "Mozilla/5.0" in TOR_BROWSER_USER_AGENT
    assert "Firefox/" in TOR_BROWSER_USER_AGENT


# ------------------------------------------------- per-circuit SOCKS listener v2


def test_password_auth_accepts_stem_title_case() -> None:
    assert TorController._password_auth_supported(["Password"]) is True
    assert TorController._password_auth_supported(["COOKIE", "Password"]) is True
    assert TorController._password_auth_supported([]) is True
    assert TorController._password_auth_supported(["COOKIE"]) is False


def test_stream_resolution_uses_source_port(config: TorPoolConfig) -> None:
    ctrl = TorController(config, EventBus())
    with ctrl._lock:
        ctrl._circuit_to_socks_user["slot-A"] = "tp_A"
    ctrl.register_source_port(41000, "slot-A", "tp_A")

    event = SimpleNamespace(id="7", source_addr="127.0.0.1:41000")
    assert ctrl._resolve_slot_for_stream(event) == ("slot-A", "tp_A")

    # Cached by stream ID for subsequent events that omit SOURCE_ADDR.
    assert ctrl._resolve_slot_for_stream(SimpleNamespace(id="7", source_addr=None)) == (
        "slot-A",
        "tp_A",
    )

    ctrl.unregister_source_port(41000)
    assert ctrl._resolve_slot_for_stream(
        SimpleNamespace(id="8", source_addr="127.0.0.1:41000")
    ) == (None, None)


def test_stream_resolution_never_falls_back_to_first_circuit(config: TorPoolConfig) -> None:
    ctrl = TorController(config, EventBus())
    with ctrl._lock:
        ctrl._socks_cred_to_circuit["tp_other"] = "slot-other"

    # Unknown stream with no source-port or username mapping must not be guessed.
    assert ctrl._resolve_slot_for_stream(SimpleNamespace(id="9", source_addr=None)) == (
        None,
        None,
    )


def test_stream_resolution_uses_socks_username(config: TorPoolConfig) -> None:
    ctrl = TorController(config, EventBus())
    with ctrl._lock:
        ctrl._socks_cred_to_circuit["tp_B"] = "slot-B"

    event = SimpleNamespace(id="10", source_addr=None, socks_username="tp_B")
    assert ctrl._resolve_slot_for_stream(event) == ("slot-B", "tp_B")


@pytest.mark.asyncio
async def test_circuit_socks_listener_maps_and_clears_source_port(
    config: TorPoolConfig,
) -> None:
    ctrl = TorController(config, EventBus())
    peer_ports: list[int] = []
    accepted = asyncio.Event()

    async def fake_tor(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername")
        peer_ports.append(int(peername[1]))
        accepted.set()
        try:
            data = await reader.read(100)
            if data:
                writer.write(b"tor:" + data)
                await writer.drain()
        finally:
            writer.close()

    tor_server = await asyncio.start_server(fake_tor, "127.0.0.1", 0)
    tor_port = int(tor_server.sockets[0].getsockname()[1])
    listener = CircuitSocksListener("slot-1", "tp_1", "127.0.0.1", tor_port, ctrl)
    local_port = await listener.start()

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
        writer.write(b"hello")
        await writer.drain()
        await asyncio.wait_for(accepted.wait(), timeout=2.0)

        for _ in range(40):
            if peer_ports and peer_ports[0] in ctrl._source_port_to_circuit:
                break
            await asyncio.sleep(0.05)
        assert ctrl._source_port_to_circuit[peer_ports[0]] == "slot-1"
        assert ctrl._source_port_to_socks_user[peer_ports[0]] == "tp_1"

        assert await asyncio.wait_for(reader.read(100), timeout=2.0) == b"tor:hello"

        writer.close()
        await writer.wait_closed()

        for _ in range(40):
            if peer_ports[0] not in ctrl._source_port_to_circuit:
                break
            await asyncio.sleep(0.05)
        assert peer_ports[0] not in ctrl._source_port_to_circuit
    finally:
        await listener.stop()
        tor_server.close()
        await tor_server.wait_closed()


@pytest.mark.asyncio
async def test_circuit_socks_listener_stop_with_active_connection(
    config: TorPoolConfig,
) -> None:
    """stop() must not deadlock on an in-flight connection (Python 3.12+ wait_closed)."""
    ctrl = TorController(config, EventBus())
    release = asyncio.Event()

    async def fake_tor(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await release.wait()
        finally:
            writer.close()

    tor_server = await asyncio.start_server(fake_tor, "127.0.0.1", 0)
    tor_port = int(tor_server.sockets[0].getsockname()[1])
    listener = CircuitSocksListener("slot-2", "tp_2", "127.0.0.1", tor_port, ctrl)
    local_port = await listener.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", local_port)

    try:
        for _ in range(40):
            if listener._active_writers:
                break
            await asyncio.sleep(0.05)
        assert listener._active_writers

        await asyncio.wait_for(listener.stop(), timeout=3.0)
        assert listener._server is None
        assert not listener._active_writers
        assert await asyncio.wait_for(reader.read(100), timeout=2.0) == b""
    finally:
        writer.close()
        release.set()
        tor_server.close()
        await tor_server.wait_closed()


@pytest.mark.asyncio
async def test_managed_circuit_kills_listener() -> None:
    stopped: list[bool] = []

    class FakeListener:
        async def stop(self) -> None:
            stopped.append(True)

    mc = ManagedCircuit(
        circuit_id="1",
        created_at=0.0,
        relay_path=[],
        socks_user="u",
        socks_pass="p",
        proxy_url="socks5h://u:p@127.0.0.1:1234",
        socks_listener=FakeListener(),  # type: ignore[arg-type]
        listener_port=1234,
    )
    await mc.kill_socks_listener()
    assert stopped == [True]
    assert mc.socks_listener is None


@pytest.mark.asyncio
async def test_circuit_pool_build_slot_starts_listener(config: TorPoolConfig) -> None:
    bus = EventBus()
    metrics = MetricsWindow()
    ctrl = TorController(config, bus, metrics=metrics)
    ctrl.build_circuit = lambda attempt=1: (  # type: ignore[method-assign]
        "99",
        [
            RelayInfo("A" * 40, "Guard"),
            RelayInfo("B" * 40, "Middle"),
            RelayInfo("C" * 40, "Exit"),
        ],
        0.5,
        "tp_99",
        "secret",
    )

    pool = CircuitPool(config, ctrl, bus, metrics)
    mc = await pool._build_slot()
    assert mc is not None
    assert mc.state == CircuitState.HEALTHY
    assert mc.listener_port > 0
    assert mc.proxy_url == f"socks5h://tp_99:secret@127.0.0.1:{mc.listener_port}"
    assert mc.socks_listener is not None

    await pool.close_all()
    assert mc.socks_listener is None
    assert pool.circuits == []


def test_metrics_records_control_port_bytes() -> None:
    metrics = MetricsWindow()
    metrics.record_control_port_bw("slot-A", 1000)
    metrics.record_control_port_bw("slot-A", 500)
    metrics.record_control_port_bw("slot-B", 42)
    assert metrics.get_control_port_bytes("slot-A") == 1500
    assert metrics.get_control_port_bytes("slot-B") == 42
    assert metrics.get_control_port_bytes("missing") == 0


def test_chunk_done_renders_verified_tor_circuit() -> None:
    renderer = TerminalVerboseRenderer(verbosity=1)
    event = Event(
        event_type=EventType.CHUNK_DONE,
        data={
            "chunk_id": 4,
            "start_byte": 0,
            "end_byte": 100,
            "circuit_id": "slot-1",
            "tor_circuit_id": "tor-77",
            "throughput_bps": 1024.0,
            "retries": 0,
        },
    )
    line = renderer.format_event(event)
    assert line is not None
    assert "circuit=slot-1" in line
    assert "tor_circ=tor-77" in line

