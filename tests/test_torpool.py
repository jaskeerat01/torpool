"""Offline unit tests for TorPool."""

import asyncio
import errno
import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from typer.testing import CliRunner

from torpool import __version__
from torpool.circuit_pool import CircuitPool, CircuitState, ManagedCircuit
from torpool.cli import app, parse_size
from torpool.config import (
    TOR_BROWSER_USER_AGENT,
    ConfigError,
    ConfigLoader,
    TorPoolConfig,
)
from torpool.dashboard import Dashboard
from torpool.downloader import DownloadError, RangeDownloader
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
from torpool.verifier import EncryptedFileSession, IntegrityVerifier, VerificationError


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
    assert "CIRCUIT" in (default.format_event(state_event) or "")
    assert "CIRCUIT" in (verbose.format_event(state_event) or "")

    build_event = Event(
        event_type=EventType.CIRCUIT_BUILD_START,
        data={"attempt": 1, "path_str": "A -> B -> C"},
    )
    assert default.format_event(build_event) is None
    assert "BUILD_START" in (verbose.format_event(build_event) or "")

    timing_event = Event(
        event_type=EventType.DEBUG_TIMING,
        data={"phase": "chunk_1", "duration_s": 1.5},
    )
    assert verbose.format_event(timing_event) is None
    assert "DEBUG:TIMING" in (debug.format_event(timing_event) or "")

    error_event = Event(event_type=EventType.ERROR, data={"message": "boom"})
    assert "boom" in (quiet.format_event(error_event) or "")


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
    loaded_after = store.load_job()
    assert loaded_after is not None
    _, after_split = loaded_after
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

    for bad in (
        "file:///etc/passwd",
        "ftp://example.com/x",
        "http://localhost/x",
        "http://127.0.0.1/x",
        "http://[::1]/x",
        "http:///nohost",
    ):
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


# -------------------------------------------------------------------------- encryption model & decrypt CLI


def test_encrypted_session_produces_no_plaintext_part(tmp_path: Path) -> None:
    enc_file = tmp_path / "payload.bin.enc"
    idx_file = tmp_path / "payload.bin.idx"
    passphrase = "correct_horse_battery_staple"

    part1 = b"Hello TorPool part 1 " * 20
    part2 = b"Hello TorPool part 2 " * 30
    total_size = len(part1) + len(part2)

    session = EncryptedFileSession(enc_file, idx_file, passphrase=passphrase, total_size=total_size)
    c1 = ChunkRecord(0, 0, len(part1) - 1)
    c2 = ChunkRecord(1, len(part1), total_size - 1)
    session.write_chunk(c1, part1)
    session.write_chunk(c2, part2)
    session.finalize()

    # Invariant: No plaintext or .part files on disk
    assert enc_file.exists()
    assert idx_file.exists()
    for f in tmp_path.iterdir():
        assert not f.name.endswith(".part")
        assert not f.name.endswith(".bin")

    # Decrypt to user-chosen path
    recovered_file = tmp_path / "decrypted_recovered.bin"
    _, recovered_sha = IntegrityVerifier.decrypt_file(
        enc_file, recovered_file, passphrase=passphrase, idx_path=idx_file
    )

    assert recovered_file.exists()
    assert (recovered_file.stat().st_mode & 0o777) == 0o600
    expected_bytes = part1 + part2
    assert recovered_file.read_bytes() == expected_bytes
    assert hashlib.sha256(expected_bytes).hexdigest() == recovered_sha

    # Wrong passphrase must fail
    wrong_out = tmp_path / "wrong.bin"
    with pytest.raises(VerificationError, match="Index authentication failed"):
        IntegrityVerifier.decrypt_file(
            enc_file, wrong_out, passphrase="wrong_passphrase", idx_path=idx_file
        )


def test_encrypted_tamper_detection(tmp_path: Path) -> None:
    enc_file = tmp_path / "tamper_test.bin.enc"
    idx_file = tmp_path / "tamper_test.bin.idx"
    passphrase = "super_secret_tamper_test"
    data = b"Sensitive ciphertext content" * 10

    session = EncryptedFileSession(enc_file, idx_file, passphrase=passphrase, total_size=len(data))
    chunk = ChunkRecord(0, 0, len(data) - 1)
    session.write_chunk(chunk, data)
    session.finalize()

    # 1. Tamper with index HMAC
    parsed = json.loads(idx_file.read_text(encoding="utf-8"))
    parsed["hmac"] = "00" * 32
    bad_idx = tmp_path / "bad.idx"
    bad_idx.write_text(json.dumps(parsed), encoding="utf-8")

    out_file = tmp_path / "tampered.out"
    with pytest.raises(VerificationError, match="Index authentication failed"):
        IntegrityVerifier.decrypt_file(enc_file, out_file, passphrase=passphrase, idx_path=bad_idx)

    # 2. Tamper with ciphertext bytes
    enc_content = bytearray(enc_file.read_bytes())
    enc_content[-1] ^= 0xFF
    bad_enc = tmp_path / "bad.enc"
    bad_enc.write_bytes(bytes(enc_content))

    with pytest.raises(VerificationError, match="Decryption failed for chunk"):
        IntegrityVerifier.decrypt_file(bad_enc, out_file, passphrase=passphrase, idx_path=idx_file)


def test_torpool_decrypt_cli_command(tmp_path: Path) -> None:
    runner = CliRunner()
    enc_file = tmp_path / "artifact.enc"
    idx_file = tmp_path / "artifact.idx"
    out_file = tmp_path / "recovered.bin"
    key_file = tmp_path / "key.txt"
    passphrase = "my_cli_passphrase_123"
    key_file.write_text(passphrase + "\n", encoding="utf-8")

    content = b"Data processed through TorPool encrypted pipeline"
    session = EncryptedFileSession(
        enc_file, idx_file, passphrase=passphrase, total_size=len(content)
    )
    chunk = ChunkRecord(0, 0, len(content) - 1)
    session.write_chunk(chunk, content)
    session.finalize()
    assert idx_file.exists()

    # Test with --key-file
    result = runner.invoke(
        app,
        ["decrypt", str(enc_file), "--out", str(out_file), "--key-file", str(key_file)],
    )
    assert result.exit_code == 0
    assert out_file.read_bytes() == content
    assert (out_file.stat().st_mode & 0o777) == 0o600

    out_file.unlink()

    # Test with TORPOOL_PASSPHRASE env var
    with patch.dict(os.environ, {"TORPOOL_PASSPHRASE": passphrase}):
        result = runner.invoke(app, ["decrypt", str(enc_file), "--out", str(out_file)])
        assert result.exit_code == 0
        assert out_file.read_bytes() == content

    # Test non-existent key file
    result = runner.invoke(
        app,
        [
            "decrypt",
            str(enc_file),
            "--out",
            str(out_file),
            "--key-file",
            str(tmp_path / "missing.txt"),
        ],
    )
    assert result.exit_code != 0


def test_key_file_validation_in_config(tmp_path: Path) -> None:
    non_existent = tmp_path / "absent_key.txt"
    cfg = TorPoolConfig(key_file=non_existent)
    with pytest.raises(ConfigError, match="Specified key_file does not exist"):
        cfg.get_passphrase()

    empty_key = tmp_path / "empty_key.txt"
    empty_key.write_text("   \n", encoding="utf-8")
    cfg_empty = TorPoolConfig(key_file=empty_key)
    with pytest.raises(ConfigError, match="is empty"):
        cfg_empty.get_passphrase()

    valid_key = tmp_path / "valid_key.txt"
    valid_key.write_text("secure_phrase_from_file\n", encoding="utf-8")
    cfg_valid = TorPoolConfig(key_file=valid_key)
    assert cfg_valid.get_passphrase() == "secure_phrase_from_file"


# -------------------------------------------------------------------------- disk space & redirect errors


@pytest.mark.asyncio
async def test_pre_download_disk_space_check(tmp_path: Path) -> None:
    bus = EventBus()
    store = StateStore(tmp_path / "state.sqlite")
    metrics = MetricsWindow()
    limiter = BandwidthLimiter(0)
    cfg = TorPoolConfig(output_dir=tmp_path, temp_dir=tmp_path)
    downloader = RangeDownloader(cfg, metrics, limiter)
    pool = CircuitPool(cfg, MagicMock(spec=TorController), bus, metrics)

    scheduler = ChunkScheduler(
        config=cfg,
        pool=pool,
        downloader=downloader,
        event_bus=bus,
        state_store=store,
        metrics=metrics,
    )

    dummy_circuit = ManagedCircuit(
        circuit_id="probe-circ",
        created_at=0.0,
        relay_path=[],
        socks_user="u",
        socks_pass="p",
        proxy_url="socks5h://127.0.0.1:9050",
    )
    with (
        patch.object(pool, "acquire", return_value=dummy_circuit),
        patch.object(pool, "release"),
        patch.object(downloader, "probe_target", return_value=(2048, True)),
        patch("shutil.disk_usage", return_value=MagicMock(free=512)),
    ):
        with pytest.raises(DownloadError, match="Insufficient disk space") as exc_info:
            await scheduler.execute_download("https://example.com/file", tmp_path / "target.bin")
        assert exc_info.value.disk_full is True


@pytest.mark.asyncio
async def test_range_downloader_enospc_handling(tmp_path: Path) -> None:
    metrics = MetricsWindow()
    limiter = BandwidthLimiter(0)
    cfg = TorPoolConfig()
    downloader = RangeDownloader(cfg, metrics, limiter)
    target = tmp_path / "enospc_target.bin"
    target.touch()

    circuit = ManagedCircuit(
        circuit_id="test-slot",
        created_at=0.0,
        relay_path=[],
        socks_user="u",
        socks_pass="p",
        proxy_url="socks5h://127.0.0.1:9050",
    )
    chunk = ChunkRecord(0, 0, 99)

    class MockStreamContext:
        def __init__(self, data: bytes):
            self.data = data

        async def __aenter__(self):
            resp = MagicMock()
            resp.status_code = 206

            async def aiter(chunk_size: int = 65536):
                yield self.data

            resp.aiter_bytes = aiter
            return resp

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with (
        patch("httpx.AsyncClient.stream", return_value=MockStreamContext(b"X" * 100)),
        patch("os.open", side_effect=OSError(errno.ENOSPC, "No space left on device")),
    ):
        with pytest.raises(DownloadError, match="Disk full while writing chunk") as exc_info:
            await downloader.download_chunk(
                "https://example.com/chunk", chunk, circuit, target_file=target
            )
        assert exc_info.value.disk_full is True


@pytest.mark.asyncio
async def test_cross_domain_redirect_guidance() -> None:
    metrics = MetricsWindow()
    limiter = BandwidthLimiter(0)
    cfg = TorPoolConfig()
    downloader = RangeDownloader(cfg, metrics, limiter)
    circuit = ManagedCircuit(
        circuit_id="test-slot",
        created_at=0.0,
        relay_path=[],
        socks_user="u",
        socks_pass="p",
        proxy_url="socks5h://127.0.0.1:9050",
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"Location": "https://otherdomain.com/final_file.bin"}

    with patch("httpx.AsyncClient.head", return_value=mock_resp):
        with pytest.raises(DownloadError, match="supply the final URL directly"):
            await downloader.probe_target("https://initialdomain.com/start_file.bin", circuit)


# -------------------------------------------------------------------------- live status reporting


def test_live_status_reporting_and_cli(tmp_path: Path) -> None:
    runner = CliRunner()
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir(parents=True, mode=0o700)

    status_file = quarantine_dir / ".torpool_status_abc123.json"
    status_data = {
        "url": "https://example.onion/secure_file.iso",
        "total_bytes": 1048576,
        "completed_bytes": 524288,
        "current_bps": 204800.0,
        "peak_bps": 409600.0,
        "avg_bps": 204800.0,
        "eta_s": 2.5,
        "healthy_count": 4,
        "circuits": [
            {
                "circuit_id": "slot-0",
                "state": "healthy",
                "tor_circuit_id": "tor-99",
                "throughput_bps": 102400.0,
                "latency_s": 0.15,
            }
        ],
    }
    status_file.write_text(json.dumps(status_data), encoding="utf-8")

    result = runner.invoke(app, ["status", "--out", str(quarantine_dir)])
    assert result.exit_code == 0
    assert "Live Download Status" in result.output
    assert "https://example.onion/secure_file.iso" in result.output
    assert "slot-0" in result.output
    assert "tor-99" in result.output
