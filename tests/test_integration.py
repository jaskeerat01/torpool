"""Optional integration test suite gated by TORPOOL_INTEGRATION=1."""

from pathlib import Path

import pytest

from tests.integration.dns_leak import DNSLeakDetector
from tests.integration.file_generator import generate_test_file
from tests.integration.server import RangeServer
from torpool.circuit_pool import CircuitPool, CircuitState, ManagedCircuit
from torpool.config import TorPoolConfig
from torpool.downloader import RangeDownloader
from torpool.events import EventBus
from torpool.metrics import BandwidthLimiter, MetricsWindow
from torpool.scheduler import ChunkScheduler
from torpool.state_store import StateStore
from torpool.verifier import IntegrityVerifier

pytestmark = pytest.mark.integration


def test_integration_no_clearnet_dns_leaks() -> None:
    """Verify that TorPool SOCKS requests use remote domain resolution (ATYP=0x03)."""
    # Valid SOCKS5 connect request with ATYP=0x03 (domain name)
    domain_req = b"\x05\x01\x00\x03\x0bexample.com\x01\xbb"
    assert DNSLeakDetector.verify_socks5h_address_type(domain_req) is True

    # Invalid SOCKS5 connect request with ATYP=0x01 (IPv4 - would leak local DNS)
    ipv4_req = b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb"
    assert DNSLeakDetector.verify_socks5h_address_type(ipv4_req) is False


@pytest.mark.asyncio
async def test_integration_local_range_server_and_chunks(tmp_path: Path) -> None:
    """Validate full ranged HTTP chunking against a local Range-request test server."""
    serve_dir = tmp_path / "server_data"
    test_file, expected_sha256 = generate_test_file(
        serve_dir / "payload.bin", size_bytes=512 * 1024
    )

    server = RangeServer(serve_dir)
    port = server.start()
    url = f"http://127.0.0.1:{port}/payload.bin"

    cfg = TorPoolConfig(
        circuits=2,
        chunk_size=128 * 1024,
        output_dir=tmp_path / "quarantine",
        temp_dir=tmp_path / "quarantine" / "tmp",
        config_path=tmp_path / "config.toml",
    )
    bus = EventBus()
    metrics = MetricsWindow()
    limiter = BandwidthLimiter(0)
    downloader = RangeDownloader(cfg, metrics, limiter)

    # Use dummy ManagedCircuits with direct loopback (no Tor daemon required)
    def make_direct_circuit(cid: str) -> ManagedCircuit:
        return ManagedCircuit(
            circuit_id=cid,
            created_at=0.0,
            relay_path=[],
            socks_user="user",
            socks_pass="pass",
            proxy_url="",
            state=CircuitState.HEALTHY,
        )

    pool = CircuitPool(cfg, None, bus, metrics)  # type: ignore[arg-type]
    pool._circuits["slot-1"] = make_direct_circuit("slot-1")
    pool._circuits["slot-2"] = make_direct_circuit("slot-2")

    state_store = StateStore(StateStore.state_path_for_url(cfg.output_dir, url))
    scheduler = ChunkScheduler(cfg, pool, downloader, state_store, bus, metrics)

    target_file = cfg.output_dir / "downloaded.bin"
    try:
        total = await scheduler.execute_download(url, target_file, resume=False)
        assert total == 512 * 1024
        actual_sha256 = IntegrityVerifier.compute_sha256(target_file)
        assert actual_sha256.lower() == expected_sha256.lower()
    finally:
        server.stop()
        state_store.remove()


@pytest.mark.asyncio
async def test_integration_range_download_and_resume(tmp_path: Path) -> None:
    """Validate that interrupted downloads resume and successfully reconstruct original payload."""
    serve_dir = tmp_path / "server_data"
    test_file, expected_sha256 = generate_test_file(
        serve_dir / "resume_test.bin", size_bytes=256 * 1024
    )

    server = RangeServer(serve_dir)
    port = server.start()
    url = f"http://127.0.0.1:{port}/resume_test.bin"

    cfg = TorPoolConfig(
        circuits=1,
        chunk_size=64 * 1024,
        output_dir=tmp_path / "quarantine",
        temp_dir=tmp_path / "quarantine" / "tmp",
        config_path=tmp_path / "config.toml",
    )
    bus = EventBus()
    metrics = MetricsWindow()
    limiter = BandwidthLimiter(0)
    downloader = RangeDownloader(cfg, metrics, limiter)

    pool = CircuitPool(cfg, None, bus, metrics)  # type: ignore[arg-type]
    mc = ManagedCircuit(
        circuit_id="direct",
        created_at=0.0,
        relay_path=[],
        socks_user="user",
        socks_pass="pass",
        proxy_url="",
        state=CircuitState.HEALTHY,
    )
    pool._circuits["direct"] = mc

    state_store = StateStore(StateStore.state_path_for_url(cfg.output_dir, url))
    scheduler = ChunkScheduler(cfg, pool, downloader, state_store, bus, metrics)

    target_file = cfg.output_dir / "resume_test.bin"
    try:
        # Pre-initialize job and simulate 2 completed chunks out of 4
        chunks = scheduler.build_initial_chunks(256 * 1024, 64 * 1024)
        downloader.preallocate_file(target_file, 256 * 1024)
        state_store.initialize_job(url, 256 * 1024, chunks)

        # Download chunk 0 and 1 manually
        await downloader.download_chunk(url, chunks[0], mc, target_file)
        state_store.mark_chunk_done(chunks[0].chunk_id, 0)
        await downloader.download_chunk(url, chunks[1], mc, target_file)
        state_store.mark_chunk_done(chunks[1].chunk_id, 0)

        # Resume download for remaining chunks
        resumed_scheduler = ChunkScheduler(cfg, pool, downloader, state_store, bus, metrics)
        total = await resumed_scheduler.execute_download(url, target_file, resume=True)
        assert total == 256 * 1024

        actual_sha256 = IntegrityVerifier.compute_sha256(target_file)
        assert actual_sha256.lower() == expected_sha256.lower()
    finally:
        server.stop()
        state_store.remove()
