"""Tests for torrent planning, state persistence, and streaming encryption."""

from pathlib import Path

import pytest

from torpool.circuit_pool import CircuitPool, CircuitState, ManagedCircuit
from torpool.config import TorPoolConfig
from torpool.events import EventBus
from torpool.metrics import MetricsWindow
from torpool.state_store import StateStore, TorrentFileRecord
from torpool.tor_controller import TorController
from torpool.torrent_manager import (
    TorrentError,
    TorrentFile,
    TorrentInstance,
    TorrentPlan,
    TorrentSource,
    TorrentSupervisor,
    safe_relative_path,
)
from torpool.verifier import IntegrityVerifier


def _files() -> list[TorrentFile]:
    return [
        TorrentFile(0, "root/a.bin", 100),
        TorrentFile(1, "root/b.bin", 80),
        TorrentFile(2, "root/c.bin", 20),
    ]


def test_multi_file_plan_shards_and_covers_every_file() -> None:
    plan = TorrentPlan.build(_files(), max_instances=2, mode="auto")
    assert plan.instance_count == 2
    assert set().union(*plan.assignments.values()) == {0, 1, 2}
    assert all(plan.assignments.values())
    assert plan.total_size == 200


def test_single_file_uses_one_instance() -> None:
    plan = TorrentPlan.build([TorrentFile(0, "only.bin", 10)], max_instances=8, mode="auto")
    assert plan.instance_count == 1
    assert plan.assignments[0] == {0}


def test_forced_single_mode_uses_one_instance() -> None:
    plan = TorrentPlan.build(_files(), max_instances=8, mode="single")
    assert plan.instance_count == 1
    assert plan.assignments[0] == {0, 1, 2}


def test_bandwidth_limits_sum_within_global_cap(tmp_path: Path) -> None:
    cfg = TorPoolConfig(output_dir=tmp_path, max_bandwidth=10_000)
    bus_metrics = MetricsWindow()
    supervisor = TorrentSupervisor(
        cfg,
        CircuitPool(cfg, TorController(cfg, EventBus()), EventBus(), bus_metrics),
        EventBus(),
        bus_metrics,
        StateStore(tmp_path / "state.sqlite"),
    )
    limits = supervisor._download_limits(3)
    assert sum(limits.values()) <= 10_000
    assert limits[0] >= 1


def test_torrent_state_roundtrip(tmp_path: Path) -> None:
    store = StateStore(StateStore.state_path_for_torrent(tmp_path, "digest"))
    files = [
        TorrentFileRecord(0, "root/a.bin", 10, assigned_instance=0),
        TorrentFileRecord(1, "root/b.bin", 20, assigned_instance=1),
    ]
    store.initialize_torrent_job("digest", "abc", 30, files, 2)
    store.mark_torrent_file_done(0, "f" * 64)
    loaded = store.load_torrent_job()
    assert loaded is not None
    meta, rows = loaded
    assert meta["infohash"] == "abc"
    assert rows[0].completed is True
    assert rows[1].completed is False
    store.remove()


def test_tree_sha256_is_deterministic_and_order_independent() -> None:
    a = IntegrityVerifier.compute_tree_sha256([("b", "2" * 64), ("a", "1" * 64)])
    b = IntegrityVerifier.compute_tree_sha256([("a", "1" * 64), ("b", "2" * 64)])
    assert a == b
    assert a != IntegrityVerifier.compute_tree_sha256([("a", "2" * 64)])


def test_streaming_encryption_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "large.bin"
    payload = b"torpool" * 100_000
    target.write_bytes(payload)
    enc = IntegrityVerifier.encrypt_file_streaming(target, "passphrase", chunk_size=8192)
    assert not target.exists()
    assert enc.exists()
    out = tmp_path / "recovered.bin"
    size, digest = IntegrityVerifier.decrypt_file(enc, out, "passphrase")
    assert size == len(payload)
    assert out.read_bytes() == payload
    assert (out.stat().st_mode & 0o777) == 0o600
    assert digest == IntegrityVerifier.compute_sha256(out)


def test_torrent_config_defaults_are_conservative() -> None:
    cfg = TorPoolConfig()
    assert cfg.circuits == 4
    assert cfg.circuit_creation_delay == 1.0
    assert cfg.torrent_mode == "auto"
    assert cfg.torrent_max_instances == 8
    assert cfg.dht_enabled is False
    assert cfg.pex_enabled is False
    assert cfg.lsd_enabled is False
    assert not hasattr(cfg, "torrent_max_uploads")


@pytest.mark.parametrize(
    "path",
    ["../x", "/etc/passwd", "a/../../b"],
)
def test_supervisor_rejects_path_traversal(path: str) -> None:
    with pytest.raises(TorrentError):
        safe_relative_path(path)


def test_symlink_components_are_not_treated_as_staged_files(tmp_path: Path) -> None:
    from torpool.torrent_manager import _has_symlink_component, _resolved_within

    root = tmp_path / "staging"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "payload.bin").write_bytes(b"secret")
    (root / "link").symlink_to(outside, target_is_directory=True)
    candidate = root / "link" / "payload.bin"
    assert _has_symlink_component(candidate, root) is True
    assert _resolved_within(candidate, root) is False


def test_hash_control_password_rejects_bad_salt() -> None:
    from torpool.tor_password import hash_control_password

    with pytest.raises(ValueError):
        hash_control_password("password", salt=b"short")


class FakeProcess:
    def __init__(self) -> None:
        self.torrent_port = 43000
        self.web_port = 42000

    async def stop(self) -> None:
        return None


class FakeClient:
    def __init__(self, uploaded: int = 0, completed: int = 30) -> None:
        self.uploaded = uploaded
        self.completed = completed
        self.paused = False

    async def torrent(self, infohash: str) -> dict:
        return {
            "hash": infohash,
            "completed": self.completed,
            "uploaded": self.uploaded,
            "progress": 1.0 if self.completed >= 30 else 0.5,
            "state": "pausedUP" if self.completed >= 30 else "downloading",
        }

    async def files(self, infohash: str) -> list[dict]:
        return [
            {"index": 0, "name": "root/a.bin", "progress": 1.0, "size": 10},
            {"index": 1, "name": "root/b.bin", "progress": 1.0, "size": 20},
            {"index": 2, "name": "root/c.bin", "progress": 1.0, "size": 20},
        ]

    async def piece_states(self, infohash: str) -> list[int]:
        return []


@pytest.mark.asyncio
async def test_poll_loop_aggregates_bytes_and_detects_uploads(tmp_path: Path) -> None:
    cfg = TorPoolConfig(
        output_dir=tmp_path,
        temp_dir=tmp_path / "tmp",
        state_dir=tmp_path / "state",
        torrent_poll_interval=0.25,
    )
    metrics = MetricsWindow()
    state = StateStore(StateStore.state_path_for_torrent(cfg.effective_state_dir, "digest"))
    supervisor = TorrentSupervisor(
        cfg,
        CircuitPool(cfg, TorController(cfg, EventBus()), EventBus(), metrics),
        EventBus(),
        metrics,
        state,
    )
    circuit = ManagedCircuit(
        circuit_id="slot-1",
        created_at=0.0,
        relay_path=[],
        socks_user="u",
        socks_pass="p",
        proxy_url="",
        state=CircuitState.HEALTHY,
    )
    plan = TorrentPlan.build(_files(), 2, "auto")
    supervisor._files = _files()
    supervisor.instances = [
        TorrentInstance(
            instance_id=0,
            circuit=circuit,
            process=FakeProcess(),  # type: ignore[arg-type]
            client=FakeClient(),  # type: ignore[arg-type]
            staging_dir=tmp_path / "0",
            selected={0, 1, 2},
        )
    ]
    await supervisor._poll_loop(plan)
    assert metrics.get_snapshot()["completed_bytes"] == 30
    assert supervisor.instances[0].done

    bad = TorrentInstance(
        instance_id=0,
        circuit=circuit,
        process=FakeProcess(),  # type: ignore[arg-type]
        client=FakeClient(uploaded=1),  # type: ignore[arg-type]
        staging_dir=tmp_path / "2",
        selected={0, 1, 2},
    )
    bad.last_uploaded = 0
    supervisor.instances = [bad]
    with pytest.raises(TorrentError, match="Zero-upload"):
        await supervisor._poll_loop(plan)


@pytest.mark.asyncio
async def test_finalize_moves_files_and_writes_manifest(tmp_path: Path) -> None:
    cfg = TorPoolConfig(output_dir=tmp_path / "out", state_dir=tmp_path / "state")
    (tmp_path / "out").mkdir()
    metrics = MetricsWindow()
    state = StateStore(StateStore.state_path_for_torrent(cfg.effective_state_dir, "digest"))
    supervisor = TorrentSupervisor(
        cfg,
        CircuitPool(cfg, TorController(cfg, EventBus()), EventBus(), metrics),
        EventBus(),
        metrics,
        state,
    )
    plan = TorrentPlan.build(_files(), 1, "single")
    staging = tmp_path / "staging"
    for file in _files():
        path = staging / file.relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * file.size)
    supervisor.instances = [
        TorrentInstance(
            instance_id=0,
            circuit=ManagedCircuit(
                circuit_id="slot-1",
                created_at=0.0,
                relay_path=[],
                socks_user="u",
                socks_pass="p",
                proxy_url="",
                state=CircuitState.HEALTHY,
            ),
            process=FakeProcess(),  # type: ignore[arg-type]
            client=FakeClient(),  # type: ignore[arg-type]
            staging_dir=staging,
            selected={0, 1, 2},
        )
    ]
    state.initialize_torrent_job("digest", "abc", 200, [], 1)
    source = TorrentSource("torrent", "[TORRENT_FILE]", "digest")
    results = await supervisor._finalize(plan, cfg.output_dir, source, None)
    assert len(results) == 3
    assert (cfg.output_dir / "root" / "a.bin").exists()
    assert (cfg.output_dir / "manifest.json").exists()
    manifest = (cfg.output_dir / "manifest.json").read_text(encoding="utf-8")
    assert "a.bin" not in manifest
    assert "root/" not in manifest
    assert all(path.stat().st_mode & 0o777 == 0o600 for path, _ in results)
