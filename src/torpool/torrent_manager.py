"""Multi-instance qBittorrent torrent orchestration over isolated Tor circuits."""

import asyncio
import base64
import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlparse

from torpool.circuit_pool import CircuitPool, CircuitState, ManagedCircuit
from torpool.config import TorPoolConfig
from torpool.events import EventBus, EventType
from torpool.metrics import MetricsWindow
from torpool.qbittorrent import (
    PreferenceExpectation,
    QBittorrentClient,
    QBittorrentProcess,
    build_torrent_preferences,
    qbittorrent_location,
)
from torpool.sanitizer import sanitize_log_text, sanitize_torrent_source
from torpool.state_store import StateStore, TorrentFileRecord
from torpool.verifier import IntegrityVerifier, VerificationError

MAX_TORRENT_FILE_BYTES = 16 * 1024 * 1024
FINISHED_STATES = {
    "pausedUP",
    "queuedUP",
    "uploading",
    "stalledUP",
    "checkingUP",
    "forcedUP",
}


class TorrentError(Exception):
    """Raised when a torrent job cannot proceed safely."""


@dataclass(frozen=True)
class TorrentFile:
    """One content file inside a torrent."""

    index: int
    relative_path: str
    size: int


@dataclass(frozen=True)
class TorrentSource:
    """Validated magnet URI or .torrent file input."""

    kind: str
    value: str
    source_digest: str
    infohash: str = ""
    torrent_bytes: Optional[bytes] = None

    @property
    def manifest_label(self) -> str:
        return sanitize_torrent_source(self.kind, self.value, self.infohash)


def _decode_infohash(value: str) -> str:
    prefix = "urn:btih:"
    if value.lower().startswith(prefix):
        raw = value[len(prefix) :]
        if len(raw) == 40:
            try:
                bytes.fromhex(raw)
            except ValueError as exc:
                raise TorrentError("Invalid magnet info-hash") from exc
            return raw.lower()
        if len(raw) == 32:
            try:
                return base64.b32decode(raw.upper()).hex()
            except Exception as exc:
                raise TorrentError("Invalid base32 magnet info-hash") from exc
        raise TorrentError("Magnet info-hash must be 40 hex or 32 base32 characters")
    prefix = "urn:btmh:"
    if value.lower().startswith(prefix):
        raw = value[len(prefix) :].lower()
        if len(raw) == 68 and raw.startswith("1220"):
            return raw[4:]
        raise TorrentError("Only v2 SHA-256 magnet info-hashes are supported")
    raise TorrentError("Magnet URI must contain xt=urn:btih: or xt=urn:btmh:")


def parse_torrent_source(value: str) -> TorrentSource:
    """Classify a fetch argument as a magnet URI or a private .torrent file."""
    lowered = value.lower()
    if lowered.startswith("magnet:"):
        parsed = urlparse(value)
        if parsed.scheme.lower() != "magnet":
            raise TorrentError("Invalid magnet URI")
        params = parse_qsl(parsed.query, keep_blank_values=True)
        keys = {key.lower(): val for key, val in params}
        forbidden = {"xs", "ws", "as"}
        if forbidden.intersection(keys):
            raise TorrentError(
                "Magnet parameters xs/ws/as are refused because they add fetch paths"
            )
        infohash = ""
        for key, val in params:
            if key.lower() == "xt":
                infohash = _decode_infohash(val)
                break
        if not infohash:
            raise TorrentError("Magnet URI is missing an info-hash")
        if not any(key.lower() == "tr" for key, _ in params):
            raise TorrentError(
                "Trackerless magnets are refused because DHT is disabled. "
                "Supply a .torrent file or a magnet with at least one tr= tracker."
            )
        digest = hashlib.sha256(f"magnet:{infohash}".encode("utf-8")).hexdigest()
        return TorrentSource(kind="magnet", value=value, source_digest=digest, infohash=infohash)

    path = Path(value).expanduser()
    if path.is_symlink():
        raise TorrentError("Refusing symlinked .torrent input")
    if not path.exists() or not path.is_file():
        raise TorrentError("Torrent input is neither a magnet URI nor a readable file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_TORRENT_FILE_BYTES:
        raise TorrentError(".torrent file size is outside the permitted range")
    data = path.read_bytes()
    if not data.startswith(b"d") or not data.endswith(b"e"):
        raise TorrentError(".torrent file is not a valid bencoded dictionary")
    digest = hashlib.sha256(data).hexdigest()
    return TorrentSource(
        kind="torrent", value="[TORRENT_FILE]", source_digest=digest, torrent_bytes=data
    )


@dataclass
class TorrentPlan:
    """File-to-instance assignment for a torrent job."""

    files: list[TorrentFile]
    assignments: dict[int, set[int]]
    total_size: int

    @property
    def instance_count(self) -> int:
        return len(self.assignments)

    @classmethod
    def build(cls, files: list[TorrentFile], max_instances: int, mode: str) -> "TorrentPlan":
        """Assign files to instances, balancing bytes while using disjoint sets."""
        if not files:
            raise TorrentError("Torrent metadata contained no content files")
        if mode == "single" or len(files) == 1:
            return cls(
                files=files,
                assignments={0: {f.index for f in files}},
                total_size=sum(f.size for f in files),
            )
        count = max(1, min(max_instances, len(files)))
        buckets: dict[int, set[int]] = {i: set() for i in range(count)}
        loads = {i: 0 for i in range(count)}
        ordered = sorted(files, key=lambda f: (-f.size, f.index))
        for file in ordered:
            target = min(range(count), key=lambda i: (loads[i], i))
            buckets[target].add(file.index)
            loads[target] += file.size
        return cls(files=files, assignments=buckets, total_size=sum(f.size for f in files))


@dataclass
class TorrentInstance:
    """A qBittorrent process bound to exactly one Tor circuit."""

    instance_id: int
    circuit: ManagedCircuit
    process: QBittorrentProcess
    client: QBittorrentClient
    staging_dir: Path
    selected: set[int] = field(default_factory=set)
    infohash: str = ""
    torrent_name: str = ""
    content_path: str = ""
    download_limit: int = 0
    last_completed: int = 0
    last_uploaded: int = 0
    last_pieces: int = 0
    done: bool = False
    version: str = "unknown"

    @property
    def circuit_id(self) -> str:
        return self.circuit.circuit_id


def safe_relative_path(value: str) -> Path:
    """Validate a torrent content path so it cannot escape the quarantine root."""
    if not value or "\x00" in value:
        raise TorrentError("Torrent contained an invalid empty content path")
    path = Path(value)
    if path.is_absolute():
        raise TorrentError("Torrent contained an absolute content path")
    parts = path.parts
    if any(part in ("", ".", "..") for part in parts):
        raise TorrentError("Torrent contained a path traversal component")
    if path.name in ("", "."):
        raise TorrentError("Torrent contained an invalid content file name")
    return path


def _resolved_within(path: Path, root: Path) -> bool:
    """Return True only if path resolves to a location inside root."""
    try:
        root_resolved = root.resolve()
        resolved = path.resolve()
    except OSError:
        return False
    return resolved == root_resolved or root_resolved in resolved.parents


def _has_symlink_component(path: Path, root: Path) -> bool:
    """Reject paths containing a symlink between root and the final entry."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


class TorrentSupervisor:
    """Run one torrent job across one or more isolated qBittorrent instances."""

    def __init__(
        self,
        config: TorPoolConfig,
        pool: CircuitPool,
        event_bus: EventBus,
        metrics: MetricsWindow,
        state_store: StateStore,
    ) -> None:
        self.config = config
        self.pool = pool
        self.event_bus = event_bus
        self.metrics = metrics
        self.state_store = state_store
        self.instances: list[TorrentInstance] = []
        self._infohash = ""
        self._job_id = ""
        self._control_path: Optional[Path] = None
        self._status_path: Optional[Path] = None
        self._files: list[TorrentFile] = []
        self._resume_completed: set[int] = set()
        self._stopped = False
        self._staging_root: Optional[Path] = None

    async def run(
        self,
        source: TorrentSource,
        output_dir: Path,
        expected_sha256: Optional[str] = None,
        resume: bool = False,
    ) -> tuple[int, str, Path]:
        """Download, finalize, hash, and optionally encrypt a torrent job."""
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(output_dir, 0o700)
        executable = qbittorrent_location(self.config.qbittorrent_executable)
        if not executable:
            raise TorrentError(
                f"qBittorrent executable not found: {self.config.qbittorrent_executable}"
            )
        self._job_id = hashlib.sha256(source.source_digest.encode("utf-8")).hexdigest()[:16]
        staging_root = output_dir / ".torrent_staging" / self._job_id
        self._staging_root = staging_root
        staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(staging_root, 0o700)

        loaded = self.state_store.load_torrent_job() if resume else None
        if loaded:
            _, persisted = loaded
            for record in persisted:
                try:
                    safe_relative_path(record.relative_path)
                except TorrentError as exc:
                    raise TorrentError("Resume state contained an unsafe content path") from exc
            self._resume_completed = {
                f.file_index
                for f in persisted
                if f.completed and self._find_existing_file(staging_root, f.relative_path)
            }

        t0 = time.monotonic()
        try:
            coordinator = await self._start_instance(
                executable, staging_root, 0, output_dir, source, download_limit=0
            )
            self.instances.append(coordinator)
            self._write_control_file(None)
            info_hashes, files = await self._wait_for_metadata(coordinator, source)
            self._infohash = info_hashes
            self._files = files
            cap_instances = self.config.torrent_max_instances
            if self.config.max_bandwidth > 0:
                if self.config.max_bandwidth < 1024:
                    raise TorrentError(
                        "max_bandwidth is too low for a torrent instance; "
                        "qBittorrent's minimum positive limit is 1 KiB/s"
                    )
                cap_instances = min(cap_instances, max(1, self.config.max_bandwidth // 1024))
            plan = TorrentPlan.build(
                files,
                min(
                    cap_instances,
                    self.config.circuits,
                    max(1, len(self.pool.healthy_circuits())),
                ),
                self.config.torrent_mode,
            )
            required = plan.total_size * (2 if self.config.encrypt else 1) + 10 * 1024 * 1024
            try:
                free = shutil.disk_usage(output_dir).free
            except OSError:
                free = required
            if free < required:
                raise TorrentError(
                    "Insufficient disk space for torrent download plus encryption buffer"
                )
            limits = self._download_limits(plan.instance_count)
            for assignment_id, selected in plan.assignments.items():
                if assignment_id == 0:
                    instance = coordinator
                else:
                    instance = await self._start_instance(
                        executable,
                        staging_root,
                        assignment_id,
                        output_dir,
                        source,
                        download_limit=limits.get(assignment_id, 0),
                    )
                    self.instances.append(instance)
                    self._write_control_file(None)
                    await self._wait_for_metadata(instance, source)
                active_selected = selected - self._resume_completed
                instance.selected = active_selected
                instance.download_limit = limits.get(assignment_id, 0)
                await self._prepare_instance(instance, active_selected, limits)
                if not active_selected:
                    instance.done = True

            self._initialize_state(source, plan)
            self.metrics.set_target_size(
                plan.total_size,
                initial_completed=sum(
                    f.size for f in plan.files if f.index in self._resume_completed
                ),
            )
            self.metrics.set_job_items(len(self._resume_completed), len(plan.files))
            self._write_control_file(plan)
            self._write_status_file(plan)

            if len(self._resume_completed) < len(plan.files):
                await self._poll_loop(plan)
            await self._stop_instances()
            final_files = await self._finalize(plan, output_dir, source, expected_sha256)
            self.state_store.remove()
            self._remove_control_files()
            tree_hash = IntegrityVerifier.compute_tree_sha256(
                [(file.relative_path, digest) for file, (_, digest) in zip(plan.files, final_files)]
            )
            result_sha = final_files[0][1] if len(final_files) == 1 else tree_hash
            self.event_bus.emit(
                EventType.TORRENT_FINISHED,
                files_total=len(plan.files),
                total_bytes=plan.total_size,
                duration_s=time.monotonic() - t0,
            )
            self._cleanup_staging()
            final_path = final_files[0][0] if len(final_files) == 1 else output_dir
            return plan.total_size, result_sha, final_path
        except Exception as exc:
            self.event_bus.emit(
                EventType.TORRENT_ERROR,
                reason=type(exc).__name__.upper(),
                message=sanitize_log_text(str(exc))[:300],
            )
            raise
        finally:
            await self.close()
            if self._control_path is None:
                self._remove_control_files()

    async def _start_instance(
        self,
        executable: str,
        staging_root: Path,
        instance_id: int,
        output_dir: Path,
        source: TorrentSource,
        download_limit: int,
    ) -> TorrentInstance:
        circuit = await self.pool.acquire()
        if not circuit:
            raise TorrentError("No healthy Tor circuit available for torrent instance")
        profile_dir = self.config.qbittorrent_temp_profile_dir / self._job_id / str(instance_id)
        web_port = self.config.qbittorrent_web_port
        if web_port and web_port + instance_id <= 65535:
            web_port += instance_id
        else:
            web_port = 0
        staging_dir = staging_root / str(instance_id)
        process: Optional[QBittorrentProcess] = None
        try:
            process = QBittorrentProcess.create(executable, profile_dir, web_port=web_port)
            staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(staging_dir, 0o700)
            client = await process.start()
            version = await client.version()
            self.event_bus.emit(
                EventType.QBITTORRENT_STARTED,
                instance_id=instance_id,
                version=version,
            )
            expected = PreferenceExpectation(
                proxy_port=circuit.listener_port,
                proxy_username=circuit.socks_user,
                save_path=str(staging_dir),
                listen_port=process.torrent_port,
                bind_interface=self.config.torrent_bind_interface,
                web_port=process.web_port,
            )
            prefs = build_torrent_preferences(
                self.config,
                circuit.socks_user,
                circuit.socks_pass,
                circuit.listener_port,
                staging_dir,
                process.torrent_port,
                process.web_port,
                download_limit,
            )
            await client.apply_and_verify(prefs, expected)
            instance = TorrentInstance(
                instance_id=instance_id,
                circuit=circuit,
                process=process,
                client=client,
                staging_dir=staging_dir,
                version=version,
            )
            self.event_bus.emit(
                EventType.CIRCUIT_ASSIGNED_TO_TORRENT,
                instance_id=instance_id,
                circuit_id=circuit.circuit_id,
                role="download",
            )
            self._write_control_file(None)
            return instance
        except Exception:
            if process is not None:
                await process.stop()
            await self.pool.release(circuit.circuit_id)
            raise

    async def _wait_for_metadata(
        self, instance: TorrentInstance, source: TorrentSource
    ) -> tuple[str, list[TorrentFile]]:
        """Add the torrent to an instance and wait for its metadata."""
        await instance.client.add_torrent(
            source.value if source.kind == "magnet" else "",
            instance.staging_dir,
            paused=source.kind == "torrent",
            torrent_bytes=source.torrent_bytes,
        )
        infohash = await self._discover_hash(instance.client, source)
        instance.infohash = infohash
        self.event_bus.emit(
            EventType.TORRENT_ADDED,
            instance_id=instance.instance_id,
            infohash_prefix=infohash[:12],
            files_total=0,
        )
        deadline = time.monotonic() + self.config.torrent_metadata_timeout
        while time.monotonic() < deadline:
            info = await instance.client.torrent(infohash)
            size_value = float((info or {}).get("size") or (info or {}).get("total_size") or 0)
            if info and size_value > 0:
                instance.torrent_name = str(info.get("name", ""))
                instance.content_path = str(info.get("content_path", ""))
                files = await instance.client.files(infohash)
                parsed = self._parse_files(files)
                await instance.client.pause(infohash)
                self.event_bus.emit(
                    EventType.TORRENT_METADATA_RECEIVED,
                    infohash_prefix=infohash[:12],
                    files_total=len(parsed),
                    total_bytes=sum(f.size for f in parsed),
                )
                return infohash, parsed
            await asyncio.sleep(0.5)
        raise TorrentError("Timed out waiting for torrent metadata over Tor")

    async def _discover_hash(self, client: QBittorrentClient, source: TorrentSource) -> str:
        deadline = time.monotonic() + self.config.torrent_metadata_timeout
        while time.monotonic() < deadline:
            torrents = await client.torrents()
            if torrents:
                if source.infohash:
                    for item in torrents:
                        if str(item.get("hash", "")).lower() == source.infohash.lower():
                            return source.infohash
                return str(torrents[0].get("hash", "")).lower()
            await asyncio.sleep(0.25)
        raise TorrentError("qBittorrent did not register the torrent")

    @staticmethod
    def _parse_files(files: list[dict[str, Any]]) -> list[TorrentFile]:
        parsed: list[TorrentFile] = []
        for position, item in enumerate(files):
            index = int(item.get("index", position))
            name = str(item.get("name", ""))
            safe_relative_path(name)
            parsed.append(
                TorrentFile(
                    index=index,
                    relative_path=name,
                    size=int(item.get("size", 0)),
                )
            )
        parsed.sort(key=lambda f: f.index)
        return parsed

    async def _prepare_instance(
        self,
        instance: TorrentInstance,
        selected: set[int],
        download_limits: dict[int, int],
    ) -> None:
        await instance.client.pause(instance.infohash)
        all_indexes = [f.index for f in self._files]
        await instance.client.set_file_priorities(instance.infohash, selected, all_indexes)
        await instance.client.set_upload_limit(instance.infohash, 1)
        limit = download_limits.get(instance.instance_id, 0)
        if limit > 0:
            await instance.client.set_download_limit(instance.infohash, limit)
        info = await instance.client.torrent(instance.infohash)
        if info:
            instance.last_uploaded = int(info.get("uploaded", 0))
            instance.last_completed = int(info.get("completed", 0))
            if instance.last_uploaded != 0:
                raise TorrentError("qBittorrent reported upload traffic before download")
        await instance.client.resume(instance.infohash)

    def _initialize_state(self, source: TorrentSource, plan: TorrentPlan) -> None:
        records = []
        for file in plan.files:
            assigned = next(
                (
                    instance_id
                    for instance_id, selected in plan.assignments.items()
                    if file.index in selected
                ),
                -1,
            )
            records.append(
                TorrentFileRecord(
                    file_index=file.index,
                    relative_path=file.relative_path,
                    size=file.size,
                    assigned_instance=assigned,
                    completed=file.index in self._resume_completed,
                )
            )
        self.state_store.initialize_torrent_job(
            source_digest=source.source_digest,
            infohash=self._infohash,
            total_size=plan.total_size,
            files=records,
            instance_count=plan.instance_count,
        )

    async def _poll_loop(self, plan: TorrentPlan) -> None:
        last_files_done = -1
        while True:
            all_done = True
            done_indexes: set[int] = set(self._resume_completed)
            for instance in self.instances:
                if not instance.selected:
                    instance.done = True
                    continue
                await self._ensure_circuit(instance)
                info = await instance.client.torrent(instance.infohash)
                if info is None:
                    raise TorrentError("qBittorrent lost the active torrent")
                uploaded = int(info.get("uploaded", 0))
                if uploaded > instance.last_uploaded:
                    raise TorrentError(
                        "Zero-upload enforcement failed: qBittorrent reported uploaded bytes"
                    )
                completed = int(info.get("completed", 0))
                if completed > instance.last_completed:
                    self.metrics.record_bytes(
                        instance.circuit_id, completed - instance.last_completed
                    )
                    instance.last_completed = completed
                states = await instance.client.piece_states(instance.infohash)
                if states:
                    pieces = sum(1 for state in states if int(state) >= 2)
                    if pieces > instance.last_pieces:
                        self.event_bus.emit(
                            EventType.TORRENT_PIECE_DONE,
                            instance_id=instance.instance_id,
                            pieces_delta=pieces - instance.last_pieces,
                            piece_count=len(states),
                        )
                        instance.last_pieces = pieces
                file_rows = await instance.client.files(instance.infohash)
                for row in file_rows:
                    index = int(row.get("index", -1))
                    if index in instance.selected and float(row.get("progress", 0.0)) >= 1.0:
                        done_indexes.add(index)
                progress = float(info.get("progress", 0.0))
                state = str(info.get("state", ""))
                if state in ("error", "missingFiles", "unknown"):
                    raise TorrentError(f"qBittorrent torrent state is {state}")
                if progress >= 0.999999 or state in FINISHED_STATES:
                    instance.done = True
                if not instance.done:
                    all_done = False
            unique_done = min(len(plan.files), len(done_indexes))
            self.metrics.set_job_items(unique_done, len(plan.files))
            if unique_done != last_files_done:
                self.event_bus.emit(
                    EventType.TORRENT_FILE_DONE,
                    instance_id=-1,
                    file_index=-1,
                    files_done=unique_done,
                    files_total=len(plan.files),
                )
                last_files_done = unique_done
            self._write_status_file(plan)
            if all_done:
                return
            await asyncio.sleep(self.config.torrent_poll_interval)

    async def _ensure_circuit(self, instance: TorrentInstance) -> None:
        if instance.circuit.state not in (CircuitState.DEAD, CircuitState.RETIRING):
            return
        await instance.client.pause(instance.infohash)
        await self.pool.release(instance.circuit.circuit_id)
        replacement = await self.pool.acquire()
        if not replacement:
            raise TorrentError("Tor circuit exhaustion while torrent was active")
        instance.circuit = replacement
        expected = PreferenceExpectation(
            proxy_port=replacement.listener_port,
            proxy_username=replacement.socks_user,
            save_path=str(instance.staging_dir),
            listen_port=instance.process.torrent_port,
            bind_interface=self.config.torrent_bind_interface,
            web_port=instance.process.web_port,
        )
        prefs = build_torrent_preferences(
            self.config,
            replacement.socks_user,
            replacement.socks_pass,
            replacement.listener_port,
            instance.staging_dir,
            instance.process.torrent_port,
            instance.process.web_port,
            instance.download_limit,
        )
        await instance.client.apply_and_verify(prefs, expected)
        await instance.client.resume(instance.infohash)
        refreshed = await instance.client.torrent(instance.infohash)
        if refreshed:
            instance.last_uploaded = int(refreshed.get("uploaded", 0))
            instance.last_completed = int(refreshed.get("completed", 0))
            if instance.last_uploaded > 0:
                raise TorrentError("Zero-upload enforcement failed after circuit rebind")
        self.event_bus.emit(
            EventType.CIRCUIT_ASSIGNED_TO_TORRENT,
            instance_id=instance.instance_id,
            circuit_id=replacement.circuit_id,
            role="rebind",
        )

    async def _finalize(
        self,
        plan: TorrentPlan,
        output_dir: Path,
        source: TorrentSource,
        expected_sha256: Optional[str],
    ) -> list[tuple[Path, str]]:
        manifest_path = output_dir / "manifest.json"
        results: list[tuple[Path, str]] = []
        passphrase = self.config.get_passphrase() if self.config.encrypt else None
        source_label = f"torrent://{self._infohash}" if self._infohash else source.manifest_label
        for file in plan.files:
            source_path = self._locate_staged_file(file)
            relative = safe_relative_path(file.relative_path)
            destination = output_dir / relative
            if not _resolved_within(destination.parent, output_dir):
                raise TorrentError("Torrent destination escaped the quarantine root")
            if _has_symlink_component(destination.parent, output_dir):
                raise TorrentError("Torrent destination path contains a symlink")
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(destination.parent, 0o700)
            if destination.is_symlink():
                raise TorrentError("Refusing to replace a symlink in quarantine")
            if destination.exists():
                IntegrityVerifier.shred_file(destination)
            try:
                os.replace(source_path, destination)
            except OSError:
                shutil.copy2(source_path, destination)
                IntegrityVerifier.shred_file(source_path)
            os.chmod(destination, 0o600)
            expected_file = expected_sha256 if len(plan.files) == 1 else None
            passed, digest, final_path = IntegrityVerifier.verify_torrent_file(
                destination,
                file.relative_path,
                source_label,
                expected_sha256=expected_file,
                manifest_path=manifest_path,
                encrypt=self.config.encrypt,
                passphrase=passphrase,
                manifest_id=f"content_{file.index:06d}",
            )
            if not passed:
                raise VerificationError("Integrity failure for torrent content file")
            results.append((final_path, digest))
            self.state_store.mark_torrent_file_done(file.index, digest)
        if len(plan.files) > 1 and expected_sha256:
            tree_hash = IntegrityVerifier.compute_tree_sha256(
                [(file.relative_path, digest) for file, (_, digest) in zip(plan.files, results)]
            )
            if tree_hash.lower() != expected_sha256.strip().lower():
                raise VerificationError("Torrent tree SHA-256 does not match --sha256")
        return results

    def _locate_staged_file(self, file: TorrentFile) -> Path:
        candidates: list[tuple[Path, Path]] = []
        relative = safe_relative_path(file.relative_path)
        for instance in self.instances:
            root = instance.staging_dir
            candidates.append((root / relative, root))
            candidates.append((root / relative.name, root))
            if instance.torrent_name:
                candidates.append((root / instance.torrent_name / relative, root))
                candidates.append((root / instance.torrent_name / relative.name, root))
            if instance.content_path:
                content = Path(instance.content_path)
                if content.is_dir():
                    candidates.append((content / relative.name, root))
                    candidates.append((content / relative, root))
                else:
                    candidates.append((content, root))
        for candidate, root in candidates:
            if (
                candidate.exists()
                and candidate.is_file()
                and not candidate.is_symlink()
                and not _has_symlink_component(candidate, root)
                and _resolved_within(candidate, root)
            ):
                return candidate
        raise TorrentError("Completed torrent file is missing from the staging directory")

    def _find_existing_file(self, staging_root: Path, relative_path: str) -> bool:
        relative = Path(relative_path)
        for child in staging_root.glob("*"):
            candidate = child / relative
            if (
                candidate.exists()
                and candidate.is_file()
                and not candidate.is_symlink()
                and not _has_symlink_component(candidate, staging_root)
                and _resolved_within(candidate, staging_root)
            ):
                return True
        return False

    def _download_limits(self, instance_count: int) -> dict[int, int]:
        cap = self.config.max_bandwidth
        if cap <= 0:
            return {i: 0 for i in range(instance_count)}
        if cap < instance_count * 1024:
            return {i: 1 for i in range(instance_count)}
        per_instance = max(1, cap // instance_count)
        return {i: per_instance for i in range(instance_count)}

    def _control_path_for(self) -> Path:
        directory = self.config.effective_state_dir
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return directory / f".torpool_torrent_control_{self._job_id}.json"

    def _status_path_for(self) -> Path:
        directory = self.config.effective_state_dir
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return directory / f".torpool_torrent_status_{self._job_id}.json"

    def _write_control_file(self, plan: Optional[TorrentPlan]) -> None:
        if not self._job_id:
            return
        path = self._control_path_for()
        data: dict[str, Any] = {
            "job_id": self._job_id,
            "infohash": self._infohash,
            "pid": os.getpid(),
            "updated_at": time.time(),
            "instances": [
                {
                    "instance_id": i.instance_id,
                    "web_port": i.process.web_port,
                    "username": i.process.username,
                    "password": i.process.password,
                    "circuit_id": i.circuit_id,
                }
                for i in self.instances
            ],
        }
        if plan:
            data["files_total"] = len(plan.files)
            data["total_bytes"] = plan.total_size
        self._atomic_private_write(path, json.dumps(data, sort_keys=True))
        self._control_path = path

    def _write_status_file(self, plan: TorrentPlan) -> None:
        path = self._status_path_for()
        snapshot = self.metrics.get_snapshot()
        data = {
            "updated_at": time.time(),
            "job_id": self._job_id,
            "infohash_prefix": self._infohash[:12],
            "files_total": len(plan.files),
            "files_done": snapshot.get("items_done", 0),
            "total_bytes": snapshot.get("total_bytes", plan.total_size),
            "completed_bytes": snapshot.get("completed_bytes", 0),
            "current_bps": snapshot.get("current_bps", 0.0),
            "peak_bps": snapshot.get("peak_bps", 0.0),
            "instances": [
                {
                    "instance_id": i.instance_id,
                    "circuit_id": i.circuit_id,
                    "state": i.circuit.state.value,
                    "throughput_bps": self.metrics.get_circuit_throughput(i.circuit_id),
                    "done": i.done,
                }
                for i in self.instances
            ],
        }
        self._atomic_private_write(path, json.dumps(data, sort_keys=True))
        self._status_path = path

    @staticmethod
    def _atomic_private_write(path: Path, payload: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)

    def _remove_control_files(self) -> None:
        for path in (self._control_path, self._status_path):
            if path and path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass

    def _cleanup_staging(self) -> None:
        staging_root = self._staging_root
        if staging_root and staging_root.exists():
            shutil.rmtree(staging_root, ignore_errors=True)

    async def _stop_instances(self) -> None:
        """Stop qBittorrent without clearing instance paths needed for finalization."""
        if self._stopped:
            return
        for instance in self.instances:
            try:
                await instance.client.pause(instance.infohash)
            except Exception:
                pass
            try:
                await instance.client.delete(instance.infohash, delete_files=False)
            except Exception:
                pass
            try:
                await instance.process.stop()
            except Exception:
                pass
            try:
                await instance.client.close()
            except Exception:
                pass
            await self.pool.release(instance.circuit.circuit_id)
            self.event_bus.emit(
                EventType.QBITTORRENT_STOPPED,
                instance_id=instance.instance_id,
                status="stopped",
            )
        self._stopped = True

    async def close(self) -> None:
        """Stop every qBittorrent instance immediately and release its circuit."""
        await self._stop_instances()
        self.instances.clear()
        self._remove_control_files()


def find_control_file(directory: Path) -> Optional[Path]:
    """Return the newest live torrent control file in a directory."""
    if not directory.exists():
        return None
    files = list(directory.glob(".torpool_torrent_control_*.json"))
    if not files:
        return None
    return max(files, key=lambda path: path.stat().st_mtime)


def load_control_file(path: Path) -> dict[str, Any]:
    """Load a 0600 torrent control file and verify restrictive permissions."""
    if path.is_symlink():
        raise TorrentError("Refusing symlinked torrent control file")
    mode = path.stat().st_mode & 0o777
    if mode != 0o600:
        raise TorrentError("Torrent control file permissions are not 0600")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TorrentError("Torrent control file is malformed")
    return data


async def torrent_control_command(control_path: Path, command: str) -> dict[str, Any]:
    """Send pause/resume/remove to every live qBittorrent instance."""
    data = load_control_file(control_path)
    results: list[dict[str, Any]] = []
    for item in data.get("instances", []):
        client = QBittorrentClient(
            port=int(item["web_port"]),
            username=str(item["username"]),
            password=str(item["password"]),
        )
        try:
            await client.login()
            hashes = [str(torrent.get("hash", "")) for torrent in await client.torrents()]
            for infohash in filter(None, hashes):
                if command == "pause":
                    await client.pause(infohash)
                elif command == "resume":
                    await client.resume(infohash)
                elif command == "remove":
                    await client.delete(infohash, delete_files=False)
            results.append({"instance_id": item.get("instance_id"), "status": "ok"})
        except Exception as exc:
            results.append({"instance_id": item.get("instance_id"), "status": type(exc).__name__})
        finally:
            await client.close()
    if command == "remove":
        for key in ("instances",):
            data[key] = []
        data["removed"] = True
        TorrentSupervisor._atomic_private_write(control_path, json.dumps(data, sort_keys=True))
    return {"command": command, "results": results}
