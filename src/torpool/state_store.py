"""StateStore: SQLite-backed persistence for chunk completion bitmaps and crash recovery."""

import hashlib
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from torpool.sanitizer import sanitize_url_for_manifest


@dataclass
class ChunkRecord:
    """Represents a byte-range chunk in the download schedule."""

    chunk_id: int
    start_byte: int
    end_byte: int
    completed: bool = False
    retries: int = 0

    @property
    def length(self) -> int:
        return self.end_byte - self.start_byte + 1


@dataclass
class TorrentFileRecord:
    """A single content file inside a BitTorrent job."""

    file_index: int
    relative_path: str
    size: int
    assigned_instance: int = -1
    completed: bool = False
    sha256: str = ""

    @property
    def name(self) -> str:
        return self.relative_path


class StateStore:
    """
    Persists download metadata, chunk boundaries, and completion status in SQLite.
    Supports dynamic chunk splitting and crash-safe resume.
    """

    def __init__(self, state_file: Path) -> None:
        self.state_file = state_file
        self.state_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        self._init_db()
        if self.state_file.exists():
            os.chmod(self.state_file, 0o600)

    @staticmethod
    def state_path_for_url(output_dir: Path, url: str) -> Path:
        """Compute deterministic state DB filename from sanitized target URL."""
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        return output_dir / f".torpool_state_{url_hash}.sqlite"

    @staticmethod
    def state_path_for_torrent(output_dir: Path, source_digest: str) -> Path:
        """Compute deterministic state DB filename for a torrent source digest."""
        digest = hashlib.sha256(source_digest.encode("utf-8")).hexdigest()[:16]
        return output_dir / f".torpool_torrent_state_{digest}.sqlite"

    def _init_db(self) -> None:
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chunks (
                    chunk_id INTEGER PRIMARY KEY,
                    start_byte INTEGER NOT NULL,
                    end_byte INTEGER NOT NULL,
                    completed INTEGER NOT NULL DEFAULT 0,
                    retries INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS circuits_meta (
                    circuit_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS torrent_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS torrent_files (
                    file_index INTEGER PRIMARY KEY,
                    relative_path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    assigned_instance INTEGER NOT NULL DEFAULT -1,
                    completed INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS torrent_instances (
                    instance_id INTEGER PRIMARY KEY,
                    circuit_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    def initialize_job(self, url: str, total_size: int, chunks: list[ChunkRecord]) -> None:
        """Initialize state store for a new download job."""
        clean_url = sanitize_url_for_manifest(url)
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute("DELETE FROM metadata")
            conn.execute("DELETE FROM chunks")
            conn.execute("INSERT INTO metadata (key, value) VALUES ('url', ?)", (clean_url,))
            conn.execute(
                "INSERT INTO metadata (key, value) VALUES ('total_size', ?)", (str(total_size),)
            )
            conn.executemany(
                "INSERT INTO chunks (chunk_id, start_byte, end_byte, completed, retries) VALUES (?, ?, ?, ?, ?)",
                [
                    (c.chunk_id, c.start_byte, c.end_byte, int(c.completed), c.retries)
                    for c in chunks
                ],
            )
            conn.commit()

    def load_job(self) -> Optional[tuple[int, list[ChunkRecord]]]:
        """Load persisted total_size and chunk records for --resume."""
        with self._lock, sqlite3.connect(self.state_file) as conn:
            row = conn.execute("SELECT value FROM metadata WHERE key = 'total_size'").fetchone()
            if not row:
                return None
            total_size = int(row[0])
            rows = conn.execute(
                "SELECT chunk_id, start_byte, end_byte, completed, retries FROM chunks ORDER BY start_byte ASC"
            ).fetchall()
            chunks = [
                ChunkRecord(
                    chunk_id=r[0],
                    start_byte=r[1],
                    end_byte=r[2],
                    completed=bool(r[3]),
                    retries=r[4],
                )
                for r in rows
            ]
            return total_size, chunks

    def mark_chunk_done(self, chunk_id: int, retries: int) -> None:
        """Mark a chunk completed in SQLite."""
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute(
                "UPDATE chunks SET completed = 1, retries = ? WHERE chunk_id = ?",
                (retries, chunk_id),
            )
            conn.commit()

    def update_chunk_split(self, updated: ChunkRecord, new_second_half: ChunkRecord) -> None:
        """Persist a dynamic chunk split when adapting chunk size downward for a slow circuit."""
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute(
                "UPDATE chunks SET start_byte = ?, end_byte = ?, retries = ? WHERE chunk_id = ?",
                (updated.start_byte, updated.end_byte, updated.retries, updated.chunk_id),
            )
            conn.execute(
                "INSERT INTO chunks (chunk_id, start_byte, end_byte, completed, retries) VALUES (?, ?, ?, 0, 0)",
                (new_second_half.chunk_id, new_second_half.start_byte, new_second_half.end_byte),
            )
            conn.commit()

    def record_circuit_meta(self, circuit_id: str, state: str) -> None:
        """Persist circuit state snapshot."""
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO circuits_meta (circuit_id, state, updated_at) VALUES (?, ?, ?)",
                (circuit_id, state, time.time()),
            )
            conn.commit()

    def initialize_torrent_job(
        self,
        source_digest: str,
        infohash: str,
        total_size: int,
        files: list[TorrentFileRecord],
        instance_count: int,
    ) -> None:
        """Initialize or replace torrent resume metadata."""
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute("DELETE FROM torrent_meta")
            conn.execute("DELETE FROM torrent_files")
            meta = {
                "source_digest": source_digest,
                "infohash": infohash,
                "total_size": str(total_size),
                "instance_count": str(instance_count),
            }
            conn.executemany(
                "INSERT INTO torrent_meta (key, value) VALUES (?, ?)", list(meta.items())
            )
            conn.executemany(
                """
                INSERT INTO torrent_files
                    (file_index, relative_path, size, assigned_instance, completed, sha256)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        f.file_index,
                        f.relative_path,
                        f.size,
                        f.assigned_instance,
                        int(f.completed),
                        f.sha256,
                    )
                    for f in files
                ],
            )
            conn.commit()

    def load_torrent_job(self) -> Optional[tuple[dict[str, str], list[TorrentFileRecord]]]:
        """Load persisted torrent job metadata and file records, if present."""
        with self._lock, sqlite3.connect(self.state_file) as conn:
            meta_rows = conn.execute("SELECT key, value FROM torrent_meta").fetchall()
            if not meta_rows:
                return None
            meta = {str(k): str(v) for k, v in meta_rows}
            rows = conn.execute(
                """
                SELECT file_index, relative_path, size, assigned_instance, completed, sha256
                FROM torrent_files ORDER BY file_index ASC
                """
            ).fetchall()
            files = [
                TorrentFileRecord(
                    file_index=r[0],
                    relative_path=str(r[1]),
                    size=int(r[2]),
                    assigned_instance=int(r[3]),
                    completed=bool(r[4]),
                    sha256=str(r[5]),
                )
                for r in rows
            ]
            return meta, files

    def mark_torrent_file_done(self, file_index: int, sha256: str = "") -> None:
        """Mark a torrent content file complete in the resume database."""
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute(
                "UPDATE torrent_files SET completed = 1, sha256 = ? WHERE file_index = ?",
                (sha256, file_index),
            )
            conn.commit()

    def assign_torrent_file(self, file_index: int, instance_id: int) -> None:
        """Persist the qBittorrent instance assigned to a torrent file."""
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute(
                "UPDATE torrent_files SET assigned_instance = ? WHERE file_index = ?",
                (instance_id, file_index),
            )
            conn.commit()

    def record_torrent_instance(self, instance_id: int, circuit_id: str, state: str) -> None:
        """Persist the circuit/state mapping for a torrent instance."""
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO torrent_instances
                    (instance_id, circuit_id, state, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (instance_id, circuit_id, state, time.time()),
            )
            conn.commit()

    def remove(self) -> None:
        """Remove state file upon verified completion."""
        if self.state_file.exists():
            self.state_file.unlink()
