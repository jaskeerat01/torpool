"""StateStore: SQLite-backed persistence for chunk completion bitmaps and crash recovery."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3
import threading
import time
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
            conn.commit()

    def initialize_job(self, url: str, total_size: int, chunks: list[ChunkRecord]) -> None:
        """Initialize state store for a new download job."""
        clean_url = sanitize_url_for_manifest(url)
        with self._lock, sqlite3.connect(self.state_file) as conn:
            conn.execute("DELETE FROM metadata")
            conn.execute("DELETE FROM chunks")
            conn.execute("INSERT INTO metadata (key, value) VALUES ('url', ?)", (clean_url,))
            conn.execute("INSERT INTO metadata (key, value) VALUES ('total_size', ?)", (str(total_size),))
            conn.executemany(
                "INSERT INTO chunks (chunk_id, start_byte, end_byte, completed, retries) VALUES (?, ?, ?, ?, ?)",
                [(c.chunk_id, c.start_byte, c.end_byte, int(c.completed), c.retries) for c in chunks],
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

    def remove(self) -> None:
        """Remove state file upon verified completion."""
        if self.state_file.exists():
            self.state_file.unlink()
