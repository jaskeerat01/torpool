"""RangeDownloader performing ranged HTTP transfers over SOCKS5h into preallocated files."""

import errno
import os
import secrets
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from torpool.circuit_pool import ManagedCircuit
from torpool.config import TOR_BROWSER_USER_AGENT, TorPoolConfig
from torpool.metrics import BandwidthLimiter, MetricsWindow
from torpool.state_store import ChunkRecord


class DownloadError(Exception):
    """Raised on chunk transfer failure."""

    def __init__(
        self,
        message: str,
        reason: str = "TRANSFER_ERR",
        status_code: int = 0,
        disk_full: bool = False,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.status_code = status_code
        self.disk_full = disk_full


class RangeDownloader:
    """
    Executes ranged HTTP requests through an assigned circuit's SOCKS5h proxy.
    Writes directly to the chunk's byte offset in a preallocated file.
    Verifies exact received byte count before marking complete.
    """

    def __init__(
        self,
        config: TorPoolConfig,
        metrics: MetricsWindow,
        bandwidth_limiter: BandwidthLimiter,
    ) -> None:
        self.config = config
        self.metrics = metrics
        self.bandwidth_limiter = bandwidth_limiter

    @staticmethod
    def preallocate_file(file_path: Path, total_size: int) -> None:
        """Create directory with 0700 perms and preallocate target file with 0600 perms."""
        file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(file_path.parent, 0o700)
        flags = os.O_CREAT | os.O_RDWR
        fd = os.open(file_path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            if total_size > 0:
                os.ftruncate(fd, total_size)
        finally:
            os.close(fd)

    @staticmethod
    def shred_file(file_path: Path) -> None:
        """Overwrite a temporary file with random bytes, flush, and unlink."""
        if not file_path.exists() or not file_path.is_file():
            return
        try:
            size = file_path.stat().st_size
            with file_path.open("r+b") as f:
                remaining = size
                block = 65536
                while remaining > 0:
                    to_write = min(block, remaining)
                    f.write(secrets.token_bytes(to_write))
                    remaining -= to_write
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            pass
        finally:
            try:
                file_path.unlink()
            except Exception:
                pass

    async def probe_target(self, url: str, circuit: ManagedCircuit) -> tuple[int, bool]:
        """
        Determine file size and range support via HEAD or Range: bytes=0-0 GET.
        Refuses cross-origin redirects without user confirmation.
        Returns (total_bytes, supports_ranges).
        """
        orig_host = urlparse(url).hostname
        async with httpx.AsyncClient(
            proxy=circuit.proxy_url if circuit.proxy_url else None,
            timeout=httpx.Timeout(self.config.circuit_timeout),
            headers={"User-Agent": TOR_BROWSER_USER_AGENT},
            follow_redirects=False,
            trust_env=False,
        ) as client:
            resp = await client.head(url)
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                new_host = urlparse(loc).hostname
                if new_host and new_host != orig_host:
                    raise DownloadError(
                        f"Refusing cross-domain redirect from '{orig_host}' to '{new_host}'. "
                        "For security, supply the final URL directly to 'torpool fetch'.",
                        reason="CROSS_DOMAIN_REDIRECT",
                    )

            accept_ranges = resp.headers.get("Accept-Ranges", "").lower() == "bytes"
            content_length = int(resp.headers.get("Content-Length", "-1"))

            # Verify with a 1-byte range GET if HEAD was ambiguous
            if not accept_ranges or content_length < 0:
                r_resp = await client.get(url, headers={"Range": "bytes=0-0"})
                if r_resp.status_code == 206:
                    accept_ranges = True
                    cr = r_resp.headers.get("Content-Range", "")
                    if "/" in cr:
                        total_str = cr.split("/")[-1].strip()
                        if total_str.isdigit():
                            content_length = int(total_str)
                elif r_resp.status_code == 200:
                    accept_ranges = False
                    content_length = int(r_resp.headers.get("Content-Length", "-1"))

            return content_length, accept_ranges

    async def download_chunk(
        self,
        url: str,
        chunk: ChunkRecord,
        circuit: ManagedCircuit,
        target_file: Optional[Path] = None,
        encrypted_session: Optional[Any] = None,
    ) -> float:
        """
        Download a single byte-range chunk via the circuit's SOCKS5h proxy and write at offset.
        If encrypted_session is provided, encrypts chunk in memory before writing ciphertext to disk.
        Returns measured chunk throughput in bytes/sec.
        """
        expected_len = chunk.length
        range_header = f"bytes={chunk.start_byte}-{chunk.end_byte}"
        t0 = time.monotonic()
        received = 0
        chunk_buf = bytearray() if encrypted_session is not None else None

        try:
            async with httpx.AsyncClient(
                proxy=circuit.proxy_url if circuit.proxy_url else None,
                timeout=httpx.Timeout(self.config.circuit_timeout),
                headers={
                    "User-Agent": TOR_BROWSER_USER_AGENT,
                    "Range": range_header,
                },
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream("GET", url) as resp:
                    if resp.status_code in (429, 503):
                        raise DownloadError(
                            f"Rate limited or service unavailable (HTTP {resp.status_code})",
                            reason=f"HTTP_{resp.status_code}",
                            status_code=resp.status_code,
                        )
                    if resp.status_code not in (200, 206):
                        raise DownloadError(
                            f"Unexpected HTTP status {resp.status_code}",
                            reason=f"HTTP_{resp.status_code}",
                            status_code=resp.status_code,
                        )

                    if encrypted_session is not None:
                        async for data in resp.aiter_bytes(chunk_size=65536):
                            if not data:
                                continue
                            await self.bandwidth_limiter.consume(len(data))
                            chunk_buf.extend(data)  # type: ignore[union-attr]
                            received += len(data)
                            self.metrics.record_bytes(circuit.circuit_id, len(data))
                    else:
                        assert target_file is not None
                        fd = os.open(target_file, os.O_RDWR)
                        try:
                            async for data in resp.aiter_bytes(chunk_size=65536):
                                if not data:
                                    continue
                                await self.bandwidth_limiter.consume(len(data))
                                os.pwrite(fd, data, chunk.start_byte + received)
                                received += len(data)
                                self.metrics.record_bytes(circuit.circuit_id, len(data))
                        finally:
                            os.close(fd)

        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise DownloadError(
                    "Disk full while writing chunk (ENOSPC)", reason="DISK_FULL", disk_full=True
                ) from exc
            raise DownloadError(f"I/O error: {exc}", reason="IO_ERROR") from exc
        except DownloadError:
            raise
        except httpx.TimeoutException as exc:
            raise DownloadError("Chunk transfer timed out", reason="TIMEOUT") from exc
        except Exception as exc:
            raise DownloadError(f"Stream disconnected: {exc}", reason="DISCONNECT") from exc

        if received != expected_len:
            raise DownloadError(
                f"Chunk length mismatch: expected {expected_len}, received {received}",
                reason="SIZE_MISMATCH",
            )

        if encrypted_session is not None and chunk_buf is not None:
            encrypted_session.write_chunk(chunk, bytes(chunk_buf))
            chunk_buf.clear()

        elapsed = max(0.001, time.monotonic() - t0)
        return float(received) / elapsed

    async def download_streaming_fallback(
        self,
        url: str,
        circuit: ManagedCircuit,
        target_file: Optional[Path] = None,
        encrypted_session: Optional[Any] = None,
    ) -> int:
        """
        Single-circuit streaming download fallback when server does not support HTTP Range requests.
        Returns total bytes written.
        """
        received = 0

        try:
            async with httpx.AsyncClient(
                proxy=circuit.proxy_url if circuit.proxy_url else None,
                timeout=httpx.Timeout(self.config.circuit_timeout),
                headers={"User-Agent": TOR_BROWSER_USER_AGENT},
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream("GET", url) as resp:
                    resp.raise_for_status()
                    if encrypted_session is not None:
                        block_idx = 0
                        async for data in resp.aiter_bytes(chunk_size=65536):
                            if not data:
                                continue
                            await self.bandwidth_limiter.consume(len(data))
                            blk_chunk = ChunkRecord(
                                chunk_id=block_idx,
                                start_byte=received,
                                end_byte=received + len(data) - 1,
                            )
                            encrypted_session.write_chunk(blk_chunk, data)
                            block_idx += 1
                            received += len(data)
                            self.metrics.record_bytes(circuit.circuit_id, len(data))
                    else:
                        assert target_file is not None
                        target_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        os.chmod(target_file.parent, 0o700)
                        fd = os.open(target_file, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
                        try:
                            os.fchmod(fd, 0o600)
                            async for data in resp.aiter_bytes(chunk_size=65536):
                                if not data:
                                    continue
                                await self.bandwidth_limiter.consume(len(data))
                                os.write(fd, data)
                                received += len(data)
                                self.metrics.record_bytes(circuit.circuit_id, len(data))
                        finally:
                            os.close(fd)
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise DownloadError(
                    "Disk full during streaming download (ENOSPC)",
                    reason="DISK_FULL",
                    disk_full=True,
                ) from exc
            raise DownloadError(f"I/O error: {exc}", reason="IO_ERROR") from exc

        return received
