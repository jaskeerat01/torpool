"""Loopback-only qBittorrent Web API client and temporary process supervisor."""

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx

from torpool.config import TorPoolConfig
from torpool.events import EventBus, EventType


class QBittorrentError(Exception):
    """Raised when qBittorrent cannot be started, configured, or queried safely."""


def _free_loopback_port() -> int:
    """Ask the kernel for an unused loopback TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _pbkdf2_password(password: str, salt: bytes) -> str:
    """Return qBittorrent's salted PBKDF2-HMAC-SHA512 WebUI password format."""
    derived = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, 100_000, 64)
    return f"{base64.b64encode(salt).decode('ascii')}:{base64.b64encode(derived).decode('ascii')}"


def _write_profile_config(profile_dir: Path, web_port: int, username: str, password: str) -> Path:
    """Create a private qBittorrent profile with a loopback-only authenticated WebUI."""
    config_dir = profile_dir / "qBittorrent" / "config"
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(profile_dir, 0o700)
    os.chmod(profile_dir / "qBittorrent", 0o700)
    os.chmod(config_dir, 0o700)
    salt = secrets.token_bytes(16)
    password_hash = _pbkdf2_password(password, salt)
    config_path = config_dir / "qBittorrent.conf"
    content = f"""[LegalNotice]
Accepted=true

[Preferences]
WebUI\\Enabled=true
WebUI\\Address=127.0.0.1
WebUI\\Port={web_port}
WebUI\\Username={username}
WebUI\\Password_PBKDF2="@ByteArray({password_hash})"
WebUI\\LocalHostAuth=false
WebUI\\CSRFProtection=true
WebUI\\HostHeaderValidation=true
WebUI\\ClickjackingProtection=true
WebUI\\MaxAuthenticationFailCount=3
WebUI\\BanDuration=3600
WebUI\\UPnP=false
"""
    fd = os.open(config_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    return config_path


def secure_rmtree(path: Path) -> None:
    """Overwrite regular files then remove a temporary qBittorrent profile tree."""
    if not path.exists():
        return
    if path.is_file() or path.is_symlink() or not path.is_dir():
        with contextlib.suppress(Exception):
            size = path.stat().st_size
            if path.is_file() and not path.is_symlink():
                with path.open("r+b") as handle:
                    remaining = size
                    while remaining > 0:
                        block = min(65536, remaining)
                        handle.write(secrets.token_bytes(block))
                        remaining -= block
                    handle.flush()
                    os.fsync(handle.fileno())
        with contextlib.suppress(Exception):
            path.unlink()
        return
    for child in path.iterdir():
        secure_rmtree(child)
    with contextlib.suppress(Exception):
        path.rmdir()


@dataclass
class QBittorrentProcess:
    """A temporary qBittorrent process bound to one Tor circuit SOCKS listener."""

    executable: str
    profile_dir: Path
    web_port: int
    torrent_port: int
    username: str
    password: str
    process: Optional[asyncio.subprocess.Process] = field(default=None, repr=False)
    _stdout_task: Optional[asyncio.Task[None]] = field(default=None, repr=False)
    _stderr_task: Optional[asyncio.Task[None]] = field(default=None, repr=False)

    @classmethod
    def create(cls, executable: str, profile_dir: Path, web_port: int = 0) -> "QBittorrentProcess":
        """Allocate ports and credentials for a new temporary instance."""
        profile_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(profile_dir, 0o700)
        return cls(
            executable=executable,
            profile_dir=profile_dir,
            web_port=web_port or _free_loopback_port(),
            torrent_port=_free_loopback_port(),
            username=f"torpool_{secrets.token_hex(6)}",
            password=secrets.token_urlsafe(24),
        )

    def _child_env(self) -> dict[str, str]:
        """Build a minimal child environment without secrets or proxy variables."""
        home = str(self.profile_dir)
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": home,
            "XDG_CONFIG_HOME": home,
            "XDG_DATA_HOME": home,
            "XDG_CACHE_HOME": home,
            "TMPDIR": home,
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": "C.UTF-8",
            "QBT_NO_SPLASH": "1",
            "QT_QPA_PLATFORM": "offscreen",
        }
        return env

    async def start(self, startup_timeout: float = 30.0) -> "QBittorrentClient":
        """Start qBittorrent and wait for its loopback Web API to accept logins."""
        _write_profile_config(self.profile_dir, self.web_port, self.username, self.password)
        argv = [
            self.executable,
            f"--profile={self.profile_dir}",
            f"--webui-port={self.web_port}",
            f"--torrenting-port={self.torrent_port}",
            "--no-splash",
        ]
        previous_umask = os.umask(0o077)
        try:
            self.process = await asyncio.create_subprocess_exec(
                *argv,
                env=self._child_env(),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        finally:
            os.umask(previous_umask)
        self._stdout_task = asyncio.create_task(self._drain(self.process.stdout))
        self._stderr_task = asyncio.create_task(self._drain(self.process.stderr))

        client = QBittorrentClient(
            port=self.web_port, username=self.username, password=self.password
        )
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if self.process.returncode is not None:
                raise QBittorrentError(
                    f"qBittorrent exited during startup (code={self.process.returncode})"
                )
            try:
                await client.login()
                return client
            except Exception:
                await asyncio.sleep(0.2)
        await client.close()
        await self.stop()
        raise QBittorrentError("Timed out waiting for qBittorrent loopback Web API")

    @staticmethod
    async def _drain(stream: Optional[asyncio.StreamReader]) -> None:
        """Discard child output; it may contain peer addresses or tracker URLs."""
        if stream is None:
            return
        with contextlib.suppress(Exception):
            while await stream.readline():
                pass

    async def stop(self) -> None:
        """Ask qBittorrent to shut down, then terminate/kill and remove the profile."""
        if self.process and self.process.returncode is None:
            client = QBittorrentClient(
                port=self.web_port, username=self.username, password=self.password
            )
            with contextlib.suppress(Exception):
                await client.login()
                await client.shutdown()
            await client.close()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=8.0)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    self.process.terminate()
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        self.process.kill()
                    with contextlib.suppress(Exception):
                        await self.process.wait()
        for task in (self._stdout_task, self._stderr_task):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self.process = None
        secure_rmtree(self.profile_dir)


class QBittorrentClient:
    """Typed async client for the official qBittorrent Web API over loopback."""

    def __init__(
        self,
        port: int,
        username: str,
        password: str,
        timeout: float = 15.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if not (0 < port < 65536):
            raise QBittorrentError("qBittorrent Web API port is invalid")
        base_url = f"http://127.0.0.1:{port}"
        self._username = username
        self._password = password
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(timeout),
            headers={"Referer": base_url, "Origin": base_url},
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )
        self._logged_in = False

    async def close(self) -> None:
        """Close the underlying loopback HTTP client."""
        await self._client.aclose()

    async def login(self) -> None:
        """Authenticate with the loopback Web UI and retain its SID cookie."""
        resp = await self._client.post(
            "/api/v2/auth/login",
            data={"username": self._username, "password": self._password},
        )
        if resp.status_code != 200 or resp.text.strip() != "Ok.":
            raise QBittorrentError("qBittorrent Web API authentication failed")
        self._logged_in = True

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        if not self._logged_in:
            await self.login()
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            raise QBittorrentError(f"qBittorrent API request failed (status={resp.status_code})")
        return resp

    async def version(self) -> str:
        """Return the qBittorrent version string."""
        resp = await self._request("GET", "/api/v2/app/version")
        return resp.text.strip()

    async def preferences(self) -> dict[str, Any]:
        """Read the full qBittorrent preference dictionary."""
        resp = await self._request("GET", "/api/v2/app/preferences")
        data = resp.json()
        if not isinstance(data, dict):
            raise QBittorrentError("qBittorrent preferences response was not an object")
        return data

    async def set_preferences(self, preferences: dict[str, Any]) -> None:
        """Apply a partial qBittorrent preference dictionary."""
        await self._request(
            "POST",
            "/api/v2/app/setPreferences",
            data={"json": json.dumps(preferences, separators=(",", ":"))},
        )

    async def apply_and_verify(
        self, preferences: dict[str, Any], expected: "PreferenceExpectation"
    ) -> dict[str, Any]:
        """Apply preferences, read them back, and fail closed on any mismatch."""
        try:
            await self.set_preferences(preferences)
            current = await self.preferences()
            validate_preferences(current, expected)
            return current
        except QBittorrentError:
            # qBittorrent 4.x may expect an integer proxy type; retry once with
            # the authenticated SOCKS5 enum value, then require a full read-back.
            alternative = dict(preferences)
            alternative["proxy_type"] = 4
            await self.set_preferences(alternative)
            current = await self.preferences()
            validate_preferences(current, expected)
            return current

    async def add_torrent(
        self,
        source: str,
        save_path: Path,
        paused: bool,
        torrent_bytes: Optional[bytes] = None,
    ) -> None:
        """Add a magnet URI or raw .torrent file to qBittorrent."""
        data: dict[str, Any] = {
            "savepath": str(save_path),
            "paused": "true" if paused else "false",
            "skip_checking": "false",
            "autoTMM": "false",
            "sequentialDownload": "false",
            "firstLastPiecePrio": "false",
            "root_folder": "true",
        }
        if torrent_bytes is not None:
            files = {"torrents": ("torpool.torrent", torrent_bytes, "application/x-bittorrent")}
            await self._request("POST", "/api/v2/torrents/add", data=data, files=files)
        else:
            data["urls"] = source
            await self._request("POST", "/api/v2/torrents/add", data=data)

    async def torrents(self) -> list[dict[str, Any]]:
        """Return all torrents from /torrents/info."""
        resp = await self._request("GET", "/api/v2/torrents/info")
        data = resp.json()
        if not isinstance(data, list):
            raise QBittorrentError("qBittorrent torrent list was not an array")
        return [dict(item) for item in data]

    async def torrent(self, infohash: str) -> Optional[dict[str, Any]]:
        """Return a single torrent record by infohash, if present."""
        for item in await self.torrents():
            if str(item.get("hash", "")).lower() == infohash.lower():
                return item
        return None

    async def files(self, infohash: str) -> list[dict[str, Any]]:
        """Return the content-file list for a torrent."""
        resp = await self._request("GET", "/api/v2/torrents/files", params={"hash": infohash})
        data = resp.json()
        if not isinstance(data, list):
            raise QBittorrentError("qBittorrent file list was not an array")
        return [dict(item) for item in data]

    async def piece_states(self, infohash: str) -> list[int]:
        """Return piece completion states when the API supports it."""
        with contextlib.suppress(Exception):
            resp = await self._request(
                "GET", "/api/v2/torrents/pieceStates", params={"hash": infohash}
            )
            data = resp.json()
            if isinstance(data, list):
                return [int(v) for v in data]
        return []

    async def set_file_priorities(
        self, infohash: str, selected: set[int], all_indexes: list[int]
    ) -> None:
        """Select exactly the assigned content files and skip all others."""
        selected_ids = [str(i) for i in sorted(selected)]
        skipped_ids = [str(i) for i in sorted(set(all_indexes) - selected)]
        if selected_ids:
            await self._request(
                "POST",
                "/api/v2/torrents/filePrio",
                data={
                    "hash": infohash,
                    "id": "|".join(selected_ids),
                    "priority": "1",
                },
            )
        if skipped_ids:
            await self._request(
                "POST",
                "/api/v2/torrents/filePrio",
                data={
                    "hash": infohash,
                    "id": "|".join(skipped_ids),
                    "priority": "0",
                },
            )

    async def set_upload_limit(self, infohash: str, limit: int = 1) -> None:
        """Apply the minimum per-torrent upload rate as a zero-upload backstop."""
        await self._request(
            "POST",
            "/api/v2/torrents/setUploadLimit",
            data={"hashes": infohash, "limit": str(limit)},
        )

    async def set_download_limit(self, infohash: str, limit: int) -> None:
        """Apply a per-torrent download limit in bytes/second."""
        await self._request(
            "POST",
            "/api/v2/torrents/setDownloadLimit",
            data={"hashes": infohash, "limit": str(limit)},
        )

    async def pause(self, infohash: str) -> None:
        """Stop a torrent (qBittorrent 5.x) with a pause fallback for 4.x."""
        try:
            await self._request("POST", "/api/v2/torrents/stop", data={"hashes": infohash})
        except QBittorrentError:
            await self._request("POST", "/api/v2/torrents/pause", data={"hashes": infohash})

    async def resume(self, infohash: str) -> None:
        """Start a torrent (qBittorrent 5.x) with a resume fallback for 4.x."""
        try:
            await self._request("POST", "/api/v2/torrents/start", data={"hashes": infohash})
        except QBittorrentError:
            await self._request("POST", "/api/v2/torrents/resume", data={"hashes": infohash})

    async def delete(self, infohash: str, delete_files: bool = False) -> None:
        """Remove a torrent from qBittorrent, optionally deleting its files."""
        await self._request(
            "POST",
            "/api/v2/torrents/delete",
            data={
                "hashes": infohash,
                "deleteFiles": "true" if delete_files else "false",
            },
        )

    async def transfer_info(self) -> dict[str, Any]:
        """Return global transfer counters and rates."""
        resp = await self._request("GET", "/api/v2/transfer/info")
        data = resp.json()
        if not isinstance(data, dict):
            raise QBittorrentError("qBittorrent transfer info was not an object")
        return data

    async def shutdown(self) -> None:
        """Request qBittorrent application shutdown."""
        with contextlib.suppress(Exception):
            await self._request("POST", "/api/v2/app/shutdown")


@dataclass(frozen=True)
class PreferenceExpectation:
    """Expected security-critical qBittorrent preferences after read-back."""

    proxy_port: int
    proxy_username: str
    save_path: str
    listen_port: int
    bind_interface: str
    web_port: int


def build_torrent_preferences(
    config: TorPoolConfig,
    proxy_username: str,
    proxy_password: str,
    listener_port: int,
    save_path: Path,
    listen_port: int,
    web_port: int,
    download_limit_bytes_s: int = 0,
) -> dict[str, Any]:
    """
    Build the conservative qBittorrent preference dictionary for one circuit.

    Uploading is prohibited: upload slots are requested as zero and the upload
    rate is pinned to qBittorrent's minimum positive value. The per-torrent
    limit is separately set to 1 byte/s by ``set_upload_limit``.
    """
    return {
        "proxy_type": "SOCKS5",
        "proxy_ip": "127.0.0.1",
        "proxy_port": listener_port,
        "proxy_auth_enabled": True,
        "proxy_username": proxy_username,
        "proxy_password": proxy_password,
        "proxy_hostname_lookup": True,
        "proxy_peer_connections": True,
        "proxy_bittorrent": True,
        "proxy_rss": True,
        "proxy_misc": True,
        "anonymous_mode": True,
        "dht": False,
        "pex": config.pex_enabled,
        "lsd": False,
        "upnp": False,
        "random_port": False,
        "listen_port": listen_port,
        "current_network_interface": config.torrent_bind_interface,
        "bittorrent_protocol": 1,
        "max_uploads": 0,
        "max_uploads_per_torrent": 0,
        # qBittorrent normalizes positive global limits <=1024 to 1 KiB/s.
        # The exact 1 byte/s backstop is applied per torrent in set_upload_limit().
        "up_limit": 1,
        "max_ratio": 0,
        "max_ratio_enabled": True,
        "max_ratio_act": 1,
        "max_seeding_time": 0,
        "max_seeding_time_enabled": True,
        "queueing_enabled": False,
        "save_path": str(save_path),
        "temp_path_enabled": False,
        "preallocate_all": False,
        "start_paused_enabled": False,
        "auto_tmm_enabled": False,
        "max_connec": config.torrent_max_connections,
        "max_connec_per_torrent": (
            config.per_host_concurrency
            if config.per_host_concurrency > 0
            else config.torrent_max_connections
        ),
        "dl_limit": max(0, int(download_limit_bytes_s)),
        "web_ui_address": "127.0.0.1",
        "web_ui_port": web_port,
        "web_ui_upnp": False,
        "web_ui_csrf_protection_enabled": True,
        "web_ui_clickjacking_protection_enabled": True,
        "web_ui_host_header_validation_enabled": True,
        "web_ui_secure_cookie_enabled": False,
        "bypass_local_auth": False,
        "bypass_auth_subnet_whitelist_enabled": False,
    }


def validate_preferences(prefs: dict[str, Any], expected: PreferenceExpectation) -> None:
    """Fail closed when qBittorrent did not retain the required OPSEC settings."""
    proxy_type = prefs.get("proxy_type")
    if proxy_type not in ("SOCKS5", 4, 2):
        raise QBittorrentError("qBittorrent proxy type is not SOCKS5")
    if prefs.get("proxy_ip") != "127.0.0.1":
        raise QBittorrentError("qBittorrent proxy is not bound to loopback")
    if int(prefs.get("proxy_port", 0)) != expected.proxy_port:
        raise QBittorrentError("qBittorrent proxy port does not match the circuit listener")
    if prefs.get("proxy_auth_enabled") is not True:
        raise QBittorrentError("qBittorrent proxy authentication is not enabled")
    if prefs.get("proxy_username") != expected.proxy_username:
        raise QBittorrentError("qBittorrent proxy username does not match the circuit")
    for key in ("proxy_hostname_lookup", "proxy_peer_connections", "proxy_bittorrent"):
        if prefs.get(key) is not True:
            raise QBittorrentError(f"qBittorrent preference {key} is not enabled")
    for key in ("dht", "lsd", "upnp"):
        if prefs.get(key) is not False:
            raise QBittorrentError(f"qBittorrent preference {key} is not disabled")
    if prefs.get("anonymous_mode") is not True:
        raise QBittorrentError("qBittorrent anonymous mode is not enabled")
    if int(prefs.get("bittorrent_protocol", 0)) != 1:
        raise QBittorrentError("qBittorrent is not restricted to TCP peer transport")
    up_limit = int(prefs.get("up_limit", -1))
    if up_limit <= 0 or up_limit > 1024:
        raise QBittorrentError("qBittorrent upload rate limit is not pinned to the minimum")
    max_uploads = int(prefs.get("max_uploads", -1))
    max_uploads_per_torrent = int(prefs.get("max_uploads_per_torrent", -1))
    # qBittorrent normalizes a request of 0 to its -1 "not configured" sentinel.
    # Any positive slot count is rejected; the uploaded-byte counter is authoritative.
    if max_uploads > 0 or max_uploads_per_torrent > 0:
        raise QBittorrentError("qBittorrent upload slots are not disabled")
    if prefs.get("max_ratio_enabled") is not True or float(prefs.get("max_ratio", -1)) != 0.0:
        raise QBittorrentError("qBittorrent share ratio removal is not configured")
    if int(prefs.get("max_ratio_act", -1)) != 1:
        raise QBittorrentError("qBittorrent share action is not remove")
    if prefs.get("max_seeding_time_enabled") is not True:
        raise QBittorrentError("qBittorrent seeding-time removal is not enabled")
    if int(prefs.get("max_seeding_time", -1)) != 0:
        raise QBittorrentError("qBittorrent seeding time is not zero")
    if prefs.get("web_ui_address") != "127.0.0.1":
        raise QBittorrentError("qBittorrent Web UI is not bound to loopback")
    if int(prefs.get("web_ui_port", 0)) != expected.web_port:
        raise QBittorrentError("qBittorrent Web UI port mismatch")
    if prefs.get("web_ui_upnp") is not False:
        raise QBittorrentError("qBittorrent Web UI UPnP is not disabled")
    if prefs.get("current_network_interface") != expected.bind_interface:
        raise QBittorrentError("qBittorrent is not bound to the configured loopback interface")
    if str(prefs.get("save_path", "")) != expected.save_path:
        raise QBittorrentError("qBittorrent save path mismatch")
    if int(prefs.get("listen_port", 0)) != expected.listen_port:
        raise QBittorrentError("qBittorrent listen port mismatch")


def qbittorrent_location(executable: str) -> Optional[str]:
    """Return the resolved qBittorrent executable path, if present."""
    candidate = Path(executable).expanduser()
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return shutil.which(executable)


def qbittorrent_version(executable: str) -> Optional[str]:
    """Query a local qBittorrent binary version without network activity."""
    import subprocess

    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": os.environ.get("PATH", ""),
                "QT_QPA_PLATFORM": "offscreen",
                "LANG": "C.UTF-8",
            },
        )
    except Exception:
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0].strip() if output else None


def qbittorrent_start_event(bus: EventBus, instance_id: int, version: str) -> None:
    """Emit a sanitized qBittorrent startup event."""
    bus.emit(EventType.QBITTORRENT_STARTED, instance_id=instance_id, version=version)
