"""CLI entry point built with Typer, managing signals, authorization notice, and subcommands."""

import asyncio
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from torpool.circuit_pool import CircuitPool
from torpool.config import ConfigError, ConfigLoader, TorPoolConfig
from torpool.dashboard import Dashboard
from torpool.downloader import RangeDownloader
from torpool.events import EventBus, EventType, SanitizedLogWriter, TerminalVerboseRenderer
from torpool.health_monitor import HealthMonitor
from torpool.metrics import BandwidthLimiter, MetricsWindow
from torpool.qbittorrent import (
    PreferenceExpectation,
    QBittorrentError,
    QBittorrentProcess,
    build_torrent_preferences,
    qbittorrent_location,
    qbittorrent_version,
)
from torpool.sanitizer import clear_proxy_env, sanitize_log_text
from torpool.scheduler import ChunkScheduler, SchedulerError
from torpool.state_store import StateStore
from torpool.throttle import CircuitBuildThrottle
from torpool.tor_controller import RelayInfo, TorController, TorError
from torpool.torrent_manager import (
    TorrentError,
    TorrentSource,
    TorrentSupervisor,
    find_control_file,
    load_control_file,
    parse_torrent_source,
    torrent_control_command,
)
from torpool.verifier import IntegrityVerifier, VerificationError

app = typer.Typer(
    name="torpool",
    help="Multi-circuit Tor file downloader for authorized defensive threat-intelligence analysis.",
    add_completion=False,
)
circuits_app = typer.Typer(help="Inspect and rotate pooled Tor circuits.")
app.add_typer(circuits_app, name="circuits")
torrent_app = typer.Typer(help="Inspect and control a running torrent download job.")
app.add_typer(torrent_app, name="torrent")

err_console = Console(stderr=True)

AUTHORIZATION_NOTICE = """
================================================================================
                        TORPOOL AUTHORIZATION NOTICE
================================================================================
This tool is strictly for retrieving content that you (the operator) are
legally and contractually authorized to access—such as your organization's own
data, published research datasets, or sources covered by a formal data-sharing
agreement for defensive threat-intelligence analysis.

You must NOT use this tool to obtain data from sources you have no right to
access, interact with illicit marketplaces, or evade access controls.
================================================================================
"""


def parse_size(size_str: str) -> int:
    """Parse human-readable byte size strings like '10M', '512K', or raw integers."""
    s = size_str.strip().upper()
    multipliers = {
        "K": 1024,
        "KB": 1024,
        "KIB": 1024,
        "M": 1024**2,
        "MB": 1024**2,
        "MIB": 1024**2,
        "G": 1024**3,
        "GB": 1024**3,
        "GIB": 1024**3,
    }
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if s.endswith(suffix):
            return int(float(s[: -len(suffix)].strip()) * mult)
    return int(s)


def ensure_authorized(cfg: TorPoolConfig) -> None:
    """Prompt the operator on first run to confirm authorization and store in config."""
    if cfg.authorized_confirmed or os.environ.get("TORPOOL_ACCEPT_AUTH") == "1":
        return
    if not sys.stdin.isatty():
        err_console.print(
            "[red]Authorization not confirmed. Run `uv run torpool init` first.[/red]"
        )
        raise typer.Exit(code=1)

    err_console.print(AUTHORIZATION_NOTICE)
    confirmed = typer.confirm(
        "Do you confirm that you are authorized to access and retrieve the target content for your stated purpose?"
    )
    if not confirmed:
        err_console.print("[red]Authorization declined. Exiting.[/red]")
        raise typer.Exit(code=1)
    ConfigLoader.save_authorization(cfg.config_path)
    cfg.authorized_confirmed = True


@app.command("init")
def cmd_init(
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
) -> None:
    """Initialize TorPool configuration, quarantine directory, and operator authorization."""
    clear_proxy_env()
    cfg = ConfigLoader.load(config_path=config_file)
    err_console.print(AUTHORIZATION_NOTICE)
    if not cfg.authorized_confirmed:
        confirmed = typer.confirm(
            "Do you confirm that you are authorized to access and retrieve the target content for your stated purpose?"
        )
        if not confirmed:
            raise typer.Exit(code=1)
        ConfigLoader.save_authorization(cfg.config_path)

    cfg.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cfg.output_dir, 0o700)
    cfg.temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cfg.temp_dir, 0o700)
    cfg.effective_state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cfg.effective_state_dir, 0o700)
    cfg.qbittorrent_temp_profile_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cfg.qbittorrent_temp_profile_dir, 0o700)
    err_console.print(
        f"[green]Initialized TorPool config at {cfg.config_path} and quarantine at {cfg.output_dir}[/green]"
    )


@app.command("doctor")
def cmd_doctor(
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
    skip_torrent: bool = typer.Option(
        False, "--skip-torrent", help="Skip qBittorrent validation for HTTP-only deployments"
    ),
) -> None:
    """
    Verify Tor daemon reachability, TOR_CONTROL_PASSWORD authentication,
    100% bootstrap status, SOCKS port reachability, directory permissions,
    qBittorrent availability, and mandatory preference read-back.
    Never echoes the control password.
    """
    clear_proxy_env()
    try:
        cfg = ConfigLoader.load(config_path=config_file)
        _ = cfg.get_control_password()
    except ConfigError as exc:
        err_console.print(f"[red][DOCTOR FAIL] Configuration/Auth check: {exc}[/red]")
        raise typer.Exit(code=1)

    bus = EventBus()
    ctrl = TorController(cfg, bus)
    try:
        ctrl.connect_and_verify()
    except TorError as exc:
        err_console.print(f"[red][DOCTOR FAIL] Tor Control verification failed: {exc}[/red]")
        raise typer.Exit(code=1)

    try:
        # Check SOCKS listener reachability
        try:
            with socket.create_connection((cfg.tor_socks_host, cfg.socks_port_base), timeout=3.0):
                pass
        except Exception as exc:
            err_console.print(
                f"[red][DOCTOR FAIL] Tor SOCKS port {cfg.tor_socks_host}:{cfg.socks_port_base} unreachable: {exc}[/red]"
            )
            raise typer.Exit(code=1)

        # Check quarantine permissions
        cfg.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(cfg.output_dir, 0o700)
        mode = cfg.output_dir.stat().st_mode & 0o777
        if mode != 0o700:
            err_console.print(
                f"[red][DOCTOR FAIL] Quarantine directory {cfg.output_dir} permissions are {oct(mode)}, expected 0o700[/red]"
            )
            raise typer.Exit(code=1)

        if cfg.circuit_creation_delay < 0.5:
            err_console.print(
                "[red][DOCTOR FAIL] circuit_creation_delay is below the mandatory 0.5s minimum[/red]"
            )
            raise typer.Exit(code=1)

        if not skip_torrent:
            executable = qbittorrent_location(cfg.qbittorrent_executable)
            if not executable:
                err_console.print(
                    f"[red][DOCTOR FAIL] qBittorrent executable not found: {cfg.qbittorrent_executable}[/red]"
                )
                raise typer.Exit(code=1)
            version = qbittorrent_version(executable)
            if not version:
                err_console.print("[red][DOCTOR FAIL] qBittorrent did not report a version[/red]")
                raise typer.Exit(code=1)
            try:
                asyncio.run(_doctor_torrent_check(cfg, ctrl, bus, executable))
            except Exception as exc:
                err_console.print(
                    f"[red][DOCTOR FAIL] qBittorrent/Tor SOCKS verification failed: {exc}[/red]"
                )
                raise typer.Exit(code=1)
            err_console.print(
                f"[green][DOCTOR OK] qBittorrent {version} started with verified SOCKS5 preferences.[/green]"
            )

        err_console.print(
            "[green][DOCTOR OK] Tor control auth, 100% bootstrap, SOCKS listener, permissions, "
            "and circuit-creation throttling verified.[/green]"
        )
    finally:
        ctrl.close()


async def _doctor_torrent_check(
    cfg: TorPoolConfig,
    ctrl: TorController,
    bus: EventBus,
    executable: str,
) -> None:
    """Start one circuit and one temporary qBittorrent instance, then verify prefs."""
    metrics = MetricsWindow(graph_window_seconds=cfg.graph_window)
    pool = CircuitPool(cfg, ctrl, bus, metrics)
    process: Optional[QBittorrentProcess] = None
    client = None
    try:
        cfg.temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(cfg.temp_dir, 0o700)
        await pool.initialize_pool(1)
        circuit = await pool.acquire()
        if not circuit:
            raise TorError("No circuit available for qBittorrent doctor check")
        profile_dir = cfg.qbittorrent_temp_profile_dir / f"doctor-{os.getpid()}-{int(time.time())}"
        process = QBittorrentProcess.create(executable, profile_dir, web_port=0)
        client = await process.start()
        expected = PreferenceExpectation(
            proxy_port=circuit.listener_port,
            proxy_username=circuit.socks_user,
            save_path=str(cfg.temp_dir),
            listen_port=process.torrent_port,
            bind_interface=cfg.torrent_bind_interface,
            web_port=process.web_port,
        )
        prefs = build_torrent_preferences(
            cfg,
            circuit.socks_user,
            circuit.socks_pass,
            circuit.listener_port,
            cfg.temp_dir,
            process.torrent_port,
            process.web_port,
            0,
        )
        await client.apply_and_verify(prefs, expected)
        await pool.release(circuit.circuit_id)
    finally:
        if client is not None:
            await client.close()
        if process is not None:
            await process.stop()
        await pool.close_all()


@app.command("verify")
def cmd_verify(
    file: Path = typer.Argument(..., exists=True, readable=True, help="File to hash and verify"),
    sha256: Optional[str] = typer.Option(None, "--sha256", help="Expected SHA-256 hex digest"),
) -> None:
    """Compute SHA-256 of a quarantined file and optionally compare against expected digest."""
    digest = IntegrityVerifier.compute_sha256(file)
    if sha256:
        if digest.lower() == sha256.strip().lower():
            err_console.print(f"[green]VERIFIED: {file.name} matches SHA-256 {digest}[/green]")
            return
        err_console.print(f"[red]MISMATCH: expected {sha256}, calculated {digest}[/red]")
        raise typer.Exit(code=1)
    err_console.print(f"SHA-256 ({file.name}): {digest}")


@app.command("status")
def cmd_status(
    graph: bool = typer.Option(False, "--graph", help="Display live bandwidth graph"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
    out: Optional[Path] = typer.Option(None, "--out", help="Quarantine output directory to check"),
) -> None:
    """
    Display current pool throughput, bytes completed, ETA, and per-circuit status.
    Inspects live status files written by running fetch jobs.
    """
    clear_proxy_env()
    cfg = ConfigLoader.load(
        config_path=config_file, cli_overrides={"graph": graph, "output_dir": out}
    )

    # Check for live status files in output_dir
    status_files = (
        list(cfg.output_dir.glob(".torpool_status_*.json")) if cfg.output_dir.exists() else []
    )
    if not status_files:
        torrent_status_files = [
            path
            for directory in {cfg.effective_state_dir, cfg.output_dir}
            if directory.exists()
            for path in directory.glob(".torpool_torrent_status_*.json")
        ]
        if torrent_status_files:
            latest = max(torrent_status_files, key=lambda path: path.stat().st_mtime)
            try:
                data = json.loads(latest.read_text(encoding="utf-8"))
                table = Table(title="Live Torrent Status")
                table.add_column("Property", style="bold")
                table.add_column("Value")
                table.add_row("Info-hash", str(data.get("infohash_prefix", "unknown")))
                table.add_row(
                    "Files",
                    f"{data.get('files_done', 0)}/{data.get('files_total', 0)}",
                )
                table.add_row(
                    "Progress",
                    f"{data.get('completed_bytes', 0)}/{data.get('total_bytes', 0)} B",
                )
                table.add_row(
                    "Rate",
                    f"{float(data.get('current_bps', 0.0)) / 1024.0:.1f} KiB/s",
                )
                err_console.print(table)
                return
            except Exception:
                pass
    if status_files:
        latest_file = max(status_files, key=lambda f: f.stat().st_mtime)
        try:
            data = json.loads(latest_file.read_text(encoding="utf-8"))
            table = Table(title="Live Download Status")
            table.add_column("Property", style="bold")
            table.add_column("Value")
            table.add_row("Target URL", data.get("url", "unknown"))
            total = data.get("total_bytes", 0)
            completed = data.get("completed_bytes", 0)
            pct = (completed * 100.0 / total) if total > 0 else 0.0
            table.add_row("Progress", f"{completed}/{total} B ({pct:.1f}%)")
            table.add_row(
                "Rate",
                f"{data.get('current_bps', 0.0) / 1024.0:.1f} KiB/s (Avg: {data.get('avg_bps', 0.0) / 1024.0:.1f} KiB/s)",
            )
            eta_s = data.get("eta_s", -1.0)
            table.add_row("ETA", f"{eta_s:.1f}s" if eta_s >= 0 else "N/A")
            table.add_row("Healthy Circuits", str(data.get("healthy_count", 0)))
            err_console.print(table)

            circs = data.get("circuits", [])
            if circs:
                circ_table = Table(title="Circuit Slot Status")
                circ_table.add_column("Slot ID")
                circ_table.add_column("Tor Circ")
                circ_table.add_column("State")
                circ_table.add_column("Throughput")
                circ_table.add_column("Latency")
                for c in circs:
                    circ_table.add_row(
                        str(c.get("circuit_id")),
                        str(c.get("tor_circuit_id") or "AUTO"),
                        str(c.get("state")),
                        f"{c.get('throughput_bps', 0.0) / 1024.0:.1f} KiB/s",
                        f"{c.get('latency_s', 0.0):.3f}s",
                    )
                err_console.print(circ_table)
            return
        except Exception:
            pass

    metrics = MetricsWindow(graph_window_seconds=cfg.graph_window)
    dash = Dashboard(cfg, metrics)
    size = err_console.size
    err_console.print(dash.render_frame(width=size.width, height=size.height))
    err_console.print(
        "[dim]Note: 'torpool status' checks for active downloads in the output directory. "
        "To view live metrics during a fetch, pass the '--graph' flag.[/dim]"
    )


@app.command("decrypt")
def cmd_decrypt(
    encrypted_file: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to encrypted file (.enc)"
    ),
    out: Path = typer.Option(..., "--out", help="Destination path for decrypted plaintext file"),
    index_file: Optional[Path] = typer.Option(
        None, "--index", help="Path to authenticated index file (.idx)"
    ),
    key_file: Optional[Path] = typer.Option(None, "--key-file", help="Path to passphrase/key file"),
) -> None:
    """
    Recover plaintext from an encrypted quarantine file to a user-chosen destination with 0600 permissions.
    Never logs or stores the passphrase.
    """
    passphrase = ""
    if key_file:
        if not key_file.exists() or not key_file.is_file():
            err_console.print(f"[red]Specified key-file {key_file} does not exist[/red]")
            raise typer.Exit(code=1)
        passphrase = key_file.read_text(encoding="utf-8").strip()
    elif "TORPOOL_PASSPHRASE" in os.environ:
        passphrase = os.environ["TORPOOL_PASSPHRASE"]
    elif sys.stdin.isatty():
        passphrase = typer.prompt("Enter decryption passphrase", hide_input=True)
    else:
        err_console.print(
            "[red]No passphrase supplied via --key-file, TORPOOL_PASSPHRASE, or interactive prompt.[/red]"
        )
        raise typer.Exit(code=1)

    try:
        recovered_bytes, digest = IntegrityVerifier.decrypt_file(
            enc_path=encrypted_file,
            out_path=out,
            passphrase=passphrase,
            idx_path=index_file,
        )
        err_console.print(
            f"[green][DECRYPT OK] Recovered {recovered_bytes} bytes to {out} (SHA-256: {digest})[/green]"
        )
    except VerificationError as exc:
        err_console.print(f"[red][DECRYPT FAIL] {exc}[/red]")
        raise typer.Exit(code=1)


@circuits_app.command("list")
def cmd_circuits_list(
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
) -> None:
    """
    List active Tor circuits via the control port.
    Note: opens an independent control connection and does not inspect in-flight fetch pool slots.
    """
    clear_proxy_env()
    try:
        cfg = ConfigLoader.load(config_path=config_file)
        bus = EventBus()
        ctrl = TorController(cfg, bus)
        ctrl.connect_and_verify()
        try:
            table = Table(title="Active Tor Circuits")
            table.add_column("ID")
            table.add_column("Status")
            table.add_column("Path")
            if ctrl._controller:
                for circ in ctrl._controller.get_circuits():
                    path_str = " -> ".join(f"{nick}[${fp[:8]}]" for fp, nick in circ.path)
                    table.add_row(str(circ.id), str(circ.status), path_str)
            err_console.print(table)
        finally:
            ctrl.close()
    except (ConfigError, TorError) as exc:
        err_console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(code=1)


@circuits_app.command("rotate")
def cmd_circuits_rotate(
    circuit_id: str = typer.Argument(..., help="Circuit ID to close and rotate"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
) -> None:
    """
    Close a specific Tor circuit ID and build a replacement.
    Note: operates independently on the Tor daemon and does not mutate active fetch pool slots.
    """
    clear_proxy_env()
    try:
        cfg = ConfigLoader.load(config_path=config_file)
        bus = EventBus()
        ctrl = TorController(cfg, bus)
        ctrl.connect_and_verify()
        try:
            new_id, path, dur = asyncio.run(_rotate_circuit(cfg, bus, ctrl, circuit_id))
            path_str = " -> ".join(r.short_str for r in path)
            err_console.print(
                f"[green]Rotated circuit {circuit_id} -> {new_id} ({path_str}) in {dur:.2f}s[/green]"
            )
        finally:
            ctrl.close()
    except (ConfigError, TorError) as exc:
        err_console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(code=1)


async def _rotate_circuit(
    cfg: TorPoolConfig, bus: EventBus, ctrl: TorController, circuit_id: str
) -> tuple[str, list[RelayInfo], float]:
    """Close one circuit and build a replacement under the mandatory throttle."""
    throttle = CircuitBuildThrottle(cfg.circuit_creation_delay, bus)
    await throttle.wait("CIRCUIT_ROTATE")
    await asyncio.to_thread(ctrl.close_circuit, circuit_id)
    new_id, path, duration, _, _ = await asyncio.to_thread(ctrl.build_circuit, 1)
    return new_id, path, duration


@torrent_app.command("status")
def cmd_torrent_status(
    out: Optional[Path] = typer.Option(None, "--out", help="State/output directory to inspect"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
) -> None:
    """Display sanitized progress for a running torrent job."""
    clear_proxy_env()
    cfg = ConfigLoader.load(config_path=config_file, cli_overrides={"output_dir": out})
    directories = {cfg.effective_state_dir, cfg.output_dir}
    status_files = [
        path
        for directory in directories
        if directory.exists()
        for path in directory.glob(".torpool_torrent_status_*.json")
    ]
    if not status_files:
        err_console.print("[yellow]No live torrent job found.[/yellow]")
        raise typer.Exit(code=1)
    latest = max(status_files, key=lambda path: path.stat().st_mtime)
    try:
        data = json.loads(latest.read_text(encoding="utf-8"))
    except Exception as exc:
        err_console.print(f"[red]Unable to read torrent status: {exc}[/red]")
        raise typer.Exit(code=1)
    table = Table(title="Live Torrent Status")
    table.add_column("Property", style="bold")
    table.add_column("Value")
    table.add_row("Info-hash", str(data.get("infohash_prefix", "unknown")))
    files_total = int(data.get("files_total", 0))
    files_done = int(data.get("files_done", 0))
    table.add_row("Files", f"{files_done}/{files_total}")
    total = int(data.get("total_bytes", 0))
    completed = int(data.get("completed_bytes", 0))
    pct = (completed * 100.0 / total) if total > 0 else 0.0
    table.add_row("Progress", f"{completed}/{total} B ({pct:.1f}%)")
    table.add_row("Rate", f"{float(data.get('current_bps', 0.0)) / 1024.0:.1f} KiB/s")
    err_console.print(table)
    instances = data.get("instances", [])
    if instances:
        inst_table = Table(title="Torrent Instances")
        inst_table.add_column("Instance")
        inst_table.add_column("Circuit")
        inst_table.add_column("State")
        inst_table.add_column("Rate")
        for item in instances:
            inst_table.add_row(
                str(item.get("instance_id")),
                str(item.get("circuit_id")),
                str(item.get("state")),
                f"{float(item.get('throughput_bps', 0.0)) / 1024.0:.1f} KiB/s",
            )
        err_console.print(inst_table)


def _torrent_command(command: str, out: Optional[Path], config_file: Optional[Path]) -> None:
    clear_proxy_env()
    cfg = ConfigLoader.load(config_path=config_file, cli_overrides={"output_dir": out})
    control_path = find_control_file(cfg.effective_state_dir) or find_control_file(cfg.output_dir)
    if control_path is None:
        err_console.print("[yellow]No live torrent control file found.[/yellow]")
        raise typer.Exit(code=1)
    try:
        data = load_control_file(control_path)
        payload = asyncio.run(torrent_control_command(control_path, command))
    except Exception as exc:
        err_console.print(f"[red]Torrent command failed: {exc}[/red]")
        raise typer.Exit(code=1)
    err_console.print(
        f"[green]Torrent {command} issued for infohash "
        f"{str(data.get('infohash', ''))[:12]} ({len(payload.get('results', []))} instance(s)).[/green]"
    )


@torrent_app.command("pause")
def cmd_torrent_pause(
    out: Optional[Path] = typer.Option(None, "--out", help="State/output directory to inspect"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
) -> None:
    """Pause all torrents in the running job."""
    _torrent_command("pause", out, config_file)


@torrent_app.command("resume")
def cmd_torrent_resume(
    out: Optional[Path] = typer.Option(None, "--out", help="State/output directory to inspect"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
) -> None:
    """Resume all torrents in the running job."""
    _torrent_command("resume", out, config_file)


@torrent_app.command("remove")
def cmd_torrent_remove(
    out: Optional[Path] = typer.Option(None, "--out", help="State/output directory to inspect"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
) -> None:
    """Remove torrents from qBittorrent without deleting quarantine files."""
    _torrent_command("remove", out, config_file)


@app.command("healthcheck")
def cmd_healthcheck(
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
) -> None:
    """Lightweight Tor-only health check for Docker/compose; no qBittorrent spawn."""
    clear_proxy_env()
    try:
        cfg = ConfigLoader.load(config_path=config_file)
        _ = cfg.get_control_password()
    except ConfigError as exc:
        err_console.print(f"[red][HEALTHCHECK FAIL] {exc}[/red]")
        raise typer.Exit(code=1)
    bus = EventBus()
    ctrl = TorController(cfg, bus)
    try:
        ctrl.connect_and_verify()
        try:
            with socket.create_connection((cfg.tor_socks_host, cfg.socks_port_base), timeout=3.0):
                pass
        except Exception as exc:
            err_console.print(f"[red][HEALTHCHECK FAIL] SOCKS unreachable: {exc}[/red]")
            raise typer.Exit(code=1)
        err_console.print("[green][HEALTHCHECK OK] Tor control and SOCKS are healthy.[/green]")
    except TorError as exc:
        err_console.print(f"[red][HEALTHCHECK FAIL] {exc}[/red]")
        raise typer.Exit(code=1)
    finally:
        ctrl.close()


@app.command("fetch")
def cmd_fetch(
    source: str = typer.Argument(
        ..., help="HTTP(S)/.onion URL, magnet URI, or private .torrent file"
    ),
    circuits: Optional[int] = typer.Option(
        None, "--circuits", help="Number of Tor circuits (1-100)"
    ),
    chunk_size: Optional[str] = typer.Option(
        None, "--chunk-size", help="Chunk size for HTTP downloads (e.g. 10M, 4M)"
    ),
    out: Optional[Path] = typer.Option(None, "--out", help="Quarantine output directory"),
    sha256: Optional[str] = typer.Option(None, "--sha256", help="Expected SHA-256 hash"),
    encrypt: Optional[bool] = typer.Option(
        None, "--encrypt", help="Encrypt downloaded file at rest (AES-256-GCM)"
    ),
    key_file: Optional[Path] = typer.Option(
        None, "--key-file", help="Path to encryption key/passphrase file"
    ),
    resume: bool = typer.Option(False, "--resume", help="Resume interrupted download from state"),
    max_bandwidth: Optional[str] = typer.Option(
        None, "--max-bandwidth", help="Global rate limit in bytes/s (e.g. 5M)"
    ),
    per_host_concurrency: Optional[int] = typer.Option(
        None, "--per-host-concurrency", help="Max concurrent connections"
    ),
    torrent_mode: Optional[str] = typer.Option(
        None, "--torrent-mode", help="Torrent mode: auto, multi_file, or single"
    ),
    torrent_max_connections: Optional[int] = typer.Option(
        None, "--torrent-max-connections", help="Per-instance qBittorrent connection cap"
    ),
    verbose: int = typer.Option(0, "-v", count=True, help="Verbosity (-v or -vv)"),
    quiet: bool = typer.Option(False, "--quiet", help="Errors and final result only"),
    graph: bool = typer.Option(False, "--graph", help="Display live bandwidth graph"),
    log_file: Optional[Path] = typer.Option(None, "--log-file", help="Path to sanitized log file"),
    new_identity: bool = typer.Option(
        False, "--new-identity", help="Issue SIGNAL NEWNYM before starting"
    ),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Path to config TOML file"),
) -> None:
    """Download an HTTP(S)/onion file, magnet URI, or .torrent across Tor circuits."""
    clear_proxy_env()
    verbosity_val = -1 if quiet else verbose

    overrides = {
        "circuits": circuits,
        "chunk_size": parse_size(chunk_size) if chunk_size else None,
        "output_dir": out,
        "encrypt": encrypt,
        "key_file": key_file,
        "max_bandwidth": parse_size(max_bandwidth) if max_bandwidth else None,
        "per_host_concurrency": per_host_concurrency,
        "torrent_mode": torrent_mode,
        "torrent_max_connections": torrent_max_connections,
        "verbosity": verbosity_val,
        "graph": graph,
        "log_file": log_file,
    }

    torrent_source: Optional[TorrentSource] = None
    try:
        cfg = ConfigLoader.load(config_path=config_file, cli_overrides=overrides)
        _ = cfg.get_control_password()
        is_local_torrent = not source.lower().startswith(
            ("http://", "https://")
        ) and source.lower().endswith(".torrent")
        is_torrent = source.lower().startswith("magnet:") or is_local_torrent
        if is_torrent:
            if chunk_size:
                raise ConfigError("--chunk-size is not applicable to torrent downloads")
            torrent_source = parse_torrent_source(source)
        else:
            TorController.validate_url_opsec(source)
    except (ConfigError, TorError, TorrentError) as exc:
        err_console.print(f"[red]Startup Error: {exc}[/red]")
        raise typer.Exit(code=1)

    ensure_authorized(cfg)

    if torrent_source is not None:
        exit_code = asyncio.run(
            _run_torrent_job(
                cfg=cfg,
                source=torrent_source,
                expected_sha256=sha256,
                resume=resume,
                new_identity=new_identity,
            )
        )
    else:
        exit_code = asyncio.run(
            _run_fetch_job(
                cfg=cfg,
                url=source,
                expected_sha256=sha256,
                resume=resume,
                new_identity=new_identity,
            )
        )
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


async def _run_torrent_job(
    cfg: TorPoolConfig,
    source: TorrentSource,
    expected_sha256: Optional[str],
    resume: bool,
    new_identity: bool,
) -> int:
    """Run a magnet/.torrent job across isolated qBittorrent instances."""
    bus = EventBus()
    renderer = TerminalVerboseRenderer(verbosity=cfg.verbosity, stream=sys.stderr)
    bus.subscribe(renderer)
    if cfg.log_file:
        bus.subscribe(SanitizedLogWriter(cfg.log_file))
    await bus.start()

    metrics = MetricsWindow(graph_window_seconds=cfg.graph_window)
    ctrl = TorController(cfg, bus, metrics=metrics)
    try:
        ctrl.connect_and_verify()
    except TorError as exc:
        bus.emit(EventType.ERROR, message=str(exc), reason="TOR_INIT_FAILED")
        await bus.stop()
        return 1

    cfg.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cfg.output_dir, 0o700)
    cfg.effective_state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cfg.effective_state_dir, 0o700)
    cfg.qbittorrent_temp_profile_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cfg.qbittorrent_temp_profile_dir, 0o700)

    pool = CircuitPool(cfg, ctrl, bus, metrics)
    monitor = HealthMonitor(cfg, pool, bus)
    state_path = StateStore.state_path_for_torrent(cfg.effective_state_dir, source.source_digest)
    state_store = StateStore(state_path)
    supervisor = TorrentSupervisor(cfg, pool, bus, metrics, state_store)
    dashboard = Dashboard(cfg, metrics, pool)

    loop = asyncio.get_running_loop()
    interrupted = False

    def _on_signal() -> None:
        nonlocal interrupted
        interrupted = True
        bus.emit(
            EventType.SECURITY_ALERT,
            message="Transfer paused: SIGNAL_INTERRUPT",
            reason="FAIL_CLOSED",
        )
        asyncio.create_task(supervisor.close())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            pass

    t0 = time.monotonic()
    try:
        if new_identity:
            ctrl.new_identity()
        await pool.initialize_pool(min(cfg.circuits, cfg.torrent_max_instances))
        await monitor.start()
        await dashboard.start()
        total_bytes, digest, _final_path = await supervisor.run(
            source,
            cfg.output_dir,
            expected_sha256=expected_sha256,
            resume=resume,
        )
        duration = time.monotonic() - t0
        bus.emit(
            EventType.JOB_COMPLETE,
            status="VERIFIED",
            bytes=total_bytes,
            sha256=digest,
            duration_s=duration,
        )
        return 0
    except (TorrentError, VerificationError, QBittorrentError, TorError) as exc:
        bus.emit(
            EventType.TORRENT_ERROR,
            reason="TORRENT_JOB_ERROR",
            message=sanitize_log_text(str(exc))[:300],
        )
        return 130 if interrupted else 1
    except Exception as exc:  # noqa: BLE001 - fail closed and report sanitized reason
        bus.emit(EventType.ERROR, message=str(exc)[:300], reason="UNEXPECTED_ERROR")
        return 130 if interrupted else 1
    finally:
        await dashboard.stop()
        await monitor.stop()
        await supervisor.close()
        await pool.close_all()
        ctrl.close()
        await bus.stop()


async def _run_fetch_job(
    cfg: TorPoolConfig,
    url: str,
    expected_sha256: Optional[str],
    resume: bool,
    new_identity: bool,
) -> int:
    """Run the original HTTP range-download path unchanged."""
    bus = EventBus()
    renderer = TerminalVerboseRenderer(verbosity=cfg.verbosity, stream=sys.stderr)
    bus.subscribe(renderer)
    if cfg.log_file:
        bus.subscribe(SanitizedLogWriter(cfg.log_file))

    await bus.start()
    metrics = MetricsWindow(graph_window_seconds=cfg.graph_window)
    limiter = BandwidthLimiter(max_bandwidth_bps=cfg.max_bandwidth)
    ctrl = TorController(cfg, bus, metrics=metrics)

    try:
        ctrl.connect_and_verify()
    except TorError as exc:
        bus.emit(EventType.ERROR, message=str(exc), reason="TOR_INIT_FAILED")
        await bus.stop()
        return 1

    pool = CircuitPool(cfg, ctrl, bus, metrics)
    monitor = HealthMonitor(cfg, pool, bus)
    downloader = RangeDownloader(cfg, metrics, limiter)
    state_path = StateStore.state_path_for_url(cfg.effective_state_dir, url)
    state_store = StateStore(state_path)
    scheduler = ChunkScheduler(cfg, pool, downloader, state_store, bus, metrics)
    dashboard = Dashboard(cfg, metrics, pool)

    ctrl.register_leak_callback(scheduler.trigger_emergency_pause)

    # Handle SIGINT / SIGTERM cleanly
    loop = asyncio.get_running_loop()
    interrupted = False

    def _on_signal() -> None:
        nonlocal interrupted
        interrupted = True
        scheduler.trigger_emergency_pause("SIGNAL_INTERRUPT")

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            pass

    t0 = time.monotonic()
    parsed_path = Path(urlparse(url).path)
    file_name = parsed_path.name if parsed_path.name else "downloaded_artifact.bin"
    target_file = cfg.output_dir / file_name

    try:
        if new_identity:
            ctrl.new_identity()
        await pool.initialize_pool()
        await monitor.start()
        await dashboard.start()

        total_bytes = await scheduler.execute_download(url, target_file, resume=resume)
        target_to_verify = (
            target_file.with_name(f"{target_file.name}.enc") if cfg.encrypt else target_file
        )
        passed, digest, final_path = IntegrityVerifier.verify_and_record(
            file_path=target_to_verify,
            url=url,
            expected_sha256=expected_sha256,
            encrypt=cfg.encrypt,
        )
        duration = time.monotonic() - t0
        if passed:
            state_store.remove()
            bus.emit(
                EventType.JOB_COMPLETE,
                status="VERIFIED",
                bytes=total_bytes,
                sha256=digest,
                duration_s=duration,
            )
            return 0
        else:
            bus.emit(
                EventType.ERROR,
                message=f"Integrity check failed for {final_path.name}: expected {expected_sha256}, got {digest}",
                reason="HASH_MISMATCH",
            )
            return 2
    except SchedulerError as exc:
        bus.emit(EventType.ERROR, message=str(exc), reason="SCHEDULER_ERROR")
        return 130 if interrupted else 1
    except Exception as exc:  # noqa: BLE001 - report and fail closed
        bus.emit(EventType.ERROR, message=str(exc), reason="UNEXPECTED_ERROR")
        return 1
    finally:
        await dashboard.stop()
        await monitor.stop()
        await pool.close_all()
        ctrl.close()
        await bus.stop()

        # Shred leftover temporary artifacts so partial plaintext never persists.
        if cfg.temp_dir.exists():
            for leftover in cfg.temp_dir.glob("*"):
                if leftover.is_file():
                    RangeDownloader.shred_file(leftover)
