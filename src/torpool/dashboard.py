"""Dashboard: Live terminal UI and bandwidth graph rendered from MetricsWindow with zero network calls."""

import asyncio
import locale
import sys
import time
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from torpool.circuit_pool import CircuitPool
from torpool.config import TorPoolConfig
from torpool.metrics import MetricsWindow

UNICODE_BLOCKS = " ▂▃▄▅▆▇█"
ASCII_BLOCKS = " ._,-=+*#"


class Dashboard:
    """
    Presentational terminal dashboard and optional bandwidth graph.
    Reads strictly from MetricsWindow and CircuitPool in memory.
    Never performs network I/O and never influences scheduling decisions.
    """

    def __init__(
        self,
        config: TorPoolConfig,
        metrics: MetricsWindow,
        pool: Optional[CircuitPool] = None,
        force_ascii: Optional[bool] = None,
    ) -> None:
        self.config = config
        self.metrics = metrics
        self.pool = pool
        self._force_ascii = force_ascii
        self._running = False
        self._task: Optional[asyncio.Task[None]] = None
        self.dropped_frames: int = 0

    def is_utf8(self) -> bool:
        """Detect whether the terminal supports UTF-8 block characters."""
        if self._force_ascii is True:
            return False
        if self._force_ascii is False:
            return True
        enc = getattr(sys.stderr, "encoding", None) or locale.getpreferredencoding(False) or "ascii"
        return "utf" in enc.lower()

    def render_sparkline(self, samples: list[float], width: int) -> str:
        """Render a 1-line sparkline of throughput samples scaled to width."""
        if width <= 0:
            return ""
        charset = UNICODE_BLOCKS if self.is_utf8() else ASCII_BLOCKS
        if not samples:
            return charset[0] * width

        tail = samples[-width:]
        if len(tail) < width:
            tail = ([0.0] * (width - len(tail))) + tail

        peak = max(tail) if max(tail) > 0 else 1.0
        chars = []
        for val in tail:
            idx = int((val / peak) * (len(charset) - 1))
            idx = max(0, min(len(charset) - 1, idx))
            chars.append(charset[idx])
        return "".join(chars)

    def render_aggregate_chart(self, samples: list[float], width: int, height: int) -> str:
        """Render multi-row aggregate throughput line/area chart over graph_window."""
        width = max(10, width)
        height = max(3, height)
        charset = UNICODE_BLOCKS if self.is_utf8() else ASCII_BLOCKS
        fill_char = charset[-1]
        empty_char = " "

        tail = samples[-width:]
        if len(tail) < width:
            tail = ([0.0] * (width - len(tail))) + tail

        peak = max(tail) if max(tail) > 0 else 1.0
        rows: list[str] = []
        for r in range(height - 1, -1, -1):
            threshold = (r + 0.5) / float(height)
            line_chars = [fill_char if (v / peak) >= threshold and v > 0 else empty_char for v in tail]
            rows.append("".join(line_chars))
        return "\n".join(rows)

    def render_frame(self, width: int = 80, height: int = 24) -> Panel:
        """
        Render the status and graph view for the given terminal dimensions.
        Adapts to terminal resize; below 60 columns falls back to compact text summary.
        Never displays target URL or local IP addresses.
        """
        snap = self.metrics.get_snapshot()
        curr_kib = float(snap["current_bps"]) / 1024.0
        peak_kib = float(snap["peak_bps"]) / 1024.0
        avg_kib = float(snap["avg_bps"]) / 1024.0
        completed = int(snap["completed_bytes"])
        total = int(snap["total_bytes"])
        eta_s = float(snap["eta_s"])
        eta_str = f"{eta_s:.1f}s" if eta_s >= 0 else "N/A"
        pct = (completed * 100.0 / total) if total > 0 else 0.0

        # Compact text fallback for narrow terminals (< 60 columns)
        if width < 60 or height < 12:
            compact = (
                f"Rate: {curr_kib:.1f} KiB/s (Peak {peak_kib:.1f}, Avg {avg_kib:.1f})\n"
                f"Done: {completed}/{total} B ({pct:.1f}%) ETA: {eta_str}"
            )
            return Panel(Text(compact), title="TorPool", width=max(20, width))

        chart_width = max(15, width - 12)
        chart_height = max(3, min(8, height - 14))
        agg_hist: list[float] = list(snap["aggregate_history"])  # type: ignore[arg-type]
        chart_str = self.render_aggregate_chart(agg_hist, width=chart_width, height=chart_height)

        table = Table(show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Circuit ID", width=12)
        table.add_column("State", width=10)
        table.add_column("Rate (KiB/s)", justify="right", width=14)
        table.add_column("Sparkline", ratio=1)

        circ_hists: dict[str, list[float]] = snap["circuit_histories"]  # type: ignore[assignment]
        spark_w = max(8, width - 48)

        if self.pool:
            for c in self.pool.circuits:
                c_hist = circ_hists.get(c.circuit_id, [])
                c_rate = self.metrics.get_circuit_throughput(c.circuit_id) / 1024.0
                spark = self.render_sparkline(c_hist, spark_w)
                table.add_row(c.circuit_id, c.state.value, f"{c_rate:.1f}", spark)
        else:
            for cid, c_hist in circ_hists.items():
                c_rate = (c_hist[-1] / 1024.0) if c_hist else 0.0
                spark = self.render_sparkline(c_hist, spark_w)
                table.add_row(cid, "healthy", f"{c_rate:.1f}", spark)

        header_summary = (
            f"Current: {curr_kib:.1f} KiB/s | Peak: {peak_kib:.1f} KiB/s | "
            f"Avg: {avg_kib:.1f} KiB/s | Completed: {completed}/{total} B ({pct:.1f}%) | ETA: {eta_str}\n\n"
            f"Aggregate Bandwidth ({self.config.graph_window}s window):\n{chart_str}"
        )

        grid = Table.grid(expand=True)
        grid.add_row(Text(header_summary))
        grid.add_row(table)
        return Panel(grid, title="TorPool Live Bandwidth Monitor", width=width)

    async def start(self) -> None:
        """Start non-blocking live rendering task if graph is enabled and stderr is a TTY."""
        if not self.config.graph or not sys.stderr.isatty():
            return
        self._running = True
        self._task = asyncio.create_task(self._render_loop())

    async def stop(self) -> None:
        """Stop live rendering task."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _render_loop(self) -> None:
        console = Console(stderr=True)
        refresh = self.config.graph_refresh
        with Live(console=console, auto_refresh=False, transient=True) as live:
            while self._running:
                t0 = time.monotonic()
                size = console.size
                panel = self.render_frame(width=size.width, height=size.height)
                live.update(panel, refresh=True)
                elapsed = time.monotonic() - t0
                if elapsed > refresh:
                    # Drop missed frames rather than blocking the event loop
                    self.dropped_frames += 1
                    await asyncio.sleep(0.01)
                else:
                    await asyncio.sleep(refresh - elapsed)
