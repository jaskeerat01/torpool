"""Local HTTP server supporting HTTP Range requests for integration testing."""

import http.server
import re
import socketserver
import threading
from pathlib import Path
from typing import Optional


class RangeHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler supporting standard Range: bytes=start-end requests."""

    RANGE_RE = re.compile(r"^bytes=(\d+)-(\d+)?$")

    def end_headers(self) -> None:
        self.send_header("Accept-Ranges", "bytes")
        super().end_headers()

    def do_HEAD(self) -> None:
        path = self.translate_path(self.path)
        p = Path(path)
        if p.exists() and p.is_file():
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(p.stat().st_size))
            self.end_headers()
        else:
            self.send_error(404, "File Not Found")

    def do_GET(self) -> None:
        path = self.translate_path(self.path)
        p = Path(path)
        if not p.exists() or not p.is_file():
            self.send_error(404, "File Not Found")
            return

        file_size = p.stat().st_size
        range_header = self.headers.get("Range")

        if not range_header:
            # Full file GET
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(file_size))
            self.end_headers()
            with open(p, "rb") as f:
                self.copyfile(f, self.wfile)
            return

        m = self.RANGE_RE.match(range_header.strip())
        if not m:
            self.send_error(416, "Requested Range Not Satisfiable")
            return

        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else file_size - 1

        if start >= file_size or end >= file_size or start > end:
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{file_size}")
            self.end_headers()
            return

        length = end - start + 1
        self.send_response(206)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
        self.send_header("Content-Length", str(length))
        self.end_headers()

        with open(p, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(remaining, 65536))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)


class RangeServer:
    """Threaded HTTP server running on localhost serving files from serve_dir."""

    def __init__(self, serve_dir: Path, port: int = 0) -> None:
        self.serve_dir = serve_dir
        self.port = port
        self._server: Optional[socketserver.TCPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> int:
        handler = lambda *args, **kwargs: RangeHTTPRequestHandler(  # noqa: E731
            *args, directory=str(self.serve_dir), **kwargs
        )
        self._server = socketserver.TCPServer(("127.0.0.1", self.port), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
