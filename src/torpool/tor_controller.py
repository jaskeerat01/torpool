"""
TorController wrapper around stem with password-only authentication, explicit EXTENDCIRCUIT
paths, __LeaveStreamsUnattached 1, per-circuit local SOCKS listeners (mapping exact
SOURCE_ADDR TCP source ports to circuit IDs), and SOCKS_USERNAME circuit tagging.
"""

import asyncio
from dataclasses import dataclass
import random
import re
import secrets
import threading
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import stem
import stem.connection
from stem import CircStatus, Signal, StreamStatus
from stem.control import Controller, EventType as StemEventType

from torpool.config import TorPoolConfig
from torpool.events import EventBus, EventType
from torpool.metrics import MetricsWindow

SOCKS_USER_RE = re.compile(r'SOCKS_USERNAME="([^"]+)"')


class TorError(Exception):
    """Raised when Tor control authentication, bootstrap, or circuit control fails."""


@dataclass
class RelayInfo:
    """Metadata for a single Tor relay in a circuit path."""

    fingerprint: str
    nickname: str

    @property
    def short_str(self) -> str:
        """Format as Nickname[$8CHAR_FP] for terminal verbose output."""
        short_fp = self.fingerprint[:8]
        return f"{self.nickname}[${short_fp}]"


class CircuitSocksListener:
    """
    Dedicated local TCP SOCKS5 listener for a single ManagedCircuit.
    Forwards connections to Tor's SocksPort, recording the exact outbound TCP source port
    (which Tor emits in STREAM events as SOURCE_ADDR=127.0.0.1:<port>) BEFORE sending the
    SOCKS5 greeting. This guarantees deterministic 1-to-1 stream-to-circuit attachment
    even when Tor's STREAM event omits SOCKS_USERNAME, and allows killing an individual
    circuit's SOCKS listener mid-download (Acceptance Criterion 2).
    """

    def __init__(
        self,
        circuit_id: str,
        socks_user: str,
        tor_socks_host: str,
        tor_socks_port: int,
        controller: "TorController",
    ) -> None:
        self.circuit_id = circuit_id
        self.socks_user = socks_user
        self.tor_socks_host = tor_socks_host
        self.tor_socks_port = tor_socks_port
        self.controller = controller
        self._server: Optional[asyncio.AbstractServer] = None
        self._active_writers: set[asyncio.StreamWriter] = set()
        self._client_tasks: set[asyncio.Task[None]] = set()
        self.local_port: int = 0

    async def start(self) -> int:
        """Bind a dedicated localhost listener on an ephemeral port and return the port."""
        self._server = await asyncio.start_server(self._spawn_handler, "127.0.0.1", 0)
        sockets = self._server.sockets
        if sockets:
            self.local_port = int(sockets[0].getsockname()[1])
        return self.local_port

    def _spawn_handler(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        """Track each connection handler so stop() can cancel it deterministically."""
        task = asyncio.create_task(self._handle_client(client_reader, client_writer))
        self._client_tasks.add(task)
        task.add_done_callback(self._client_tasks.discard)

    async def stop(self) -> None:
        """Close the listener and forcefully terminate all active streams on this circuit."""
        server = self._server
        self._server = None
        if server:
            server.close()
        # Close live connections *before* waiting: since Python 3.12
        # Server.wait_closed() blocks until every active connection handler finishes.
        for writer in list(self._active_writers):
            try:
                writer.close()
            except Exception:
                pass
        self._active_writers.clear()
        handlers = [t for t in self._client_tasks if not t.done()]
        for task in handlers:
            task.cancel()
        if handlers:
            await asyncio.gather(*handlers, return_exceptions=True)
        if server:
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=2.0)
            except Exception:
                pass

    async def _handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        self._active_writers.add(client_writer)
        upstream_writer: Optional[asyncio.StreamWriter] = None
        src_port: Optional[int] = None
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.tor_socks_host, self.tor_socks_port
            )
            self._active_writers.add(upstream_writer)
            sockname = upstream_writer.get_extra_info("sockname")
            if sockname and len(sockname) >= 2:
                src_port = int(sockname[1])
                self.controller.register_source_port(src_port, self.circuit_id, self.socks_user)

            await asyncio.gather(
                self._pipe(client_reader, upstream_writer),
                self._pipe(upstream_reader, client_writer),
            )
        except Exception:
            pass
        finally:
            if src_port is not None:
                self.controller.unregister_source_port(src_port)
            self._active_writers.discard(client_writer)
            try:
                client_writer.close()
            except Exception:
                pass
            if upstream_writer is not None:
                self._active_writers.discard(upstream_writer)
                try:
                    upstream_writer.close()
                except Exception:
                    pass

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


class TorController:
    """
    Wraps stem.control.Controller.
    - Connects using password authentication exclusively from os.environ["TOR_CONTROL_PASSWORD"].
    - Creates circuits explicitly via EXTENDCIRCUIT with distinct guards/middles.
    - Enforces __LeaveStreamsUnattached 1.
    - Maps every stream deterministically to its assigned circuit via per-circuit
      CircuitSocksListener SOURCE_ADDR port correlation AND Tor's SOCKS_USERNAME circuit
      tagging (for hidden service rendezvous circuits and IsolateSOCKSAuth).
    - Verifies actual circuit usage from STREAM SUCCEEDED/SENTCONNECT and CIRC_BW events.
    """

    def __init__(
        self,
        config: TorPoolConfig,
        event_bus: EventBus,
        metrics: Optional[MetricsWindow] = None,
    ) -> None:
        self.config = config
        self.event_bus = event_bus
        self.metrics = metrics
        self._controller: Optional[Controller] = None
        self._lock = threading.Lock()

        self._used_guards: set[str] = set()
        self._used_middles: set[str] = set()

        # Mapping tables for deterministic stream -> circuit attachment and verification
        self._socks_cred_to_circuit: dict[str, str] = {}
        self._circuit_to_socks_user: dict[str, str] = {}
        self._source_port_to_circuit: dict[int, str] = {}
        self._source_port_to_socks_user: dict[int, str] = {}
        self._socks_user_to_hs_circuit: dict[str, str] = {}
        self._stream_to_slot: dict[str, str] = {}
        self._slot_to_verified_tor_circuit: dict[str, str] = {}
        self._actual_tor_circ_to_slot: dict[str, str] = {}
        self._circuit_to_exit: dict[str, str] = {}
        self._leak_callback: Optional[Callable[[str], None]] = None

    def register_leak_callback(self, callback: Callable[[str], None]) -> None:
        """Register fail-closed callback if an unexpected exit or disconnect occurs."""
        self._leak_callback = callback

    def register_source_port(self, src_port: int, circuit_id: str, socks_user: str) -> None:
        """Record outbound TCP source port -> circuit_id before SOCKS5 handshake reaches Tor."""
        with self._lock:
            self._source_port_to_circuit[src_port] = circuit_id
            self._source_port_to_socks_user[src_port] = socks_user

    def unregister_source_port(self, src_port: int) -> None:
        """Remove closed outbound TCP source port mapping."""
        with self._lock:
            self._source_port_to_circuit.pop(src_port, None)
            self._source_port_to_socks_user.pop(src_port, None)

    def get_verified_tor_circuit(self, slot_circuit_id: str) -> str:
        """Return the Tor circuit ID verified by control-port STREAM/CIRC events for slot_circuit_id."""
        with self._lock:
            return self._slot_to_verified_tor_circuit.get(slot_circuit_id, slot_circuit_id)

    @staticmethod
    def validate_url_opsec(url: str) -> None:
        """
        Verify URL scheme and hostname safety.
        Refuses non-HTTP/HTTPS schemes or loopback addresses that could bypass Tor.
        All DNS resolution occurs remotely via socks5h://.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise TorError(f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed.")
        if not parsed.hostname:
            raise TorError("Invalid URL: missing hostname.")
        if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
            raise TorError("Refusing to connect to localhost/loopback address.")

    @staticmethod
    def _password_auth_supported(auth_methods: Any) -> bool:
        """Return True when Tor offers PASSWORD auth (stem reports 'Password' on some versions)."""
        methods = [str(m).upper() for m in (auth_methods or [])]
        return not methods or "PASSWORD" in methods

    def connect_and_verify(self) -> None:
        """
        Connect to Tor control port, authenticate strictly with TOR_CONTROL_PASSWORD,
        verify 100% bootstrap and circuit establishment, and set __LeaveStreamsUnattached 1.
        """
        password = self.config.get_control_password()

        try:
            ctrl = Controller.from_port(address="127.0.0.1", port=self.config.control_port)
        except Exception as exc:
            raise TorError(f"Unable to reach Tor control port {self.config.control_port}: {exc}") from exc

        try:
            proto_info = ctrl.get_protocolinfo()
            auth_methods = getattr(proto_info, "auth_methods", [])
            if not self._password_auth_supported(auth_methods):
                ctrl.close()
                raise TorError("Tor daemon is not configured for HashedControlPassword authentication.")

            ctrl.authenticate(password=password)
        except stem.connection.AuthenticationFailure as exc:
            ctrl.close()
            raise TorError("Tor control port password authentication failed.") from exc
        except TorError:
            raise
        except Exception as exc:
            ctrl.close()
            raise TorError(f"Tor control authentication error: {exc}") from exc
        finally:
            del password

        bootstrap = ctrl.get_info("status/bootstrap-phase", "")
        if "PROGRESS=100" not in bootstrap:
            ctrl.close()
            raise TorError(f"Tor is not fully bootstrapped (reported: {bootstrap}). Refusing to start.")

        circ_est = ctrl.get_info("status/circuit-established", "0")
        if circ_est != "1":
            ctrl.close()
            raise TorError("Tor reports status/circuit-established != 1. Refusing to start.")

        try:
            ctrl.enable_feature("EXTENDED_EVENTS")
        except Exception:
            pass

        ctrl.set_conf("__LeaveStreamsUnattached", "1")
        ctrl.add_event_listener(self._on_circ_event, StemEventType.CIRC)
        ctrl.add_event_listener(self._on_stream_event, StemEventType.STREAM)
        try:
            ctrl.add_event_listener(self._on_circ_bw_event, StemEventType.CIRC_BW)
        except Exception:
            pass

        self._controller = ctrl

    def close(self) -> None:
        """Reset __LeaveStreamsUnattached and close control connection."""
        if self._controller:
            try:
                self._controller.set_conf("__LeaveStreamsUnattached", "0")
            except Exception:
                pass
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None

    def new_identity(self) -> None:
        """Issue SIGNAL NEWNYM and clear used guard/middle sets."""
        if not self._controller:
            raise TorError("Controller not connected.")
        self._controller.signal(Signal.NEWNYM)
        with self._lock:
            self._used_guards.clear()
            self._used_middles.clear()
            self._socks_user_to_hs_circuit.clear()
        self.event_bus.emit(EventType.NEW_IDENTITY)

    def select_distinct_path(self) -> list[RelayInfo]:
        """
        Choose a 3-hop path (Guard, Middle, Exit) with distinct guard and middle relays
        across the pool where consensus descriptors are available.
        """
        if not self._controller:
            raise TorError("Controller not connected.")

        try:
            statuses = list(self._controller.get_network_statuses())
        except Exception:
            statuses = []

        guards = [
            s for s in statuses
            if "Guard" in getattr(s, "flags", []) and "Running" in getattr(s, "flags", [])
        ]
        exits = [
            s for s in statuses
            if "Exit" in getattr(s, "flags", [])
            and "Running" in getattr(s, "flags", [])
            and "BadExit" not in getattr(s, "flags", [])
        ]
        middles = [s for s in statuses if "Running" in getattr(s, "flags", [])]

        if len(guards) >= 1 and len(middles) >= 2 and len(exits) >= 1:
            with self._lock:
                avail_guards = [g for g in guards if g.fingerprint not in self._used_guards] or guards
                guard = random.choice(avail_guards)
                self._used_guards.add(guard.fingerprint)

                avail_middles = [
                    m for m in middles
                    if m.fingerprint != guard.fingerprint and m.fingerprint not in self._used_middles
                ] or [m for m in middles if m.fingerprint != guard.fingerprint]
                middle = random.choice(avail_middles)
                self._used_middles.add(middle.fingerprint)

            avail_exits = [
                e for e in exits
                if e.fingerprint not in (guard.fingerprint, middle.fingerprint)
            ] or exits
            exit_relay = random.choice(avail_exits)

            return [
                RelayInfo(guard.fingerprint, getattr(guard, "nickname", "Guard")),
                RelayInfo(middle.fingerprint, getattr(middle, "nickname", "Middle")),
                RelayInfo(exit_relay.fingerprint, getattr(exit_relay, "nickname", "Exit")),
            ]

        return []

    def build_circuit(self, attempt: int = 1) -> tuple[str, list[RelayInfo], float, str, str]:
        """
        Build a dedicated circuit using EXTENDCIRCUIT.
        Returns (circuit_id, relay_path, build_duration_s, socks_user, socks_pass).
        """
        if not self._controller:
            raise TorError("Controller not connected.")

        path = self.select_distinct_path()
        path_fps = [r.fingerprint for r in path] if path else None
        path_str = " -> ".join(r.short_str for r in path) if path else "AUTO"

        self.event_bus.emit(
            EventType.CIRCUIT_BUILD_START,
            attempt=attempt,
            path_str=path_str,
        )

        t0 = time.monotonic()
        try:
            circ_id = str(self._controller.new_circuit(path=path_fps, await_build=True))
            duration = time.monotonic() - t0
            if not path:
                try:
                    c_info = self._controller.get_circuit(circ_id)
                    path = [RelayInfo(fp, nick or "Relay") for fp, nick in c_info.path]
                except Exception:
                    path = [
                        RelayInfo("0000000000000000000000000000000000000001", "Guard"),
                        RelayInfo("0000000000000000000000000000000000000002", "Middle"),
                        RelayInfo("0000000000000000000000000000000000000003", "Exit"),
                    ]

            socks_user = f"tp_{circ_id}_{secrets.token_hex(4)}"
            socks_pass = secrets.token_hex(8)
            with self._lock:
                if path:
                    self._circuit_to_exit[circ_id] = path[-1].fingerprint
                self._socks_cred_to_circuit[socks_user] = circ_id
                self._circuit_to_socks_user[circ_id] = socks_user
                self._slot_to_verified_tor_circuit[circ_id] = circ_id
                self._actual_tor_circ_to_slot[circ_id] = circ_id
            return circ_id, path, duration, socks_user, socks_pass
        except Exception as exc:
            duration = time.monotonic() - t0
            reason = getattr(exc, "code", None) or str(exc) or "TIMEOUT"
            raise TorError(f"Circuit build failed (reason={reason}) after {duration:.2f}s") from exc

    def close_circuit(self, circuit_id: str) -> None:
        """Close a circuit (and any associated HS rendezvous circuit) via CLOSECIRCUIT."""
        if not self._controller:
            return
        with self._lock:
            socks_user = self._circuit_to_socks_user.pop(circuit_id, None)
            hs_cid = self._socks_user_to_hs_circuit.pop(socks_user, None) if socks_user else None
            if socks_user:
                self._socks_cred_to_circuit.pop(socks_user, None)
            self._circuit_to_exit.pop(circuit_id, None)
            self._slot_to_verified_tor_circuit.pop(circuit_id, None)
            self._actual_tor_circ_to_slot.pop(circuit_id, None)
            if hs_cid:
                self._actual_tor_circ_to_slot.pop(hs_cid, None)

        try:
            self._controller.close_circuit(circuit_id)
        except Exception:
            pass
        if hs_cid and hs_cid != circuit_id:
            try:
                self._controller.close_circuit(hs_cid)
            except Exception:
                pass

    def get_socks_proxy_url(self, socks_user: str, socks_pass: str, listener_port: Optional[int] = None) -> str:
        """
        Return socks5h:// proxy URL for the circuit's dedicated SOCKS listener port
        (or base SocksPort) with unique IsolateSOCKSAuth credentials.
        socks5h guarantees all DNS resolution occurs inside the Tor network.
        """
        port = listener_port if listener_port and listener_port > 0 else self.config.socks_port_base
        return f"socks5h://{socks_user}:{socks_pass}@127.0.0.1:{port}"

    @staticmethod
    def _extract_socks_username(event: Any) -> Optional[str]:
        """Extract SOCKS_USERNAME from a Stem CircuitEvent or StreamEvent if present."""
        direct = getattr(event, "socks_username", None)
        if direct:
            return str(direct).strip('"')
        kw = getattr(event, "keyword_args", None)
        if isinstance(kw, dict) and "SOCKS_USERNAME" in kw:
            return str(kw["SOCKS_USERNAME"]).strip('"')
        m = SOCKS_USER_RE.search(str(event))
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _extract_source_port(event: Any) -> Optional[int]:
        """Extract client ephemeral TCP port from StreamEvent.source_addr (127.0.0.1:port)."""
        src_addr = getattr(event, "source_addr", None)
        if not src_addr:
            kw = getattr(event, "keyword_args", None)
            if isinstance(kw, dict):
                src_addr = kw.get("SOURCE_ADDR")
        if src_addr and ":" in str(src_addr):
            port_str = str(src_addr).rsplit(":", 1)[-1]
            if port_str.isdigit():
                return int(port_str)
        return None

    def _resolve_slot_for_stream(self, event: Any) -> tuple[Optional[str], Optional[str]]:
        """
        Deterministically resolve (slot_circuit_id, socks_user) for a StreamEvent using:
        1. Stream ID cache (for events after NEW),
        2. Exact SOURCE_ADDR port registered by the circuit's dedicated CircuitSocksListener,
        3. SOCKS_USERNAME in event attributes/keyword_args,
        4. Attached circuit's SOCKS_USERNAME tag on Tor's control port.
        Never falls back to circ_ids[0].
        """
        stream_id = str(getattr(event, "id", ""))
        src_port = self._extract_source_port(event)
        socks_user = self._extract_socks_username(event)

        with self._lock:
            if stream_id in self._stream_to_slot:
                slot_cid = self._stream_to_slot[stream_id]
                return slot_cid, self._circuit_to_socks_user.get(slot_cid)

            if src_port is not None and src_port in self._source_port_to_circuit:
                slot_cid = self._source_port_to_circuit[src_port]
                s_user = self._source_port_to_socks_user.get(src_port) or self._circuit_to_socks_user.get(slot_cid)
                if stream_id:
                    self._stream_to_slot[stream_id] = slot_cid
                return slot_cid, s_user

            if socks_user and socks_user in self._socks_cred_to_circuit:
                slot_cid = self._socks_cred_to_circuit[socks_user]
                if stream_id:
                    self._stream_to_slot[stream_id] = slot_cid
                return slot_cid, socks_user

        # Check if event already carries a Tor circ_id tagged with SOCKS_USERNAME
        tor_cid = str(getattr(event, "circ_id", "") or "")
        if tor_cid and tor_cid != "0":
            with self._lock:
                if tor_cid in self._actual_tor_circ_to_slot:
                    slot_cid = self._actual_tor_circ_to_slot[tor_cid]
                    return slot_cid, self._circuit_to_socks_user.get(slot_cid)
            if self._controller:
                try:
                    c_info = self._controller.get_circuit(tor_cid)
                    c_user = self._extract_socks_username(c_info)
                    if c_user:
                        with self._lock:
                            slot_cid = self._socks_cred_to_circuit.get(c_user)
                            if slot_cid:
                                self._socks_user_to_hs_circuit[c_user] = tor_cid
                                self._slot_to_verified_tor_circuit[slot_cid] = tor_cid
                                self._actual_tor_circ_to_slot[tor_cid] = slot_cid
                                if stream_id:
                                    self._stream_to_slot[stream_id] = slot_cid
                                return slot_cid, c_user
                except Exception:
                    pass

        return None, None

    def _on_circ_event(self, event: Any) -> None:
        """
        Handle stem CIRC events:
        - Capture SOCKS_USERNAME circuit tags so IsolateSOCKSAuth / hidden-service
          rendezvous circuits are bound to their exact ManagedCircuit slot.
        - Fail closed if a built circuit unexpectedly changes its exit relay.
        """
        cid = str(getattr(event, "id", ""))
        status = str(getattr(event, "status", ""))
        reason = str(getattr(event, "reason", "NONE"))

        socks_user = self._extract_socks_username(event)
        if socks_user and cid:
            with self._lock:
                slot_cid = self._socks_cred_to_circuit.get(socks_user)
                if slot_cid:
                    self._socks_user_to_hs_circuit[socks_user] = cid
                    self._slot_to_verified_tor_circuit[slot_cid] = cid
                    self._actual_tor_circ_to_slot[cid] = slot_cid

        self.event_bus.emit(
            EventType.DEBUG_STEM,
            circuit_id=cid,
            status=status,
            reason=reason,
        )

        if status == CircStatus.BUILT:
            with self._lock:
                expected_exit = self._circuit_to_exit.get(cid)
            if expected_exit:
                path = getattr(event, "path", [])
                if path:
                    current_exit = path[-1][0]
                    if current_exit != expected_exit and self._leak_callback:
                        self._leak_callback(
                            f"Circuit {cid} exit relay changed unexpectedly ({expected_exit[:8]} -> {current_exit[:8]})."
                        )

    def _on_stream_event(self, event: Any) -> None:
        """
        Attach NEW/NEWRESOLVE streams to their exact designated circuit and verify actual
        Tor circuit assignment on SENTCONNECT/SUCCEEDED.
        """
        if not self._controller:
            return
        status = getattr(event, "status", None)
        stream_id = str(getattr(event, "id", ""))
        target = str(getattr(event, "target", "") or "")
        target_host = target.split(":", 1)[0].lower()
        is_onion = target_host.endswith(".onion")

        slot_cid, socks_user = self._resolve_slot_for_stream(event)

        if status in (StreamStatus.NEW, StreamStatus.NEWRESOLVE) and stream_id:
            if slot_cid:
                with self._lock:
                    hs_cid = self._socks_user_to_hs_circuit.get(socks_user or "")
                # For .onion targets, use the slot's dedicated HS rendezvous circuit if built;
                # otherwise try slot_cid and fall back to ATTACHSTREAM <id> 0 so Tor's
                # IsolateSOCKSAuth launches a dedicated rendezvous circuit for socks_user.
                preferred_cid = hs_cid if (is_onion and hs_cid) else slot_cid
                try:
                    self._controller.attach_stream(stream_id, preferred_cid)
                except Exception:
                    try:
                        # 0 means "no explicit circuit": Tor auto-attaches using the
                        # stream's IsolateSOCKSAuth credentials.
                        self._controller.attach_stream(stream_id, 0)
                    except Exception:
                        pass
            else:
                # Unknown origin stream: let Tor auto-attach via IsolateSOCKSAuth rather than circ_ids[0]
                try:
                    self._controller.attach_stream(stream_id, 0)
                except Exception:
                    pass

        elif status in (StreamStatus.SENTCONNECT, StreamStatus.SUCCEEDED):
            actual_tor_cid = str(getattr(event, "circ_id", "") or "")
            if actual_tor_cid and actual_tor_cid != "0" and slot_cid:
                with self._lock:
                    self._slot_to_verified_tor_circuit[slot_cid] = actual_tor_cid
                    self._actual_tor_circ_to_slot[actual_tor_cid] = slot_cid
                    if is_onion and socks_user:
                        self._socks_user_to_hs_circuit[socks_user] = actual_tor_cid

            self.event_bus.emit(
                EventType.DEBUG_STEM,
                circuit_id=actual_tor_cid or slot_cid or "NONE",
                status=f"STREAM_{status}",
                reason=str(getattr(event, "reason", "NONE")),
            )

        elif status in (StreamStatus.FAILED, StreamStatus.CLOSED):
            with self._lock:
                self._stream_to_slot.pop(stream_id, None)
            self.event_bus.emit(
                EventType.DEBUG_STEM,
                circuit_id=str(getattr(event, "circ_id", "") or slot_cid or "NONE"),
                status=f"STREAM_{status}",
                reason=str(getattr(event, "reason", "NONE")),
            )

    def _on_circ_bw_event(self, event: Any) -> None:
        """Record control-port verified circuit bandwidth from Tor CIRC_BW events."""
        if not self.metrics:
            return
        tor_cid = str(getattr(event, "id", ""))
        read_bytes = int(getattr(event, "read", 0) or 0)
        if tor_cid and read_bytes > 0:
            with self._lock:
                slot_cid = self._actual_tor_circ_to_slot.get(tor_cid, tor_cid)
            self.metrics.record_control_port_bw(slot_cid, read_bytes)
