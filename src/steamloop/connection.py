"""Async connection to a thermostat over mTLS on port 7878."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import ssl
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Self

import orjson

from .certs import CERT_SETS, CertSet, create_ssl_context
from .const import (
    BACKOFF_FACTOR,
    CONNECT_TIMEOUT,
    DEFAULT_PORT,
    HEARTBEAT_INTERVAL,
    PAIRING_TIMEOUT,
    RECONNECT_DELAY,
    RECONNECT_MAX,
    RESPONSE_TIMEOUT,
    FanMode,
    HoldType,
    ZoneMode,
)
from .exceptions import (
    AuthenticationError,
    PairingError,
    SteamloopConnectionError,
    SteamloopError,
)
from .models import (
    CoolingStatusUpdatedEvent,
    EmergencyHeatUpdatedEvent,
    ErrorResponse,
    FanModeUpdatedEvent,
    HeatingStatusUpdatedEvent,
    IndoorRelativeHumidityUpdatedEvent,
    IndoorTemperatureUpdatedEvent,
    LoginResponse,
    SetSecretKeyRequest,
    SupportedZoneModesUpdatedEvent,
    TemperatureSetpointUpdatedEvent,
    ThermostatState,
    Zone,
    ZoneAddedEvent,
    ZoneModeUpdatedEvent,
    ZoneNameUpdatedEvent,
)

_LOGGER = logging.getLogger(__name__)


def _encode_message(msg: dict[str, Any]) -> bytes:
    r"""Encode a message for sending.

    Wire format: compact JSON + " " + \x00.
    The thermostat uses null-byte delimiters to find message boundaries.
    """
    return orjson.dumps(msg) + b" \x00"


def _pairing_path(ip: str, directory: Path | None = None) -> Path:
    """Return the pairing file path for a thermostat IP."""
    md5 = hashlib.md5(ip.encode()).hexdigest()  # noqa: S324
    base = directory or Path.cwd()
    return base / f"pairing_{md5}.json"


async def load_pairing(ip: str, directory: Path | None = None) -> dict[str, str] | None:
    """
    Load saved pairing data for a thermostat IP.

    Args:
        ip: Thermostat IP address.
        directory: Directory to load from. Defaults to current directory.

    Returns:
        Pairing dict with secret_key, device_type, device_id, or None.

    """
    path = _pairing_path(ip, directory)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _load_pairing_sync, path)


def _load_pairing_sync(path: Path) -> dict[str, str] | None:
    """Synchronous pairing file read."""
    try:
        return orjson.loads(path.read_bytes())  # type: ignore[no-any-return]
    except FileNotFoundError:
        return None


async def save_pairing(
    ip: str, login_info: dict[str, str], directory: Path | None = None
) -> None:
    """
    Save pairing data for a thermostat IP.

    Args:
        ip: Thermostat IP address.
        login_info: Dict with secret_key, device_type, device_id.
        directory: Directory to save to. Defaults to current directory.

    """
    path = _pairing_path(ip, directory)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _save_pairing_sync, path, login_info)
    _LOGGER.info("Pairing saved to %s", path)


def _save_pairing_sync(path: Path, login_info: dict[str, str]) -> None:
    """Synchronous pairing file write (atomic via rename)."""
    tmp_path = path.with_suffix(".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, orjson.dumps(login_info, option=orjson.OPT_INDENT_2))
    finally:
        os.close(fd)
    tmp_path.replace(path)


class ThermostatProtocol(asyncio.Protocol):
    """
    Low-level protocol handler for thermostat communication.

    Handles framing (null-byte delimited JSON) and delegates parsed
    messages to the owning ThermostatConnection.
    """

    def __init__(self, connection: ThermostatConnection) -> None:
        self._connection = connection
        self._transport: asyncio.Transport | None = None
        self._buf = bytearray()

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Called when the TLS connection is established."""
        self._transport = transport

    def data_received(self, data: bytes) -> None:
        """Called when data is received from the thermostat."""
        self._buf.extend(data)
        self._process_buffer()

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when the connection is lost."""
        self._connection._on_connection_lost(exc)  # noqa: SLF001

    def send(self, msg: dict[str, Any]) -> None:
        """Send a message to the thermostat (sync — no drain needed)."""
        if self._transport is None:
            raise SteamloopConnectionError("Not connected")
        encoded = _encode_message(msg)
        _LOGGER.debug("[>] TX %d bytes: %r", len(encoded), encoded)
        self._transport.write(encoded)

    def send_request(self, command: str, data: dict[str, str]) -> None:
        """Send a Request-wrapped command to the thermostat."""
        self.send({"Request": {command: data}})

    def close(self) -> None:
        """Close the transport."""
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._buf.clear()

    def _process_buffer(self) -> None:
        """
        Extract complete JSON messages from the buffer and dispatch them.

        Messages on the wire are terminated by a null byte (0x00).
        The JSON is extracted by finding the first '{' and last '}'
        within each null-delimited segment.  Incomplete data (no null
        terminator yet) stays in the buffer for the next data_received().
        """
        while b"\x00" in self._buf:
            idx = self._buf.index(b"\x00")
            segment = self._buf[:idx]
            del self._buf[: idx + 1]
            if not segment:
                continue
            text = segment.decode("utf-8", errors="replace")
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                try:
                    msg = orjson.loads(text[start : end + 1])
                except orjson.JSONDecodeError:
                    _LOGGER.warning(
                        "Failed to parse JSON: %s",
                        text[start : end + 1][:200],
                    )
                else:
                    self._connection._on_message(msg)  # noqa: SLF001


class ThermostatConnection:
    """
    Async connection to a thermostat over mTLS.

    After calling connect() and login(), call start_background_tasks()
    to begin sending heartbeats. Events are dispatched automatically
    via the protocol's data_received callback.

    If the connection drops, it will automatically reconnect with
    exponential backoff. Call disconnect() to stop everything.
    """

    def __init__(
        self,
        ip: str,
        port: int = DEFAULT_PORT,
        *,
        cert_set: CertSet | None = None,
        secret_key: str,
        device_type: str = "automation",
        device_id: str = "module",
    ) -> None:
        self._ip = ip
        self._port = port
        self._cert_set = cert_set
        self._secret_key = secret_key
        self._device_type = device_type
        self._device_id = device_id
        self._protocol: ThermostatProtocol | None = None
        self._transport: asyncio.Transport | None = None
        self._run_task: asyncio.Task[None] | None = None
        self._connection_lost_event = asyncio.Event()
        self._message_queue: asyncio.Queue[dict[str, Any]] | None = None
        self.state = ThermostatState()
        self._event_callbacks: list[Callable[[dict[str, Any]], None]] = []
        self._connected = False

    @property
    def connected(self) -> bool:
        """Return True if the connection is active."""
        return self._connected

    @property
    def secret_key(self) -> str:
        """Return the secret key used for authentication."""
        return self._secret_key

    def add_event_callback(
        self, callback: Callable[[dict[str, Any]], None]
    ) -> Callable[[], None]:
        """Register an event callback. Returns a callable to unregister it."""
        self._event_callbacks.append(callback)

        def _remove() -> None:
            with contextlib.suppress(ValueError):
                self._event_callbacks.remove(callback)

        return _remove

    # --- Connection lifecycle ---

    async def connect(self) -> None:
        """
        Establish the TLS connection to the thermostat.

        If no cert_set was specified, tries each cert set in order until
        one succeeds.  If already connected, the existing connection is
        closed first.

        Raises:
            SteamloopConnectionError: If the connection fails.

        """
        if self._connected:
            self._close_transport()

        if self._cert_set is not None:
            await self._connect_with_cert_set(self._cert_set)
            return

        last_exc: Exception | None = None
        for cert_set in CERT_SETS:
            try:
                await self._connect_with_cert_set(cert_set)
            except SteamloopConnectionError as exc:  # noqa: PERF203
                _LOGGER.warning("Failed with %s certs: %s", cert_set.name, exc)
                last_exc = exc
            else:
                self._cert_set = cert_set
                return
        raise SteamloopConnectionError(
            f"Could not connect with any certificate set: {last_exc}"
        )

    async def _connect_with_cert_set(self, cert_set: CertSet) -> None:
        """Connect using a specific certificate set."""
        loop = asyncio.get_running_loop()
        ssl_ctx = await loop.run_in_executor(None, create_ssl_context, cert_set)
        _LOGGER.info(
            "Connecting to %s:%s using %s certificates...",
            self._ip,
            self._port,
            cert_set.name,
        )
        try:
            self._transport, self._protocol = await asyncio.wait_for(
                loop.create_connection(
                    lambda: ThermostatProtocol(self),
                    self._ip,
                    self._port,
                    ssl=ssl_ctx,
                ),
                timeout=CONNECT_TIMEOUT,
            )
        except ssl.SSLCertVerificationError as exc:
            raise SteamloopConnectionError(
                f"TLS cert verification failed: {exc!r}"
            ) from exc
        except ssl.SSLError as exc:
            raise SteamloopConnectionError(
                f"TLS handshake failed: {exc!r} "
                f"(errno={exc.errno}, "
                f"reason={getattr(exc, 'reason', 'unknown')})"
            ) from exc
        except TimeoutError as exc:
            raise SteamloopConnectionError(
                f"Connection timed out after {CONNECT_TIMEOUT}s"
            ) from exc
        except OSError as exc:
            raise SteamloopConnectionError(f"TCP connect failed: {exc!r}") from exc
        self._connected = True
        self._connection_lost_event.clear()
        _LOGGER.info("TLS connected to %s:%s", self._ip, self._port)

    def _close_transport(self) -> None:
        """Close the underlying transport."""
        self._connected = False
        if self._protocol is not None:
            self._protocol.close()
            self._protocol = None
        self._transport = None

    # --- Sending ---

    def send(self, msg: dict[str, Any]) -> None:
        """
        Send a message to the thermostat.

        Raises:
            SteamloopConnectionError: If not connected.

        """
        if self._protocol is None:
            raise SteamloopConnectionError("Not connected")
        self._protocol.send(msg)

    def send_request(self, command: str, data: dict[str, str]) -> None:
        """Send a Request-wrapped command to the thermostat."""
        if self._protocol is None:
            raise SteamloopConnectionError("Not connected")
        self._protocol.send_request(command, data)

    # --- Message handling ---

    def _on_message(self, msg: dict[str, Any]) -> None:
        """Called by the protocol for every complete message."""
        self._dispatch(msg)
        if self._message_queue is not None:
            self._message_queue.put_nowait(msg)

    def _on_connection_lost(self, exc: Exception | None) -> None:
        """Called by the protocol when the connection drops."""
        self._connected = False
        if exc:
            _LOGGER.warning("Connection lost: %s", exc)
        else:
            _LOGGER.warning("Connection closed by thermostat")
        self._connection_lost_event.set()

    def _dispatch(self, msg: dict[str, Any]) -> None:
        """Update internal state from a message and notify callbacks."""
        if "Event" in msg:
            self._process_event(msg["Event"])
        for cb in self._event_callbacks:
            try:
                cb(msg)
            except Exception:  # noqa: PERF203
                _LOGGER.exception("Error in event callback")

    def _get_zone(self, zone_id: str) -> Zone:
        """Get or create a zone by ID."""
        return self.state.zones.setdefault(zone_id, Zone(zone_id=zone_id))

    def _process_event(self, event: dict[str, Any]) -> None:
        """
        Process a single event and update thermostat state.

        Each Event dict contains exactly one key (the event type).
        """
        for event_type, data in event.items():
            handler = self._EVENT_HANDLERS.get(event_type)
            if handler is not None:
                try:
                    handler(self, data)
                except (KeyError, ValueError, TypeError) as exc:
                    _LOGGER.warning("Error handling %s event: %s", event_type, exc)

    def _handle_zone_added(self, data: ZoneAddedEvent) -> None:
        zid = data["zone_id"]
        if zid not in self.state.zones:
            self.state.zones[zid] = Zone(zone_id=zid)

    def _handle_zone_name_updated(self, data: ZoneNameUpdatedEvent) -> None:
        self._get_zone(data["zone_id"]).name = data["zone_name"]

    def _handle_indoor_temperature_updated(
        self, data: IndoorTemperatureUpdatedEvent
    ) -> None:
        self._get_zone(data["zone_id"]).indoor_temperature = data["indoor_temperature"]

    def _handle_temperature_setpoint_updated(
        self, data: TemperatureSetpointUpdatedEvent
    ) -> None:
        zone = self._get_zone(data["zone_id"])
        zone.heat_setpoint = data.get("heat_setpoint", zone.heat_setpoint)
        zone.cool_setpoint = data.get("cool_setpoint", zone.cool_setpoint)
        zone.deadband = data.get("deadband", zone.deadband)
        hold_str = data.get("hold_type")
        if hold_str is not None:
            zone.hold_type = HoldType(int(hold_str))

    def _handle_zone_mode_updated(self, data: ZoneModeUpdatedEvent) -> None:
        self._get_zone(data["zone_id"]).mode = ZoneMode(int(data["zone_mode"]))

    def _handle_supported_zone_modes_updated(
        self, data: SupportedZoneModesUpdatedEvent
    ) -> None:
        modes: list[ZoneMode] = []
        for raw in data["modes"].split(","):
            stripped = raw.strip()
            if stripped:
                with contextlib.suppress(ValueError):
                    modes.append(ZoneMode(int(stripped)))
        self.state.supported_modes = modes

    def _handle_fan_mode_updated(self, data: FanModeUpdatedEvent) -> None:
        self.state.fan_mode = FanMode(int(data["fan_mode"]))

    def _handle_emergency_heat_updated(self, data: EmergencyHeatUpdatedEvent) -> None:
        self.state.emergency_heat = data["emergency_heat"]

    def _handle_indoor_relative_humidity_updated(
        self, data: IndoorRelativeHumidityUpdatedEvent
    ) -> None:
        self.state.relative_humidity = data["relative_humidity"]

    def _handle_cooling_status_updated(self, data: CoolingStatusUpdatedEvent) -> None:
        self.state.cooling_active = data["cooling_active"]

    def _handle_heating_status_updated(self, data: HeatingStatusUpdatedEvent) -> None:
        self.state.heating_active = data["heating_active"]

    _EVENT_HANDLERS: ClassVar[dict[str, Callable[..., None]]] = {
        "ZoneAdded": _handle_zone_added,
        "ZoneNameUpdated": _handle_zone_name_updated,
        "IndoorTemperatureUpdated": _handle_indoor_temperature_updated,
        "TemperatureSetpointUpdated": _handle_temperature_setpoint_updated,
        "ZoneModeUpdated": _handle_zone_mode_updated,
        "SupportedZoneModesUpdated": _handle_supported_zone_modes_updated,
        "FanModeUpdated": _handle_fan_mode_updated,
        "EmergencyHeatUpdated": _handle_emergency_heat_updated,
        "IndoorRelativeHumidityUpdated": _handle_indoor_relative_humidity_updated,
        "CoolingStatusUpdated": _handle_cooling_status_updated,
        "HeatingStatusUpdated": _handle_heating_status_updated,
    }

    # --- Login / Pairing ---

    async def login(self) -> LoginResponse:
        """
        Authenticate with the thermostat.

        Returns:
            LoginResponse on success.

        Raises:
            AuthenticationError: If authentication fails.
            SteamloopConnectionError: If the connection is lost.

        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._message_queue = queue
        try:
            self.send_request(
                "Login",
                {
                    "device_id": self._device_id,
                    "device_type": self._device_type,
                    "secret_key": self._secret_key,
                },
            )
            loop = asyncio.get_running_loop()
            deadline = loop.time() + RESPONSE_TIMEOUT
            while (remaining := deadline - loop.time()) > 0:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=remaining)
                except TimeoutError:
                    break
                if "Response" not in msg:
                    continue
                resp = msg["Response"]
                if "LoginResponse" in resp:
                    login_resp: LoginResponse = resp["LoginResponse"]
                    if login_resp.get("status") == "1":
                        _LOGGER.info("Authenticated successfully")
                        return login_resp
                    raise AuthenticationError(f"Authentication failed: {login_resp}")
                if "Error" in resp:
                    err: ErrorResponse = resp["Error"]
                    raise AuthenticationError(
                        f"Error {err.get('error_type')}: {err.get('description')}"
                    )
        finally:
            self._message_queue = None
        raise AuthenticationError("No login response received")

    async def pair(self) -> SetSecretKeyRequest:
        """
        Pair with the thermostat.

        The thermostat must be in pairing mode. Sends a login request with
        an empty secret key and waits for the thermostat to send a
        SetSecretKey request containing the new secret key.

        Returns:
            SetSecretKeyRequest with the new secret_key.

        Raises:
            PairingError: If pairing fails or times out.
            SteamloopConnectionError: If the connection is lost.

        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._message_queue = queue
        try:
            self.send_request(
                "Login",
                {
                    "device_id": self._device_id,
                    "device_type": self._device_type,
                    "secret_key": "",
                },
            )
            _LOGGER.info(
                "Waiting for pairing response (put thermostat in pairing mode)..."
            )
            loop = asyncio.get_running_loop()
            deadline = loop.time() + PAIRING_TIMEOUT
            while (remaining := deadline - loop.time()) > 0:
                try:
                    msg = await asyncio.wait_for(
                        queue.get(), timeout=min(remaining, 5.0)
                    )
                except TimeoutError:
                    continue
                if "Request" in msg and "SetSecretKey" in msg.get("Request", {}):
                    ssk: SetSecretKeyRequest = msg["Request"]["SetSecretKey"]
                    secret_key = ssk["secret_key"]
                    self._secret_key = secret_key
                    _LOGGER.debug("Received secret key")
                    self.send(
                        {
                            "Response": {
                                "SecretKeyUpdated": {
                                    "secret_key": secret_key,
                                }
                            }
                        }
                    )
                    return ssk
                if "Response" in msg:
                    resp = msg["Response"]
                    if "LoginResponse" in resp:
                        status = resp["LoginResponse"].get("status")
                        if status == "1":
                            # Login accepted — the thermostat typically
                            # sends SetSecretKey next, so keep waiting.
                            _LOGGER.info("Login accepted, waiting for secret key...")
                            continue
                        raise PairingError(
                            f"Thermostat rejected pairing (status={status})"
                        )
                    if "Error" in resp:
                        err = resp["Error"]
                        raise PairingError(
                            f"Pairing error {err.get('error_type')}: "
                            f"{err.get('description')}"
                        )
        finally:
            self._message_queue = None
        raise PairingError(f"Pairing timeout — no response in {PAIRING_TIMEOUT}s")

    # --- Background tasks ---

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to keep the connection alive."""
        while self._connected:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            if self._connected and self._protocol is not None:
                self._protocol.send({"Heartbeat": {}})

    async def _run_loop(self) -> None:
        """
        Main background loop: send heartbeats, auto-reconnect on failure.

        Events are dispatched by the protocol's data_received callback.
        This loop just manages heartbeats and reconnection.
        """
        delay = RECONNECT_DELAY
        try:
            while True:
                heartbeat = asyncio.create_task(self._heartbeat_loop())
                try:
                    await self._connection_lost_event.wait()
                finally:
                    self._connected = False
                    heartbeat.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await heartbeat
                    self._close_transport()

                # Reconnect with exponential backoff
                while True:
                    _LOGGER.info("Reconnecting in %.0fs...", delay)
                    await asyncio.sleep(delay)
                    try:
                        await self.connect()
                        self.state = ThermostatState()
                        await self.login()
                        _LOGGER.info("Reconnected successfully")
                        delay = RECONNECT_DELAY
                        break
                    except (SteamloopError, OSError) as exc:
                        _LOGGER.warning("Reconnect failed: %s", exc)
                        self._close_transport()
                        delay = min(delay * BACKOFF_FACTOR, RECONNECT_MAX)
        except asyncio.CancelledError:
            return

    def start_background_tasks(self) -> None:
        """Start the background loop with heartbeats and auto-reconnect."""
        self._run_task = asyncio.create_task(self._run_loop())

    async def disconnect(self) -> None:
        """Disconnect from the thermostat and stop all background tasks."""
        if self._run_task:
            self._run_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._run_task
            self._run_task = None
        self._close_transport()
        _LOGGER.info("Disconnected")

    async def __aenter__(self) -> Self:
        """Connect, login, and start background tasks."""
        await self.connect()
        try:
            await self.login()
        except BaseException:
            self._close_transport()
            raise
        self.start_background_tasks()
        return self

    async def __aexit__(self, *args: object) -> None:
        """Disconnect and stop all background tasks."""
        await self.disconnect()

    # --- Command helpers ---

    def set_temperature_setpoint(
        self,
        zone_id: str,
        *,
        heat_setpoint: str | None = None,
        cool_setpoint: str | None = None,
        hold_type: HoldType = HoldType.MANUAL,
    ) -> None:
        """
        Set temperature setpoints for a zone.

        If a setpoint isn't provided, the current state value is used.
        Deadband is always taken from current state. If the resulting
        setpoints would violate the deadband, the opposite setpoint is
        automatically adjusted to maintain the minimum gap:

        - If only heat_setpoint is provided, cool is raised if needed.
        - If only cool_setpoint is provided, heat is lowered if needed.
        - If both are provided, cool is raised to maintain the gap.
        """
        zone = self.state.zones.get(zone_id)
        db = float(zone.deadband) if zone and zone.deadband else 3.0
        heat_requested = heat_setpoint is not None
        cool_requested = cool_setpoint is not None
        if heat_setpoint is None:
            heat_setpoint = zone.heat_setpoint if zone else "55"
        if cool_setpoint is None:
            cool_setpoint = zone.cool_setpoint if zone else "75"
        heat_f = float(heat_setpoint)
        cool_f = float(cool_setpoint)
        if cool_f - heat_f < db:
            if cool_requested and not heat_requested:
                # Only cool was requested — lower heat
                heat_f = cool_f - db
                heat_setpoint = str(int(heat_f))
            else:
                # Only heat was requested, or both — raise cool
                cool_f = heat_f + db
                cool_setpoint = str(int(cool_f))
        self.send_request(
            "UpdateTemperatureSetpoint",
            {
                "zone_id": zone_id,
                "heat_setpoint": heat_setpoint,
                "cool_setpoint": cool_setpoint,
                "deadband": str(int(db)),
                "hold_type": str(int(hold_type)),
            },
        )

    def set_fan_mode(self, mode: FanMode | int) -> None:
        """Set the fan operating mode."""
        self.send_request("UpdateFanMode", {"fan_mode": str(int(mode))})

    def set_zone_mode(self, zone_id: str, mode: ZoneMode | int) -> None:
        """Set the HVAC mode for a zone."""
        self.send_request(
            "UpdateZoneMode",
            {"zone_id": zone_id, "zone_mode": str(int(mode))},
        )

    def set_emergency_heat(self, enabled: bool) -> None:
        """Enable or disable emergency heat."""
        self.send_request(
            "UpdateEmergencyHeat",
            {"emergency_heat": "1" if enabled else "2"},
        )

    def heartbeat(self) -> None:
        """Send a heartbeat to keep the connection alive."""
        self.send({"Heartbeat": {}})
