"""Tests for CLI command handling."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from steamloop.cli import (
    _do_monitor,
    _do_pair,
    _handle_command,
    _print_state,
    main,
)
from steamloop.const import FanMode, HoldType, ZoneMode
from steamloop.exceptions import SteamloopConnectionError, SteamloopError
from steamloop.models import ThermostatState, Zone


def _make_mock_conn(
    zones: dict[str, Zone] | None = None,
) -> MagicMock:
    """Create a mock ThermostatConnection with state."""
    conn = MagicMock()
    state = ThermostatState()
    if zones:
        state.zones = zones
    conn.state = state
    return conn


def test_command_quit() -> None:
    conn = _make_mock_conn()
    result = _handle_command(conn, "quit", ["quit"], "1")
    assert result is None


def test_command_quit_short() -> None:
    conn = _make_mock_conn()
    result = _handle_command(conn, "q", ["q"], "1")
    assert result is None


def test_command_status(capsys: pytest.CaptureFixture[str]) -> None:
    zones = {"1": Zone(zone_id="1", name="Main", indoor_temperature="72")}
    conn = _make_mock_conn(zones)
    result = _handle_command(conn, "status", ["status"], "1")
    assert result == "1"
    captured = capsys.readouterr()
    assert "Thermostat State" in captured.out
    assert "Main" in captured.out
    assert "72" in captured.out


def test_command_zone_switch(capsys: pytest.CaptureFixture[str]) -> None:
    zones = {
        "1": Zone(zone_id="1", name="Main"),
        "2": Zone(zone_id="2", name="Upstairs"),
    }
    conn = _make_mock_conn(zones)
    result = _handle_command(conn, "zone 2", ["zone", "2"], "1")
    assert result == "2"
    captured = capsys.readouterr()
    assert "Upstairs" in captured.out


def test_command_zone_not_found(capsys: pytest.CaptureFixture[str]) -> None:
    zones = {"1": Zone(zone_id="1", name="Main")}
    conn = _make_mock_conn(zones)
    result = _handle_command(conn, "zone 5", ["zone", "5"], "1")
    assert result == "1"  # Unchanged
    captured = capsys.readouterr()
    assert "not found" in captured.out


def test_command_heat(capsys: pytest.CaptureFixture[str]) -> None:
    conn = _make_mock_conn()
    result = _handle_command(conn, "heat 70", ["heat", "70"], "1")
    assert result == "1"
    conn.set_temperature_setpoint.assert_called_once_with("1", heat_setpoint="70")
    captured = capsys.readouterr()
    assert "heat setpoint" in captured.out


def test_command_cool(capsys: pytest.CaptureFixture[str]) -> None:
    conn = _make_mock_conn()
    result = _handle_command(conn, "cool 74", ["cool", "74"], "1")
    assert result == "1"
    conn.set_temperature_setpoint.assert_called_once_with("1", cool_setpoint="74")
    captured = capsys.readouterr()
    assert "cool setpoint" in captured.out


def test_command_setpoint(capsys: pytest.CaptureFixture[str]) -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "setpoint 68 76", ["setpoint", "68", "76"], "1")
    conn.set_temperature_setpoint.assert_called_once_with(
        "1", heat_setpoint="68", cool_setpoint="76"
    )


def test_command_hold() -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "hold manual", ["hold", "manual"], "1")
    conn.set_temperature_setpoint.assert_called_once_with(
        "1", hold_type=HoldType.MANUAL
    )


def test_command_hold_unknown(capsys: pytest.CaptureFixture[str]) -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "hold forever", ["hold", "forever"], "1")
    conn.set_temperature_setpoint.assert_not_called()
    captured = capsys.readouterr()
    assert "Unknown hold type" in captured.out


def test_command_mode() -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "mode cool", ["mode", "cool"], "1")
    conn.set_zone_mode.assert_called_once_with("1", ZoneMode.COOL)


def test_command_mode_unknown(capsys: pytest.CaptureFixture[str]) -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "mode turbo", ["mode", "turbo"], "1")
    conn.set_zone_mode.assert_not_called()
    captured = capsys.readouterr()
    assert "Unknown mode" in captured.out


def test_command_fan() -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "fan auto", ["fan", "auto"], "1")
    conn.set_fan_mode.assert_called_once_with(FanMode.AUTO)


def test_command_fan_unknown(capsys: pytest.CaptureFixture[str]) -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "fan turbo", ["fan", "turbo"], "1")
    conn.set_fan_mode.assert_not_called()
    captured = capsys.readouterr()
    assert "Unknown fan mode" in captured.out


def test_command_eheat_on() -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "eheat on", ["eheat", "on"], "1")
    conn.set_emergency_heat.assert_called_once_with(True)


def test_command_eheat_off() -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "eheat off", ["eheat", "off"], "1")
    conn.set_emergency_heat.assert_called_once_with(False)


def test_command_raw_json() -> None:
    conn = _make_mock_conn()
    _handle_command(conn, 'raw {"Heartbeat":{}}', ["raw", '{"heartbeat":{}}'], "1")
    conn.send.assert_called_once()


def test_command_raw_invalid_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "raw {bad", ["raw", "{bad"], "1")
    conn.send.assert_not_called()
    captured = capsys.readouterr()
    assert "Invalid JSON" in captured.out


def test_command_ping() -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "ping", ["ping"], "1")
    conn.heartbeat.assert_called_once()


def test_command_help(capsys: pytest.CaptureFixture[str]) -> None:
    conn = _make_mock_conn()
    _handle_command(conn, "help", ["help"], "1")
    captured = capsys.readouterr()
    assert "Commands:" in captured.out


def test_command_unknown(capsys: pytest.CaptureFixture[str]) -> None:
    conn = _make_mock_conn()
    result = _handle_command(conn, "foobar", ["foobar"], "1")
    assert result == "1"
    captured = capsys.readouterr()
    assert "Unknown command" in captured.out


def test_print_state(capsys: pytest.CaptureFixture[str]) -> None:
    state = ThermostatState()
    state.zones["1"] = Zone(
        zone_id="1",
        name="Living Room",
        mode=ZoneMode.COOL,
        indoor_temperature="73",
        heat_setpoint="68",
        cool_setpoint="76",
        deadband="3",
        hold_type=HoldType.SCHEDULE,
    )
    state.fan_mode = FanMode.CIRCULATE
    state.emergency_heat = "2"
    state.relative_humidity = "45"
    state.cooling_active = "2"
    state.heating_active = "1"
    state.supported_modes = [ZoneMode.OFF, ZoneMode.COOL, ZoneMode.HEAT]
    _print_state(state)
    captured = capsys.readouterr()
    assert "Living Room" in captured.out
    assert "73" in captured.out
    assert "Circulate" in captured.out
    assert "OFF, COOL, HEAT" in captured.out


# ---------------------------------------------------------------------------
# _cmd_heat / _cmd_cool with no zone in state
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _do_pair
# ---------------------------------------------------------------------------


async def test_do_pair_success(capsys: pytest.CaptureFixture[str]) -> None:
    mock_conn = AsyncMock()
    mock_conn.pair.return_value = {"secret_key": "abc123"}
    mock_conn.disconnect = AsyncMock()

    with (
        patch(
            "steamloop.cli.ThermostatConnection",
            return_value=mock_conn,
        ),
        patch("steamloop.cli.save_pairing", new_callable=AsyncMock) as mock_save,
        patch("steamloop.cli._do_monitor", new_callable=AsyncMock) as mock_monitor,
        patch("steamloop.cli.asyncio.sleep", new_callable=AsyncMock),
    ):
        await _do_pair("192.168.1.100", 7878)
    mock_save.assert_called_once()
    mock_monitor.assert_called_once()
    captured = capsys.readouterr()
    assert "Pairing complete" in captured.out


async def test_do_pair_failure(capsys: pytest.CaptureFixture[str]) -> None:
    mock_conn = AsyncMock()
    mock_conn.connect = AsyncMock(side_effect=SteamloopError("fail"))
    mock_conn.disconnect = AsyncMock()

    with patch(
        "steamloop.cli.ThermostatConnection",
        return_value=mock_conn,
    ):
        await _do_pair("192.168.1.100", 7878)
    captured = capsys.readouterr()
    assert "Pairing failed" in captured.out


async def test_do_pair_empty_secret_key(
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_conn = AsyncMock()
    mock_conn.pair.return_value = {"secret_key": ""}
    mock_conn.disconnect = AsyncMock()

    with (
        patch(
            "steamloop.cli.ThermostatConnection",
            return_value=mock_conn,
        ),
        patch("steamloop.cli._do_monitor", new_callable=AsyncMock) as mock_monitor,
        patch("steamloop.cli.asyncio.sleep", new_callable=AsyncMock),
    ):
        await _do_pair("192.168.1.100", 7878)
    mock_monitor.assert_called_once()
    captured = capsys.readouterr()
    assert "Already paired" in captured.out


# ---------------------------------------------------------------------------
# _do_monitor
# ---------------------------------------------------------------------------


async def test_do_monitor_no_pairing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch(
        "steamloop.cli.load_pairing",
        new_callable=AsyncMock,
        return_value=None,
    ):
        await _do_monitor("192.168.1.100", 7878)
    captured = capsys.readouterr()
    assert "No pairing found" in captured.out


async def test_do_monitor_connection_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_conn = MagicMock()
    mock_conn.__aenter__ = AsyncMock(side_effect=SteamloopError("connect fail"))
    mock_conn.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(
            "steamloop.cli.load_pairing",
            new_callable=AsyncMock,
            return_value={"secret_key": "sk"},
        ),
        patch(
            "steamloop.cli.ThermostatConnection",
            return_value=mock_conn,
        ),
    ):
        await _do_monitor("192.168.1.100", 7878)
    captured = capsys.readouterr()
    assert "Connection failed" in captured.out


async def test_do_monitor_quit_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_conn = MagicMock()
    mock_conn.connected = True
    mock_conn.state = ThermostatState()
    mock_conn.state.zones["1"] = Zone(zone_id="1", name="Main")
    event_cb = None

    def _capture_callback(cb: Any) -> Any:
        nonlocal event_cb
        event_cb = cb
        return lambda: None

    mock_conn.add_event_callback = _capture_callback

    async def _mock_aenter(self: Any) -> MagicMock:
        return mock_conn

    mock_conn.__aenter__ = _mock_aenter
    mock_conn.__aexit__ = AsyncMock(return_value=False)

    lines = iter(["status\n", "quit\n"])

    with (
        patch(
            "steamloop.cli.load_pairing",
            new_callable=AsyncMock,
            return_value={"secret_key": "sk"},
        ),
        patch(
            "steamloop.cli.ThermostatConnection",
            return_value=mock_conn,
        ),
        patch(
            "steamloop.cli.sys.stdin",
        ) as mock_stdin,
    ):
        mock_stdin.readline.side_effect = lambda: next(lines)
        await _do_monitor("192.168.1.100", 7878)

    # Verify event callback was captured and works
    assert event_cb is not None
    event_cb({"Heartbeat": {}})

    captured = capsys.readouterr()
    assert "Disconnected" in captured.out
    # The status command exercised active_zone = result (line 325)
    assert "Thermostat State" in captured.out


async def test_do_monitor_eof(
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_conn = MagicMock()
    mock_conn.connected = True
    mock_conn.state = ThermostatState()
    mock_conn.add_event_callback = MagicMock(return_value=lambda: None)

    async def _mock_aenter(self: Any) -> MagicMock:
        return mock_conn

    mock_conn.__aenter__ = _mock_aenter
    mock_conn.__aexit__ = AsyncMock(return_value=False)

    def _readline_raises() -> str:
        raise EOFError

    with (
        patch(
            "steamloop.cli.load_pairing",
            new_callable=AsyncMock,
            return_value={"secret_key": "sk"},
        ),
        patch(
            "steamloop.cli.ThermostatConnection",
            return_value=mock_conn,
        ),
        patch(
            "steamloop.cli.sys.stdin",
        ) as mock_stdin,
    ):
        mock_stdin.readline.side_effect = _readline_raises
        await _do_monitor("192.168.1.100", 7878)
    captured = capsys.readouterr()
    assert "Disconnected" in captured.out


async def test_do_monitor_connection_error_during_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_conn = MagicMock()
    mock_conn.connected = True
    mock_conn.state = ThermostatState()
    mock_conn.add_event_callback = MagicMock(return_value=lambda: None)

    async def _mock_aenter(self: Any) -> MagicMock:
        return mock_conn

    mock_conn.__aenter__ = _mock_aenter
    mock_conn.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(
            "steamloop.cli.load_pairing",
            new_callable=AsyncMock,
            return_value={"secret_key": "sk"},
        ),
        patch(
            "steamloop.cli.ThermostatConnection",
            return_value=mock_conn,
        ),
        patch(
            "steamloop.cli._handle_command",
            side_effect=SteamloopConnectionError("lost"),
        ),
        patch(
            "steamloop.cli.sys.stdin",
        ) as mock_stdin,
    ):
        mock_stdin.readline.return_value = "status\n"
        await _do_monitor("192.168.1.100", 7878)
    captured = capsys.readouterr()
    assert "Connection error" in captured.out


async def test_do_monitor_empty_input(
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_conn = MagicMock()
    call_count = 0
    mock_conn.state = ThermostatState()
    mock_conn.add_event_callback = MagicMock(return_value=lambda: None)

    def _connected() -> bool:
        nonlocal call_count
        call_count += 1
        return call_count <= 2

    type(mock_conn).connected = property(lambda self: _connected())

    async def _mock_aenter(self: Any) -> MagicMock:
        return mock_conn

    mock_conn.__aenter__ = _mock_aenter
    mock_conn.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(
            "steamloop.cli.load_pairing",
            new_callable=AsyncMock,
            return_value={"secret_key": "sk"},
        ),
        patch(
            "steamloop.cli.ThermostatConnection",
            return_value=mock_conn,
        ),
        patch(
            "steamloop.cli.sys.stdin",
        ) as mock_stdin,
    ):
        mock_stdin.readline.return_value = "\n"
        await _do_monitor("192.168.1.100", 7878)


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


async def test_do_monitor_keyboard_interrupt(
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_conn = MagicMock()
    mock_conn.connected = True
    mock_conn.state = ThermostatState()
    mock_conn.add_event_callback = MagicMock(return_value=lambda: None)

    async def _mock_aenter(self: Any) -> MagicMock:
        return mock_conn

    mock_conn.__aenter__ = _mock_aenter
    mock_conn.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(
            "steamloop.cli.load_pairing",
            new_callable=AsyncMock,
            return_value={"secret_key": "sk"},
        ),
        patch(
            "steamloop.cli.ThermostatConnection",
            return_value=mock_conn,
        ),
        patch(
            "steamloop.cli.sys.stdin",
        ) as mock_stdin,
    ):
        mock_stdin.readline.side_effect = KeyboardInterrupt
        await _do_monitor("192.168.1.100", 7878)
    captured = capsys.readouterr()
    assert "Disconnected" in captured.out


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def test_main_pair_mode() -> None:
    sentinel = object()
    with (
        patch(
            "steamloop.cli.argparse.ArgumentParser.parse_args",
            return_value=MagicMock(
                ip="192.168.1.100", port=7878, pair=True, debug=False
            ),
        ),
        patch(
            "steamloop.cli._do_pair",
            new_callable=lambda: MagicMock(return_value=sentinel),
        ),
        patch("steamloop.cli.asyncio.run") as mock_run,
    ):
        main()
    mock_run.assert_called_once_with(sentinel)


def test_main_monitor_mode() -> None:
    sentinel = object()
    with (
        patch(
            "steamloop.cli.argparse.ArgumentParser.parse_args",
            return_value=MagicMock(
                ip="192.168.1.100", port=7878, pair=False, debug=False
            ),
        ),
        patch(
            "steamloop.cli._do_monitor",
            new_callable=lambda: MagicMock(return_value=sentinel),
        ),
        patch("steamloop.cli.asyncio.run") as mock_run,
    ):
        main()
    mock_run.assert_called_once_with(sentinel)


def test_main_debug_mode() -> None:
    with (
        patch(
            "steamloop.cli.argparse.ArgumentParser.parse_args",
            return_value=MagicMock(
                ip="192.168.1.100", port=7878, pair=False, debug=True
            ),
        ),
        patch(
            "steamloop.cli._do_monitor",
            new_callable=lambda: MagicMock(return_value=None),
        ),
        patch("steamloop.cli.asyncio.run"),
        patch("steamloop.cli.logging.basicConfig") as mock_logging,
    ):
        main()
    import logging

    mock_logging.assert_called_once()
    assert mock_logging.call_args[1]["level"] == logging.DEBUG
