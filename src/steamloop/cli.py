"""Command-line interface for steamloop thermostat control."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Any

import orjson

from .connection import ThermostatConnection, load_pairing, save_pairing
from .const import DEFAULT_PORT, FanMode, HoldType, ZoneMode
from .exceptions import SteamloopConnectionError, SteamloopError
from .models import ThermostatState

_LOGGER = logging.getLogger(__name__)

_EHEAT_LABELS = {"": "N/A", "1": "On", "2": "Off"}
_ACTIVE_LABELS = {"": "N/A", "1": "Inactive", "2": "Active"}

_HOLD_MAP: dict[str, HoldType] = {
    "manual": HoldType.MANUAL,
    "man": HoldType.MANUAL,
    "schedule": HoldType.SCHEDULE,
    "sched": HoldType.SCHEDULE,
    "hold": HoldType.HOLD,
    "next": HoldType.HOLD,
}
_MODE_MAP: dict[str, ZoneMode] = {
    "off": ZoneMode.OFF,
    "auto": ZoneMode.AUTO,
    "cool": ZoneMode.COOL,
    "heat": ZoneMode.HEAT,
}
_FAN_MAP: dict[str, FanMode] = {
    "auto": FanMode.AUTO,
    "on": FanMode.ALWAYS_ON,
    "always": FanMode.ALWAYS_ON,
    "circulate": FanMode.CIRCULATE,
}


def _print_state(state: ThermostatState) -> None:
    """Display the current thermostat state."""
    fan = state.fan_mode.name.replace("_", " ").title()
    eheat = _EHEAT_LABELS.get(state.emergency_heat, state.emergency_heat)
    cooling = _ACTIVE_LABELS.get(state.cooling_active, state.cooling_active)
    heating = _ACTIVE_LABELS.get(state.heating_active, state.heating_active)
    modes = ", ".join(m.name for m in state.supported_modes)
    print("\n--- Thermostat State ---")
    print(f"  Fan mode: {fan}")
    print(f"  Emergency heat: {eheat}")
    print(f"  Relative humidity: {state.relative_humidity}%")
    print(f"  Cooling: {cooling}")
    print(f"  Heating: {heating}")
    print(f"  Supported modes: {modes}")
    for zid, zone in sorted(state.zones.items()):
        print(f"  Zone {zid} ({zone.name}):")
        print(f"    Temperature: {zone.indoor_temperature}\u00b0F")
        print(f"    Mode: {zone.mode.name}")
        print(f"    Heat setpoint: {zone.heat_setpoint}\u00b0F")
        print(f"    Cool setpoint: {zone.cool_setpoint}\u00b0F")
        print(f"    Deadband: {zone.deadband}")
        print(f"    Hold: {zone.hold_type.name.title()}")
    print("------------------------\n")


def _print_help(active_zone: str) -> None:
    """Display available commands."""
    print("Commands:")
    print("  status                      Show thermostat state")
    print(
        f"  zone <id>                   "
        f"Select active zone (current: {active_zone})"
    )
    print("  heat <temp>                 Set heat setpoint")
    print("  cool <temp>                 Set cool setpoint")
    print("  setpoint <heat> <cool>      Set both setpoints")
    print("  hold <manual|schedule|hold> Set hold type")
    print("  mode <off|auto|cool|heat>   Set zone HVAC mode")
    print("  fan <auto|on|circulate>     Set fan mode")
    print("  eheat <on|off>              Set emergency heat")
    print("  raw <json>                  Send raw JSON message")
    print("  ping                        Send heartbeat")
    print("  quit                        Disconnect and exit")


def _cmd_heat(
    conn: ThermostatConnection, active_zone: str, temp: str
) -> None:
    """Handle the heat command."""
    print(f"Setting heat setpoint to {temp} (zone {active_zone})")
    conn.set_temperature_setpoint(active_zone, heat_setpoint=temp)


def _cmd_cool(
    conn: ThermostatConnection, active_zone: str, temp: str
) -> None:
    """Handle the cool command."""
    print(f"Setting cool setpoint to {temp} (zone {active_zone})")
    conn.set_temperature_setpoint(active_zone, cool_setpoint=temp)


def _handle_command(
    conn: ThermostatConnection,
    cmd: str,
    parts: list[str],
    active_zone: str,
) -> str | None:
    """Handle a single interactive command.

    Returns the (possibly updated) active_zone, or None to quit.
    """
    if parts[0] in ("quit", "q"):
        return None

    if parts[0] == "status":
        _print_state(conn.state)

    elif parts[0] == "zone" and len(parts) >= 2:
        zid = parts[1]
        if zid in conn.state.zones:
            active_zone = zid
            print(f"Active zone: {zid} ({conn.state.zones[zid].name})")
        else:
            available = ", ".join(sorted(conn.state.zones))
            print(f"Zone {zid} not found. Available: {available}")

    elif parts[0] == "heat" and len(parts) >= 2:
        _cmd_heat(conn, active_zone, parts[1])

    elif parts[0] == "cool" and len(parts) >= 2:
        _cmd_cool(conn, active_zone, parts[1])

    elif parts[0] == "setpoint" and len(parts) >= 3:
        print(
            f"Setting heat={parts[1]}, cool={parts[2]} "
            f"(zone {active_zone})"
        )
        conn.set_temperature_setpoint(
            active_zone, heat_setpoint=parts[1], cool_setpoint=parts[2]
        )

    elif parts[0] == "hold" and len(parts) >= 2:
        ht = _HOLD_MAP.get(parts[1])
        if ht is not None:
            print(
                f"Setting hold type to {parts[1]} (zone {active_zone})"
            )
            conn.set_temperature_setpoint(active_zone, hold_type=ht)
        else:
            print(
                f"Unknown hold type: {parts[1]}. "
                "Try: manual, schedule, hold"
            )

    elif parts[0] == "mode" and len(parts) >= 2:
        mode = _MODE_MAP.get(parts[1])
        if mode is not None:
            print(
                f"Setting zone mode to {parts[1]} (zone {active_zone})"
            )
            conn.set_zone_mode(active_zone, mode)
        else:
            print(f"Unknown mode: {parts[1]}")

    elif parts[0] == "fan" and len(parts) >= 2:
        fan = _FAN_MAP.get(parts[1])
        if fan is not None:
            print(f"Setting fan mode to {parts[1]}")
            conn.set_fan_mode(fan)
        else:
            print(f"Unknown fan mode: {parts[1]}")

    elif parts[0] == "eheat" and len(parts) >= 2:
        enabled = parts[1] in ("on", "1", "true", "enable")
        print(f"Setting emergency heat {'on' if enabled else 'off'}")
        conn.set_emergency_heat(enabled)

    elif cmd.lower().startswith("raw "):
        raw_json = cmd[4:].strip()
        try:
            msg = orjson.loads(raw_json)
            print(f"Sending: {orjson.dumps(msg).decode()}")
            conn.send(msg)
        except orjson.JSONDecodeError as exc:
            print(f"Invalid JSON: {exc}")

    elif parts[0] == "ping":
        print("Sending heartbeat")
        conn.heartbeat()

    elif parts[0] in ("help", "?"):
        _print_help(active_zone)

    else:
        print("Unknown command. Type 'help' for available commands.")

    return active_zone


async def _do_pair(ip: str, port: int) -> None:
    """Run pairing mode to obtain a secret key from the thermostat."""
    print("\n=== PAIRING MODE ===")
    print("Make sure the thermostat is in pairing mode!")
    print(
        "(On the thermostat: Menu > Settings > "
        "Remote Access > Pair New Device)\n"
    )

    conn = ThermostatConnection(ip, port, secret_key="")
    try:
        await conn.connect()
        ssk = await conn.pair()
    except (SteamloopError, OSError) as exc:
        print(f"Pairing failed: {exc}")
        print("\nMake sure:")
        print("  1. The thermostat IP is correct")
        print("  2. The thermostat is in pairing mode")
        print("  3. You are on the same network as the thermostat")
        return
    finally:
        await conn.disconnect()

    secret_key = ssk["secret_key"]
    if secret_key:
        await save_pairing(
            ip,
            {
                "secret_key": secret_key,
                "device_type": "automation",
                "device_id": "module",
            },
        )
        print("Pairing complete! Reconnecting...\n")
    else:
        print("Already paired. Connecting...\n")

    await asyncio.sleep(2)
    await _do_monitor(ip, port)


async def _do_monitor(ip: str, port: int) -> None:
    """Run monitoring mode with interactive command loop."""
    pairing = await load_pairing(ip)
    if not pairing:
        print("No pairing found. Run with --pair first.")
        return

    print("\n=== MONITORING MODE ===")
    print(f"Using saved pairing for {ip}")

    conn = ThermostatConnection(
        ip,
        port,
        secret_key=pairing["secret_key"],
        device_type=pairing.get("device_type", "automation"),
        device_id=pairing.get("device_id", "module"),
    )

    def on_event(msg: dict[str, Any]) -> None:
        print(f"[<] {orjson.dumps(msg).decode()}")

    conn.add_event_callback(on_event)

    try:
        async with conn:
            active_zone = "1"
            print(
                "\nListening for thermostat events... (Ctrl+C to quit)"
            )
            _print_help(active_zone)
            print()

            loop = asyncio.get_running_loop()
            while conn.connected:
                try:
                    line = await loop.run_in_executor(
                        None, sys.stdin.readline
                    )
                    cmd = line.strip()
                except EOFError:
                    break

                if not cmd:
                    continue

                parts = cmd.lower().split()
                try:
                    result = _handle_command(conn, cmd, parts, active_zone)
                    if result is None:
                        break
                    active_zone = result
                except SteamloopConnectionError as exc:
                    print(f"Connection error: {exc}")
                    break

    except SteamloopError as exc:
        print(f"Connection failed: {exc}")
    except KeyboardInterrupt:
        pass

    print("\nDisconnected.")


def main() -> None:
    """Entry point for the steamloop CLI."""
    parser = argparse.ArgumentParser(
        description="Thermostat Local Control CLI"
    )
    parser.add_argument("ip", help="Thermostat IP address")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--pair", action="store_true", help="Enter pairing mode"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.pair:
        asyncio.run(_do_pair(args.ip, args.port))
    else:
        asyncio.run(_do_monitor(args.ip, args.port))
