# steamloop

<p align="center">
  <a href="https://github.com/hvaclibs/steamloop/actions/workflows/ci.yml?query=branch%3Amain">
    <img src="https://img.shields.io/github/actions/workflow/status/hvaclibs/steamloop/ci.yml?branch=main&label=CI&logo=github&style=flat-square" alt="CI Status" >
  </a>
  <a href="https://steamloop.readthedocs.io">
    <img src="https://img.shields.io/readthedocs/steamloop.svg?logo=read-the-docs&logoColor=fff&style=flat-square" alt="Documentation Status">
  </a>
  <a href="https://codecov.io/gh/hvaclibs/steamloop">
    <img src="https://img.shields.io/codecov/c/github/hvaclibs/steamloop.svg?logo=codecov&logoColor=fff&style=flat-square" alt="Test coverage percentage">
  </a>
</p>
<p align="center">
  <a href="https://github.com/astral-sh/uv">
    <img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json" alt="uv">
  </a>
  <a href="https://github.com/astral-sh/ruff">
    <img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff">
  </a>
  <a href="https://github.com/pre-commit/pre-commit">
    <img src="https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white&style=flat-square" alt="pre-commit">
  </a>
</p>
<p align="center">
  <a href="https://pypi.org/project/steamloop/">
    <img src="https://img.shields.io/pypi/v/steamloop.svg?logo=python&logoColor=fff&style=flat-square" alt="PyPI Version">
  </a>
  <img src="https://img.shields.io/pypi/pyversions/steamloop.svg?style=flat-square&logo=python&amp;logoColor=fff" alt="Supported Python versions">
  <img src="https://img.shields.io/pypi/l/steamloop.svg?style=flat-square" alt="License">
</p>

---

Async Python library for local control of thermostat devices over mTLS (port 7878).

## Installation

```bash
pip install steamloop
```

## CLI

### Pairing

Put the thermostat in pairing mode (Menu > Settings > Remote Access > Pair New Device), then:

```bash
steamloop 192.168.1.100 --pair
```

This saves a pairing file in the current directory with the secret key.

### Monitoring

```bash
steamloop 192.168.1.100
```

Interactive commands: `status`, `heat <temp>`, `cool <temp>`, `mode <off|auto|cool|heat>`, `fan <auto|on|circulate>`, `eheat <on|off>`, `help`.

## Library Usage

```python
import asyncio
from steamloop import ThermostatConnection, ZoneMode, FanMode

async def main():
    conn = ThermostatConnection(
        "192.168.1.100",
        secret_key="your-secret-key-from-pairing",
    )
    async with conn:
        # State is populated automatically from thermostat events
        for zone_id, zone in conn.state.zones.items():
            print(f"{zone.name}: {zone.indoor_temperature}°F")

        # Send commands (sync — no await needed)
        conn.set_temperature_setpoint("1", heat_setpoint="72")
        conn.set_zone_mode("1", ZoneMode.COOL)
        conn.set_fan_mode(FanMode.AUTO)

asyncio.run(main())
```

### Pairing Programmatically

`pair()` returns the secret key directly — store it however you like:

```python
from steamloop import ThermostatConnection

async def pair(ip: str) -> str:
    conn = ThermostatConnection(ip, secret_key="")
    try:
        await conn.connect()
        ssk = await conn.pair()
        return ssk["secret_key"]  # store in a database, config entry, etc.
    finally:
        await conn.disconnect()
```

Or use the built-in file helpers to save/load pairing data to disk:

```python
from steamloop import ThermostatConnection, save_pairing, load_pairing

# Save after pairing
await save_pairing(ip, {
    "secret_key": secret_key,
    "device_type": "automation",
    "device_id": "module",
})

# Load later
pairing = await load_pairing(ip)
conn = ThermostatConnection(ip, secret_key=pairing["secret_key"])
```

### Event Callbacks

```python
def on_event(msg):
    print("Received:", msg)

remove = conn.add_event_callback(on_event)
# later: remove() to unregister
```

## Home Assistant Integration

Key design points for using steamloop in a Home Assistant integration:

- **Commands are sync** — `set_zone_mode()`, `set_fan_mode()`, `set_temperature_setpoint()` use `transport.write()` internally, so they won't block the event loop. No `await` needed.
- **State is always fresh** — the `asyncio.Protocol` receives events via `data_received()` and updates `conn.state` automatically. Just read properties directly.
- **Auto-reconnect** — after calling `start_background_tasks()`, the connection automatically reconnects with exponential backoff (5s, 10s, 20s, ... up to 5 min).
- **Event callbacks** — use `add_event_callback()` to trigger `async_write_ha_state()` when the thermostat pushes updates.
- **Multi-zone** — create one `ClimateEntity` per `conn.state.zones` entry. Zones are populated automatically after login.

## API Reference

### `ThermostatConnection(ip, port=7878, *, secret_key, cert_set=None, device_type="automation", device_id="module")`

| Method | Async | Description |
|--------|-------|-------------|
| `connect()` | yes | Establish mTLS connection |
| `login()` | yes | Authenticate with secret key |
| `pair()` | yes | Pair and receive secret key |
| `start_background_tasks()` | no | Start heartbeat + auto-reconnect |
| `disconnect()` | yes | Close connection and stop tasks |
| `set_temperature_setpoint(zone_id, *, heat_setpoint, cool_setpoint, hold_type)` | no | Set zone temperature |
| `set_zone_mode(zone_id, mode)` | no | Set zone HVAC mode |
| `set_fan_mode(mode)` | no | Set fan mode |
| `set_emergency_heat(enabled)` | no | Toggle emergency heat |
| `add_event_callback(fn)` | no | Register event listener (returns unregister callable) |

Supports `async with` for automatic connect/login/disconnect:

```python
async with ThermostatConnection(ip, secret_key=key) as conn:
    ...  # connected, logged in, background tasks running
# automatically disconnected
```

### Enums

- `ZoneMode` — `OFF`, `AUTO`, `COOL`, `HEAT`
- `FanMode` — `AUTO`, `ALWAYS_ON`, `CIRCULATE`
- `HoldType` — `UNDEFINED`, `MANUAL`, `SCHEDULE`, `HOLD`

### State

- `conn.state.zones` — `dict[str, Zone]` with temperature, setpoints, mode per zone
- `conn.state.fan_mode` — current `FanMode`
- `conn.state.supported_modes` — `list[ZoneMode]`
- `conn.state.emergency_heat` / `relative_humidity` / `cooling_active` / `heating_active`

## Contributors

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- prettier-ignore-start -->
<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- markdownlint-disable -->
<!-- markdownlint-enable -->
<!-- ALL-CONTRIBUTORS-LIST:END -->
<!-- prettier-ignore-end -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

## Credits

[![Copier](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/copier-org/copier/master/img/badge/badge-grayscale-inverted-border-orange.json)](https://github.com/copier-org/copier)

This package was created with
[Copier](https://copier.readthedocs.io/) and the
[browniebroke/pypackage-template](https://github.com/browniebroke/pypackage-template)
project template.
