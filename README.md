# Bastille Display Integration

Receives webhook alerts from the Bastille platform (Zone Detections and ADAM Findings) and triggers visual/audio alerts on Algo or Freeport display devices.

## Requirements

- Ubuntu 24.04
- Python 3.12+

## Installation

1. Clone the repository:

```bash
cd /home/bn
git clone https://github.com/Bastille-Integration/bastille_display_integration.git
cd bastille_display_integration
```

2. Run the install script:

```bash
sudo bash install.sh
```

This will:
- Install system and Python dependencies
- Configure sudoers for service restart from the config UI
- Generate a self-signed SSL certificate for the config UI
- Install and enable systemd services
- Start both the integration service and config UI

## Configuration

Open the config UI in a browser:

```
https://<host-ip>:8443
```

Default credentials: `bn` / `bn` (configurable via `ui_username` / `ui_password` in `config.yaml`)

### Config UI Tabs

The config UI is organized into four tabs:

#### Status

- **Integration Service** -- shows running/stopped state, PID, and uptime
- **Config UI Service** -- shows running/stopped state, PID, and uptime
- **Display Target** -- verifies connectivity to the Algo (HTTP) or Freeport (TLS) device and reports reachable/unreachable with connection details
- **Running Configuration** -- summarized in three categories:
  - Webhook Listener (host, port, SSL, endpoint paths)
  - Display Target (vendor, host, port, clear time, strobe/tone for Algo)
  - Filtering (monitored protocols, allowed tags)

#### Configuration

- Select display vendor (Algo or Freeport) -- only relevant settings are shown
- Global settings: listener host, port, webhook paths, log file, clear time
- Webhook listener protocol: toggle HTTP/HTTPS with SSL certificate and key upload
- Monitored protocols: toggle cellular, Wi-Fi, BLE, or add custom protocols
- Allowed tags: add/remove tags for devices that should not trigger alerts
- Algo-specific: target host/port, credentials, text color, strobe pattern/color, tone selection
- Freeport-specific: target host/port, credentials
- Save, Discard Changes, or Save & Restart Service buttons

#### Testing

- Send test alerts directly to the running integration service
- **Zone Detection** test: configure protocol, zone, vendor, manufacturer, transmitter ID, and tags
- **ADAM Finding** test: configure protocol, severity, reason, zone, vendor, transmitter ID, network name, tags, severity score, and webhook name
- Protocol dropdowns are populated from the configured monitored protocols list
- Results displayed inline with success/failure status

#### Alerts

- View a history of all received alerts (up to 500, most recent first)
- Each alert shows: timestamp, type (Zone Detection / ADAM Finding), protocol, zone, vendor, severity, and status (Sent / Filtered)
- Color-coded severity badges (critical, high, medium, low)
- Status indicates whether the alert was sent to the display or filtered (by protocol or tag)
- Refresh to load latest alerts or Clear All to reset the log

Configuration is stored in `config.yaml` and can also be edited directly.

## Webhook Endpoints

| Endpoint | Description |
|---|---|
| `POST /zone-detections` | Receives Bastille zone detection webhooks (ndjson) |
| `POST /adam-findings` | Receives Bastille ADAM finding webhooks (json) |

Paths and port are configurable via `config.yaml` or the config UI.

## Services

| Service | Port | Description |
|---|---|---|
| `bastille_display_integration` | 8001 | Webhook listener and alert dispatcher |
| `bastille_config_ui` | 8443 | HTTPS configuration UI |

Manage with systemd:

```bash
sudo systemctl restart bastille_display_integration.service
sudo systemctl status bastille_display_integration.service
sudo systemctl status bastille_config_ui.service
```

The config UI service is tied to the main service via `PartOf` -- restarting the main service also restarts the config UI.
