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

Default credentials: `bn` / `bn`

From the config UI you can:
- Select display vendor (Algo or Freeport)
- Configure listener host, port, and webhook paths
- Toggle HTTP/HTTPS for the webhook listener and upload SSL certificates
- Set monitored protocols and allowed tags
- Configure vendor-specific settings (connection, display, strobe, tone)
- Send test alerts with customizable data
- Save configuration and restart the service

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
