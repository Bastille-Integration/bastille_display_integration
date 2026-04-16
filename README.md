# Bastille Display Integration

Receives webhook alerts from the Bastille platform (Zone Detections and ADAM Findings) and triggers visual/audio alerts on Algo or Freeport display devices.

## Architecture

```
┌──────────────────────┐
│   Bastille Platform   │
│                       │
│  ┌─────────────────┐  │
│  │ Zone Detections  │  │
│  │    (ndjson)      │──┼──── POST /zone-detections ────┐
│  └─────────────────┘  │                                │
│  ┌─────────────────┐  │                                ▼
│  │  ADAM Findings   │  │                   ┌────────────────────────┐
│  │     (json)       │──┼── POST /adam-findings ──▶│  Integration Service   │
│  └─────────────────┘  │                   │     (port 8001)        │
└──────────────────────┘                   │                        │
                                           │  ┌──────────────────┐  │
                                           │  │ Parse Webhook    │  │
                                           │  │ Filter Protocol  │  │
                                           │  │ Filter Tags      │  │
                                           │  │ Apply Template   │  │
                                           │  └───────┬──────────┘  │
                                           │          │             │
                                           └──────────┼─────────────┘
                                                      │
                                    ┌─────────────────┼─────────────────┐
                                    │                 │                 │
                                    ▼                 ▼                 ▼
                           ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
                           │  Algo        │  │  Algo        │  │  Algo        │
                           │  Screen API  │  │  Strobe API  │  │  Tone API    │
                           │  (HTTP POST) │  │  (HTTP POST) │  │  (HTTP POST) │
                           └──────────────┘  └──────────────┘  └──────────────┘

                                           ── OR ──

                                    ┌──────────────────────────────────┐
                                    │  Freeport Display                │
                                    │  (TLS socket commands)           │
                                    │  - Set alert text + color        │
                                    │  - Hide clocks/background        │
                                    └──────────────────────────────────┘


┌──────────────────────┐
│   Config UI          │   https://<host>:8443
│   (port 8443)        │
│                      │
│  Status ─ service health, display connectivity, running config
│  Configuration ─ vendor, listener, protocols, tags, templates
│  Testing ─ send test alerts, preview commands, clear display
│  Alerts ─ alert history log
└──────────────────────┘
```

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

### Applying Changes

Most configuration changes require the integration service to be restarted before they take effect. This includes changes to:

- **Listener settings** -- host, port, webhook paths
- **Vendor selection** -- switching between Algo and Freeport
- **Connection settings** -- target host, port, credentials
- **SSL settings** -- enabling/disabling HTTPS, certificate changes
- **Monitored protocols and allowed tags**

Use the **Save & Restart Service** button in the Configuration tab to save and restart in one step. The config UI will briefly disconnect during the restart.

**Exception:** Display message templates and Algo text display settings (font, size, scroll, position) are read live from the config file on each alert and take effect immediately after saving -- no restart required.

### Global Settings

| Setting | Description | Default |
|---|---|---|
| Log File | Path to the application log file | `app.log` |
| Listener Host | IP address to bind the webhook listener. Use `0.0.0.0` to listen on all interfaces | `0.0.0.0` |
| Listener Port | Port for the webhook listener | `8001` |
| Zone Detections Path | URL path for zone detection webhooks | `/zone-detections` |
| ADAM Findings Path | URL path for ADAM finding webhooks | `/adam-findings` |
| Clear Time | Seconds to wait before clearing the display after the last alert. If a new alert arrives during this window, the timer resets | `60` |
| Monitored Protocols | Only alerts matching these protocols will trigger the display (e.g., cellular, wifi, ble). Custom protocols can be added | `cellular, wifi, ble` |
| Allowed Tags | Devices tagged with any of these tags will not trigger alerts (e.g., authorized, exclude) | `authorized, exclude` |

### Config UI Tabs

The config UI is organized into five tabs:

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

## Configuring Display Devices

Before the integration can send alerts, the display device must be configured to accept API commands.

### Algo Setup

1. Open the Algo web interface in a browser: `http://<algo-ip>`
2. Log in with the Algo admin credentials
3. Navigate to **API** or **Advanced Settings**
4. **Enable the API** -- ensure the REST API is turned on
5. Note the username and password for API access (default is typically `admin` / `algo`)
6. In the config UI, enter the Algo target host (e.g., `http://<algo-ip>`), port, and credentials under the **Algo Connection** section

### Freeport Setup

1. Log in to the Freeport management interface
2. Navigate to **User Management** or **Administration**
3. **Create a new user** with API privileges:
   - Set a username and password (e.g., `bn` / `bn`)
   - Ensure the user has **API access** permissions enabled
4. Navigate to **API Settings** or **System Configuration**
5. **Enable the API** -- ensure the TLS API interface is turned on and note the port (default is typically `80`)
6. In the config UI, enter the Freeport target host (IP address, not URL), port, and the API user credentials under the **Freeport Connection** section

### Verifying Display Connectivity

After configuring the display device and entering its details in the config UI:

1. Go to the **Status** tab -- the **Display Target** box should show "Reachable"
2. Go to the **Testing** tab and use **Preview Display Commands** to verify the payloads look correct
3. Send a test alert to confirm the display responds
4. Use **Clear Display** to reset the display after testing

## Configuring Bastille Webhooks

After installation, configure the Bastille platform to send webhooks to this integration.

### Zone Detection Webhook

1. Log in to the Bastille command console
2. Navigate to **Settings > Webhooks**
3. Click **Add Webhook**
4. Configure the webhook:
   - **Name**: Display Integration - Zone Detections
   - **URL**: `http://<integration-host-ip>:8001/zone-detections` (or `https://` if SSL is enabled)
   - **Event Type**: Zone Detections
5. Configure any filters as needed (zones, protocols, etc.)
6. Save the webhook

### ADAM Finding Webhook

1. Log in to the Bastille command console
2. Navigate to **Settings > Webhooks**
3. Click **Add Webhook**
4. Configure the webhook:
   - **Name**: Display Integration - ADAM Findings
   - **URL**: `http://<integration-host-ip>:8001/adam-findings` (or `https://` if SSL is enabled)
   - **Event Type**: Findings
5. Configure any filters or policy rules as needed
6. Save the webhook

### Notes

- Replace `<integration-host-ip>` with the IP address or hostname of the machine running this integration
- The port and paths shown above are defaults -- if you changed them in the config UI, use the values shown on the **Status** tab under **Webhook Listener**
- If the integration is configured with HTTPS, ensure the Bastille platform can reach it over TLS (self-signed certificates may need to be trusted or verification disabled on the Bastille side)
- Use the **Testing** tab in the config UI to verify the integration is receiving and processing alerts correctly before relying on it in production

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
