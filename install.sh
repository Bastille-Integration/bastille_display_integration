#!/usr/bin/env bash
set -e

INSTALL_DIR="/home/bn/bastille_display_integration"
SERVICE_USER="bn"

# Must run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo bash install.sh"
  exit 1
fi

echo "=== Bastille Display Integration - Installer ==="

# --- Dependencies ---
echo ""
echo "[1/7] Installing system dependencies..."
if fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
  echo "Another apt process is running:"
  ps -eo pid,comm | grep -E "apt|dpkg" | grep -v grep
  read -p "Kill the existing apt process and continue? (y/n): " KILL_APT
  if [ "$KILL_APT" = "y" ] || [ "$KILL_APT" = "Y" ]; then
    killall apt-get apt dpkg 2>/dev/null || true
    sleep 2
    echo "Apt process killed."
  else
    echo "Waiting for apt lock to be released..."
    while fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
      sleep 2
    done
  fi
fi
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-fastapi python3-httpx openssl net-tools

echo "[1/7] Installing Python packages..."
python3 -m pip install ndjson PyYAML --break-system-packages --quiet

# --- Sudoers ---
echo ""
echo "[2/7] Configuring sudoers for service restart..."
# Write sudoers rule directly to avoid file copy issues
echo "$SERVICE_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart bastille_display_integration.service" > /etc/sudoers.d/bastille
chown root:root /etc/sudoers.d/bastille
chmod 440 /etc/sudoers.d/bastille
# Validate sudoers syntax
if ! visudo -c -f /etc/sudoers.d/bastille >/dev/null 2>&1; then
  echo "ERROR: Invalid sudoers file. Removing."
  rm -f /etc/sudoers.d/bastille
  exit 1
fi
echo "Sudoers configured for user '$SERVICE_USER'."
echo "Verifying: $(cat /etc/sudoers.d/bastille)"

# --- SSL Certificates ---
echo ""
echo "[3/7] Generating self-signed SSL certificate for config UI..."
CERT_DIR="$INSTALL_DIR/certs"
mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
    -days 365 -nodes \
    -subj "/CN=bastille-config-ui" 2>/dev/null
  chown -R "$SERVICE_USER":"$SERVICE_USER" "$CERT_DIR"
  echo "SSL certificate generated."
else
  echo "SSL certificates already exist, skipping."
fi

# --- Service Files ---
echo ""
echo "[4/7] Installing systemd service files..."
cp "$INSTALL_DIR/bastille_display_integration.service" /etc/systemd/system/
cp "$INSTALL_DIR/bastille_config_ui.service" /etc/systemd/system/
systemctl daemon-reload
echo "Service files installed."

# --- Enable Services ---
echo ""
echo "[5/7] Enabling services..."
systemctl enable bastille_display_integration.service
systemctl enable bastille_config_ui.service
echo "Services enabled."

# --- Initialize Config and Log ---
echo ""
echo "[6/7] Initializing config and log files..."
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
  if [ -f "$INSTALL_DIR/config.yaml.bak" ]; then
    cp "$INSTALL_DIR/config.yaml.bak" "$INSTALL_DIR/config.yaml"
    echo "config.yaml created from backup."
  else
    cat > "$INSTALL_DIR/config.yaml" << 'EOF'
log_file: app.log
source_host: 0.0.0.0
source_path: /zone-detections
adam_path: /adam-findings
source_port: 8001
source_ssl: false
source_ssl_cert: certs/integration_cert.pem
source_ssl_key: certs/integration_key.pem
clear_time: 60
monitored_protocols:
  - cellular
  - wifi
  - ble
  - bt
  - ieee_802_15_4
zone_detection_template: "ALERT - {protocol} in {zone} - Vendor: {vendor} - ALERT"
adam_finding_template: "ADAM ALERT - {severity} - {reasons} - {protocol} in {zone} - Vendor: {vendor}"
allowed_tags:
  - authorized
  - exclude
vendor: Algo
target_host: http://CHANGE_ME
target_port: 80
auth_username: CHANGE_ME
auth_password: CHANGE_ME
text_color: red
EOF
    echo "config.yaml created from template (edit before use)."
  fi
  chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/config.yaml"
else
  echo "config.yaml already exists, skipping."
fi
if [ ! -f "$INSTALL_DIR/app.log" ]; then
  touch "$INSTALL_DIR/app.log"
  chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/app.log"
  echo "app.log created."
else
  echo "app.log already exists, skipping."
fi

# --- Start Services ---
echo ""
echo "[7/7] Starting services..."
systemctl restart bastille_display_integration.service
systemctl restart bastille_config_ui.service
echo "Services started."

# --- Summary ---
echo ""
echo "=== Installation Complete ==="
echo ""
echo "  Integration service: $(systemctl is-active bastille_display_integration.service)"
echo "  Config UI service:   $(systemctl is-active bastille_config_ui.service)"
echo ""
echo "  Config UI: https://$(hostname -I | awk '{print $1}')"
echo "  Webhooks:  http://$(hostname -I | awk '{print $1}'):8001"
echo ""
echo "  Edit config.yaml or use the Config UI to configure your display vendor."
