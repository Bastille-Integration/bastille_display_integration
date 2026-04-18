#!/usr/bin/env bash
set -e

INSTALL_DIR="/home/bn/bastille_display_integration"
SERVICE_USER="bn"
HOME_DIR="/home/$SERVICE_USER"

# Must run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo bash cleanup_for_export.sh"
  exit 1
fi

echo "=== Bastille Display Integration - Export Cleanup ==="
echo ""
echo "This script prepares the VM for customer handoff by removing"
echo "git credentials, shell history, logs, and sensitive data."
echo ""
read -p "Continue? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
  echo "Aborted."
  exit 0
fi

# --- Stop Services ---
echo ""
echo "[1/8] Stopping services..."
systemctl stop bastille_display_integration.service 2>/dev/null || true
systemctl stop bastille_config_ui.service 2>/dev/null || true

# --- Git Credentials ---
echo ""
echo "[2/8] Removing git credentials and config..."
rm -f "$HOME_DIR/.git-credentials"
rm -f "$HOME_DIR/.gitconfig"
rm -f /root/.git-credentials
rm -f /root/.gitconfig
su - "$SERVICE_USER" -c "git credential-cache exit 2>/dev/null" || true

# Remove git repo data from install directory
if [ -d "$INSTALL_DIR/.git" ]; then
  rm -rf "$INSTALL_DIR/.git"
  echo "Removed .git directory."
fi

# --- SSH Keys ---
echo ""
echo "[3/8] Removing SSH keys..."
rm -rf "$HOME_DIR/.ssh"
rm -rf /root/.ssh
echo "SSH keys removed."

# --- Shell History ---
echo ""
echo "[4/8] Clearing shell history..."
rm -f "$HOME_DIR/.bash_history"
rm -f "$HOME_DIR/.zsh_history"
rm -f /root/.bash_history
rm -f /root/.zsh_history
echo "Shell history cleared."

# --- Claude Code Config ---
echo ""
echo "[5/8] Removing Claude Code config..."
rm -rf "$HOME_DIR/.claude"
rm -rf /root/.claude
echo "Claude Code config removed."

# --- Application Logs & Data ---
echo ""
echo "[6/8] Cleaning application data..."
rm -f "$INSTALL_DIR/app.log"
rm -f "$INSTALL_DIR/alerts.json"
echo "Logs and alert history removed."

# --- SSL Certificates ---
echo ""
echo "[7/8] Regenerating SSL certificates..."
rm -rf "$INSTALL_DIR/certs"
mkdir -p "$INSTALL_DIR/certs"
openssl req -x509 -newkey rsa:2048 \
  -keyout "$INSTALL_DIR/certs/key.pem" -out "$INSTALL_DIR/certs/cert.pem" \
  -days 365 -nodes \
  -subj "/CN=bastille-config-ui" 2>/dev/null
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/certs"
echo "Fresh SSL certificates generated."

# --- Reset Config ---
echo ""
echo "[8/8] Resetting config.yaml to defaults..."
cat > "$INSTALL_DIR/config.yaml" << 'CONFIGEOF'
## GLOBAL
#
# Config UI credentials
ui_username: bn
ui_password: bn
#Logging
log_file: app.log
#Integration IP - 0.0.0.0 if global.
source_host: 0.0.0.0
#Integration path where Bastille webhooks will be sent.
source_path: /zone-detections
#Integration path where Bastille ADAM findings will be sent.
adam_path: /adam-findings
#Integration port where Bastille webhooks will be sent.
source_port: 8001
# Enable HTTPS for the webhook listener (true/false)
source_ssl: false
# Paths to SSL cert and key for webhook listener (only used if source_ssl is true)
source_ssl_cert: certs/integration_cert.pem
source_ssl_key: certs/integration_key.pem
# Algo screen will clear if no alerts are triggered for this amount of time.
clear_time: 60
# Display message templates. Available variables:
#   Zone Detection: {protocol}, {zone}, {vendor}, {tags}
#   ADAM Finding: {protocol}, {zone}, {vendor}, {severity}, {reasons}, {tags}
zone_detection_template: "ALERT - {protocol} in {zone} - Vendor: {vendor} - ALERT"
adam_finding_template: "ADAM ALERT - {severity} - {reasons} - {protocol} in {zone} - Vendor: {vendor}"
# ONLY monitored protocols will alert.
monitored_protocols:
  - cellular
  - wifi
  - ble
  - bt
  - ieee_802_15_4
# If device tagged with below tags, will NOT alert.
allowed_tags:
  - authorized
  - exclude
#
## FREEPORT
#
#vendor: Freeport
#target_host: 10.35.44.51
#target_port: 2311
#auth_username: bn
#auth_password: bn
# Font size for alert detail text on Freeport display (default: 160)
#freeport_detail_font_size: 160
#
# ALGO
#
vendor: Algo
target_host: http://CHANGE_ME
target_port: 80
auth_username: admin
auth_password: algo
text_color: red
# Algo text display settings
algo_text_color: orange
algo_text_font: roboto
algo_text_size: medium
algo_text_position: middle
algo_text_scroll: "1"
algo_text_scroll_speed: "4"
strobe_pattern: 2
strobe_color: red
# Set tone on/off and recording from above default list (or record your own)
tone: true
tone_wav: bell-na.wav
CONFIGEOF
chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/config.yaml"
echo "Config reset to defaults."

# --- Restart Services ---
echo ""
echo "Starting services..."
systemctl start bastille_display_integration.service 2>/dev/null || true
systemctl start bastille_config_ui.service 2>/dev/null || true

# --- Summary ---
echo ""
echo "=== Cleanup Complete ==="
echo ""
echo "The following has been removed:"
echo "  - Git credentials, .git directory, and .gitconfig"
echo "  - SSH keys"
echo "  - Shell history (bn and root)"
echo "  - Claude Code configuration"
echo "  - Application logs and alert history"
echo "  - Old SSL certificates (regenerated)"
echo "  - config.yaml reset to defaults (credentials set to CHANGE_ME)"
echo ""
echo "The customer will need to:"
echo "  1. Configure the display vendor and connection in the Config UI"
echo "  2. Set up Bastille webhooks pointing to this integration"
echo "  3. Change the Config UI password (default: bn/bn)"
echo ""
echo "VM is ready for export."
