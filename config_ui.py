from fastapi import FastAPI, Request, Depends, HTTPException, status, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
import yaml
import os
import subprocess
import logging
import json
import requests
import uvicorn

INTEGRATION_CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
ALERTS_FILE = os.path.join(os.path.dirname(__file__), "alerts.json")

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")
CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
CERT_FILE = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE = os.path.join(CERT_DIR, "key.pem")
VERSION = "2.0.1"
UI_PORT = 443

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ConfigUI")

TONE_OPTIONS = [
    "bell-na.wav",
    "bell-uk.wav",
    "buzzer.wav",
    "chime.wav",
    "dogs.wav",
    "gong.wav",
    "page-notif.wav",
    "speech-test.wav",
    "tone-1kHz-max.wav",
    "warble1-low.wav",
    "warble2-med.wav",
    "warble3-high.wav",
    "warble4-trill.wav",
]

app = FastAPI()
security = HTTPBasic()

def _get_host_ip():
    """Get the primary IP address of this machine."""
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_ui_users():
    """Read UI users from config. Supports both legacy single-user and multi-user format."""
    cfg = load_config()
    users = cfg.get("ui_users")
    if isinstance(users, list) and users:
        return {u["username"]: u["password"] for u in users if "username" in u and "password" in u}
    # Fallback to legacy single-user config
    return {cfg.get("ui_username", "bn"): cfg.get("ui_password", "bn")}


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    users = get_ui_users()
    for username, password in users.items():
        if secrets.compare_digest(credentials.username, username) and secrets.compare_digest(credentials.password, str(password)):
            return credentials
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Basic"},
    )


def generate_self_signed_cert():
    """Generate a self-signed certificate if one does not exist."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        logger.info("SSL certificates already exist.")
        return
    os.makedirs(CERT_DIR, exist_ok=True)
    logger.info("Generating self-signed SSL certificate...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", KEY_FILE, "-out", CERT_FILE,
        "-days", "365", "-nodes",
        "-subj", "/CN=bastille-config-ui"
    ], check=True)
    logger.info("SSL certificate generated.")


def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


@app.get("/api/users", response_class=JSONResponse)
async def get_users(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    users = get_ui_users()
    return [{"username": u} for u in users]


@app.post("/api/users", response_class=JSONResponse)
async def add_user(request: Request, credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    if not username or not password:
        return JSONResponse(status_code=400, content={"status": "error", "detail": "Username and password required"})
    cfg = load_config()
    users = cfg.get("ui_users", [])
    if not isinstance(users, list):
        users = []
    # Migrate legacy single-user to list
    if not users:
        legacy_user = cfg.get("ui_username", "bn")
        legacy_pass = cfg.get("ui_password", "bn")
        users = [{"username": legacy_user, "password": legacy_pass}]
    if any(u["username"] == username for u in users):
        return JSONResponse(status_code=400, content={"status": "error", "detail": "User already exists"})
    users.append({"username": username, "password": password})
    cfg["ui_users"] = users
    save_config(cfg)
    logger.info(f"User '{username}' added.")
    return {"status": "ok"}


@app.put("/api/users/password", response_class=JSONResponse)
async def change_password(request: Request, credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    body = await request.json()
    username = body.get("username", "").strip()
    new_password = body.get("new_password", "").strip()
    if not username or not new_password:
        return JSONResponse(status_code=400, content={"status": "error", "detail": "Username and new password required"})
    cfg = load_config()
    users = cfg.get("ui_users", [])
    if not isinstance(users, list):
        users = []
    # Migrate legacy single-user to list
    if not users:
        legacy_user = cfg.get("ui_username", "bn")
        legacy_pass = cfg.get("ui_password", "bn")
        users = [{"username": legacy_user, "password": legacy_pass}]
    found = False
    for u in users:
        if u["username"] == username:
            u["password"] = new_password
            found = True
            break
    if not found:
        return JSONResponse(status_code=404, content={"status": "error", "detail": "User not found"})
    cfg["ui_users"] = users
    save_config(cfg)
    logger.info(f"Password changed for user '{username}'.")
    return {"status": "ok"}


@app.delete("/api/users", response_class=JSONResponse)
async def delete_user(request: Request, credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    body = await request.json()
    username = body.get("username", "").strip()
    if not username:
        return JSONResponse(status_code=400, content={"status": "error", "detail": "Username required"})
    cfg = load_config()
    users = cfg.get("ui_users", [])
    if not isinstance(users, list):
        users = []
    if not users:
        legacy_user = cfg.get("ui_username", "bn")
        legacy_pass = cfg.get("ui_password", "bn")
        users = [{"username": legacy_user, "password": legacy_pass}]
    if len(users) <= 1:
        return JSONResponse(status_code=400, content={"status": "error", "detail": "Cannot delete the last user"})
    new_users = [u for u in users if u["username"] != username]
    if len(new_users) == len(users):
        return JSONResponse(status_code=404, content={"status": "error", "detail": "User not found"})
    cfg["ui_users"] = new_users
    save_config(cfg)
    logger.info(f"User '{username}' deleted.")
    return {"status": "ok"}


@app.get("/api/config", response_class=JSONResponse)
async def get_config(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    return load_config()


@app.get("/api/config/export")
async def export_config(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    from fastapi.responses import Response
    import io
    import zipfile
    cfg = load_config()
    if cfg.get("source_ssl"):
        # Export as zip with config + certs
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(CONFIG_PATH, "config.yaml")
            cert_path = os.path.join(INTEGRATION_CERT_DIR, "integration_cert.pem")
            key_path = os.path.join(INTEGRATION_CERT_DIR, "integration_key.pem")
            if os.path.exists(cert_path):
                zf.write(cert_path, "certs/integration_cert.pem")
            if os.path.exists(key_path):
                zf.write(key_path, "certs/integration_key.pem")
        buf.seek(0)
        return Response(
            content=buf.read(),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=bastille_config_export.zip"}
        )
    else:
        with open(CONFIG_PATH, "r") as f:
            content = f.read()
        return Response(
            content=content,
            media_type="application/x-yaml",
            headers={"Content-Disposition": "attachment; filename=config.yaml"}
        )


@app.post("/api/config/restore", response_class=JSONResponse)
async def restore_config(file: UploadFile = File(...), credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    import io
    import zipfile
    content = await file.read()
    filename = file.filename or ""

    # Backup current config
    backup_path = CONFIG_PATH + ".bak"
    with open(CONFIG_PATH, "r") as f:
        with open(backup_path, "w") as bak:
            bak.write(f.read())

    if filename.endswith(".zip") or content[:4] == b"PK\x03\x04":
        # Zip file - extract config and certs
        try:
            zf = zipfile.ZipFile(io.BytesIO(content))
        except zipfile.BadZipFile:
            return JSONResponse(status_code=400, content={"status": "error", "detail": "Invalid zip file"})
        if "config.yaml" not in zf.namelist():
            return JSONResponse(status_code=400, content={"status": "error", "detail": "Zip must contain config.yaml"})
        cfg_data = zf.read("config.yaml")
        try:
            parsed = yaml.safe_load(cfg_data)
            if not isinstance(parsed, dict):
                return JSONResponse(status_code=400, content={"status": "error", "detail": "Invalid config file format"})
        except yaml.YAMLError as e:
            return JSONResponse(status_code=400, content={"status": "error", "detail": f"YAML parse error: {e}"})
        with open(CONFIG_PATH, "wb") as f:
            f.write(cfg_data)
        # Extract certs if present
        os.makedirs(INTEGRATION_CERT_DIR, exist_ok=True)
        for cert_name in ["certs/integration_cert.pem", "certs/integration_key.pem"]:
            if cert_name in zf.namelist():
                dest = os.path.join(os.path.dirname(__file__), cert_name)
                with open(dest, "wb") as f:
                    f.write(zf.read(cert_name))
                if "key" in cert_name:
                    os.chmod(dest, 0o600)
        logger.info("Configuration and certificates restored from zip. Backup saved to config.yaml.bak")
        return {"status": "ok", "detail": "Config and SSL certificates restored"}
    else:
        # Plain yaml file
        try:
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict):
                return JSONResponse(status_code=400, content={"status": "error", "detail": "Invalid config file format"})
        except yaml.YAMLError as e:
            return JSONResponse(status_code=400, content={"status": "error", "detail": f"YAML parse error: {e}"})
        with open(CONFIG_PATH, "wb") as f:
            f.write(content)
        logger.info("Configuration restored from uploaded file. Backup saved to config.yaml.bak")
        return {"status": "ok"}


@app.put("/api/config", response_class=JSONResponse)
async def put_config(request: Request, credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    body = await request.json()
    save_config(body)
    logger.info("Configuration saved.")
    return {"status": "ok"}


@app.get("/api/status", response_class=JSONResponse)
async def get_status(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    def get_service_info(service_name):
        info = {}
        for prop in ["ActiveState", "SubState", "MainPID", "ActiveEnterTimestamp"]:
            try:
                result = subprocess.run(
                    ["systemctl", "show", service_name, f"--property={prop}"],
                    capture_output=True, text=True, timeout=5
                )
                val = result.stdout.strip().split("=", 1)[-1]
                info[prop] = val
            except Exception:
                info[prop] = "unknown"
        return info

    integration = get_service_info("bastille_display_integration.service")
    config_ui = get_service_info("bastille_config_ui.service")
    cfg = load_config()

    # Display target health check
    target_health = {"reachable": False, "detail": "Not checked"}
    vendor_name = cfg.get("vendor", "")
    target_host = cfg.get("target_host", "")
    target_port = cfg.get("target_port", 80)

    if vendor_name == "Algo" and target_host:
        try:
            resp = requests.get(
                target_host,
                auth=(cfg.get("auth_username", ""), cfg.get("auth_password", "")),
                timeout=5,
                verify=False
            )
            target_health = {"reachable": True, "detail": f"HTTP {resp.status_code}"}
        except requests.exceptions.ConnectionError:
            target_health = {"reachable": False, "detail": "Connection refused"}
        except requests.exceptions.Timeout:
            target_health = {"reachable": False, "detail": "Connection timed out"}
        except Exception as e:
            target_health = {"reachable": False, "detail": str(e)}

    elif vendor_name == "Freeport" and target_host:
        import socket
        import ssl as ssl_mod
        try:
            raw = socket.create_connection((target_host, int(target_port)), timeout=5)
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            tls = ctx.wrap_socket(raw, server_hostname=target_host)
            tls.close()
            target_health = {"reachable": True, "detail": f"TLS connection OK on port {target_port}"}
        except socket.timeout:
            target_health = {"reachable": False, "detail": "Connection timed out"}
        except ConnectionRefusedError:
            target_health = {"reachable": False, "detail": "Connection refused"}
        except Exception as e:
            target_health = {"reachable": False, "detail": str(e)}

    return {
        "version": VERSION,
        "services": {
            "integration": integration,
            "config_ui": config_ui,
        },
        "target_health": target_health,
        "config_summary": {
            "vendor": cfg.get("vendor", "N/A"),
            "source_host": cfg.get("source_host", "N/A"),
            "source_port": cfg.get("source_port", "N/A"),
            "source_path": cfg.get("source_path", "N/A"),
            "adam_path": cfg.get("adam_path", "N/A"),
            "source_ssl": cfg.get("source_ssl", False),
            "listener_protocol": "HTTPS" if cfg.get("source_ssl") else "HTTP",
            "host_ip": _get_host_ip(),
            "target_host": cfg.get("target_host", "N/A"),
            "target_port": cfg.get("target_port", "N/A"),
            "monitored_protocols": cfg.get("monitored_protocols", []),
            "allowed_tags": cfg.get("allowed_tags", []),
            "clear_time": cfg.get("clear_time", "N/A"),
            "strobe_pattern": cfg.get("strobe_pattern", "N/A"),
            "strobe_color": cfg.get("strobe_color", "N/A"),
            "tone": cfg.get("tone", False),
            "tone_wav": cfg.get("tone_wav", "N/A"),
        }
    }


@app.post("/api/restart", response_class=JSONResponse)
async def restart_service(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    import threading
    def _delayed_restart():
        import time
        time.sleep(1)
        subprocess.run(
            ["sudo", "systemctl", "restart", "bastille_display_integration.service"],
            capture_output=True, text=True, timeout=15
        )
    threading.Thread(target=_delayed_restart, daemon=True).start()
    logger.info("Integration service restart scheduled.")
    return {"status": "ok"}


@app.post("/api/upload-cert", response_class=JSONResponse)
async def upload_cert(
    cert: UploadFile = File(...),
    key: UploadFile = File(...),
    credentials: HTTPBasicCredentials = Depends(verify_credentials),
):
    os.makedirs(INTEGRATION_CERT_DIR, exist_ok=True)
    cert_path = os.path.join(INTEGRATION_CERT_DIR, "integration_cert.pem")
    key_path = os.path.join(INTEGRATION_CERT_DIR, "integration_key.pem")
    cert_data = await cert.read()
    key_data = await key.read()
    with open(cert_path, "wb") as f:
        f.write(cert_data)
    with open(key_path, "wb") as f:
        f.write(key_data)
    os.chmod(key_path, 0o600)
    logger.info("Integration SSL cert and key uploaded.")
    return {"status": "ok", "cert_path": cert_path, "key_path": key_path}


@app.get("/api/cert-status", response_class=JSONResponse)
async def cert_status(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    cert_path = os.path.join(INTEGRATION_CERT_DIR, "integration_cert.pem")
    key_path = os.path.join(INTEGRATION_CERT_DIR, "integration_key.pem")
    return {
        "cert_exists": os.path.exists(cert_path),
        "key_exists": os.path.exists(key_path),
    }


@app.post("/api/preview-commands", response_class=JSONResponse)
async def preview_commands(request: Request, credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    body = await request.json()
    test_type = body.get("test_type")
    payload = body.get("payload", {})
    cfg = load_config()
    vendor_name = cfg.get("vendor", "Algo")

    # Extract fields based on test type
    if test_type == "zone_detection":
        p = payload.get("payload", {})
        emitter = p.get("emitter", {})
        protocol = emitter.get("protocol", "")
        zone = p.get("zone_name", "")
        vendor_val = emitter.get("vendor", "")
        tags = p.get("tags", [])
        template = cfg.get("zone_detection_template", "ALERT - {protocol} in {zone} - Vendor: {vendor} - ALERT")
        alert_text = template.format(
            protocol=protocol, zone=zone, vendor=vendor_val,
            tags=", ".join(tags) if isinstance(tags, list) else tags
        )
        text_color = cfg.get("algo_text_color", "orange")
    else:
        p = payload.get("payload", {})
        snap = p.get("reference_snapshot", {})
        emitter = snap.get("emitter", {})
        protocol = emitter.get("protocol", "")
        vendor_val = emitter.get("vendor", "")
        tags = snap.get("tags", [])
        severity = p.get("severity", "unknown")
        reasons = p.get("reasons", [])
        reason_text = ", ".join(reasons) if reasons else "unknown"
        zone = ""
        for tag in tags:
            if tag.lower().startswith("zone:"):
                zone = tag[5:]
                break
        template = cfg.get("adam_finding_template", "ADAM ALERT - {severity} - {reasons} - {protocol} in {zone} - Vendor: {vendor}")
        alert_text = template.format(
            protocol=protocol, zone=zone, vendor=vendor_val,
            severity=severity.upper() if severity else "UNKNOWN",
            reasons=reason_text,
            tags=", ".join(tags) if isinstance(tags, list) else tags
        )
        text_color = "red" if severity in ("high", "critical") else cfg.get("algo_text_color", "orange")

    commands = []

    if vendor_name == "Algo":
        commands.append({
            "action": "Alert Screen",
            "endpoint": "POST /api/controls/screen/start",
            "payload": {
                "type": "image",
                "text1": alert_text,
                "textColor": text_color,
                "textFont": cfg.get("algo_text_font", "roboto"),
                "textPosition": cfg.get("algo_text_position", "middle"),
                "textScroll": str(cfg.get("algo_text_scroll", "1")),
                "textScrollSpeed": str(cfg.get("algo_text_scroll_speed", "4")),
                "textSize": cfg.get("algo_text_size", "medium")
            }
        })
        commands.append({
            "action": "Strobe On",
            "endpoint": "POST /api/controls/strobe/start",
            "payload": {
                "pattern": cfg.get("strobe_pattern", 2),
                "color1": cfg.get("strobe_color", "red")
            }
        })
        if cfg.get("tone", False):
            commands.append({
                "action": "Tone",
                "endpoint": "POST /api/controls/tone/start",
                "payload": {
                    "path": cfg.get("tone_wav", "bell-na.wav"),
                    "loop": "false"
                }
            })

    elif vendor_name == "Freeport":
        font_size = cfg.get("freeport_detail_font_size", 160)
        commands.append({
            "action": "Freeport Alert",
            "endpoint": f"TLS {cfg.get('target_host', '')}:{cfg.get('target_port', 80)}",
            "payload": [
                "set feature background visible: false",
                "set feature message 1 text: ALERT",
                "set feature message 1 font color: #D30000",
                "set feature message 1 font size: 220",
                "set feature message 2 visible: true",
                "set feature message 2 font color: #D30000",
                f"set feature message 2 font size: {font_size}",
                f'set feature message 2 text: "{alert_text}"',
                "set feature clock 0 visible: false",
                "set feature clock 1 visible: false",
                "set feature clock 2 visible: false",
                "set feature clock 3 visible: false",
            ]
        })

    return {"vendor": vendor_name, "commands": commands}


@app.post("/api/clear-display", response_class=JSONResponse)
async def proxy_clear_display(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    cfg = load_config()
    scheme = "https" if cfg.get("source_ssl") else "http"
    host = cfg.get("source_host", "0.0.0.0")
    if host == "0.0.0.0":
        host = "127.0.0.1"
    port = cfg.get("source_port", 8001)
    url = f"{scheme}://{host}:{port}/clear-display"
    try:
        resp = requests.post(url, timeout=10, verify=False)
        return {"status": "ok", "code": resp.status_code}
    except requests.exceptions.ConnectionError:
        return JSONResponse(status_code=502, content={"status": "error", "detail": "Could not connect to integration service. Is it running?"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(e)})


@app.post("/api/test", response_class=JSONResponse)
async def send_test(request: Request, credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    body = await request.json()
    test_type = body.get("test_type")
    payload = body.get("payload")
    cfg = load_config()
    scheme = "https" if cfg.get("source_ssl") else "http"
    host = cfg.get("source_host", "0.0.0.0")
    if host == "0.0.0.0":
        host = "127.0.0.1"
    port = cfg.get("source_port", 8001)
    if test_type == "zone_detection":
        path = cfg.get("source_path", "/zone-detections")
        url = f"{scheme}://{host}:{port}{path}"
        data = json.dumps(payload)
        headers = {"Content-Type": "application/x-ndjson"}
    else:
        path = cfg.get("adam_path", "/adam-findings")
        url = f"{scheme}://{host}:{port}{path}"
        data = json.dumps(payload)
        headers = {"Content-Type": "application/json"}
    try:
        resp = requests.post(url, data=data, headers=headers, timeout=10, verify=False)
        try:
            resp_json = resp.json()
            if resp_json.get("errors"):
                return {"status": "error", "code": resp.status_code, "detail": "; ".join(resp_json["errors"])}
        except Exception:
            pass
        return {"status": "ok", "code": resp.status_code, "response": resp.text}
    except requests.exceptions.ConnectionError:
        return JSONResponse(status_code=502, content={"status": "error", "detail": "Could not connect to integration service. Is it running?"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(e)})


@app.get("/api/alerts", response_class=JSONResponse)
async def get_alerts(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "r") as f:
            alerts = json.load(f)
        return alerts
    return []


@app.delete("/api/alerts", response_class=JSONResponse)
async def clear_alerts(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    if os.path.exists(ALERTS_FILE):
        os.remove(ALERTS_FILE)
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def config_page(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    config = load_config()
    tone_options_json = str(TONE_OPTIONS).replace("'", '"')
    return HTML_PAGE.replace("__TONE_OPTIONS__", tone_options_json).replace("__VERSION__", VERSION)


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bastille Display Integration - Configuration</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2a2d3a;
    --accent: #4f8ff7;
    --accent-hover: #6da3ff;
    --text: #e1e4ed;
    --text-muted: #8b8fa3;
    --success: #3cb043;
    --danger: #d30000;
    --warning: #f5a623;
    --input-bg: #12141c;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 2rem;
  }
  .container { max-width: 780px; margin: 0 auto; }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border);
  }
  h1 { font-size: 1.5rem; font-weight: 600; }
  h1 span { color: var(--accent); }
  .badge {
    font-size: 0.75rem;
    padding: 0.25rem 0.6rem;
    border-radius: 4px;
    font-weight: 500;
  }
  .badge-algo { background: #1e3a5f; color: #6da3ff; }
  .badge-freeport { background: #3a1e5f; color: #b06dff; }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .card-title {
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: 1rem;
    color: var(--text);
  }

  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  .form-group { display: flex; flex-direction: column; }
  .form-group.full { grid-column: 1 / -1; }
  label {
    font-size: 0.8rem;
    font-weight: 500;
    color: var(--text-muted);
    margin-bottom: 0.35rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  input, select {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.55rem 0.75rem;
    color: var(--text);
    font-size: 0.9rem;
    outline: none;
    transition: border-color 0.15s;
  }
  input:focus, select:focus { border-color: var(--accent); }
  input[type="number"] { width: 100%; }

  .vendor-select {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 0.5rem;
  }
  .vendor-btn {
    flex: 1;
    padding: 0.75rem;
    border: 2px solid var(--border);
    border-radius: 8px;
    background: var(--input-bg);
    color: var(--text-muted);
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
    text-align: center;
  }
  .vendor-btn:hover { border-color: var(--accent); color: var(--text); }
  .vendor-btn.active { border-color: var(--accent); color: var(--accent); background: #1a2640; }

  .checkbox-group {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  .checkbox-pill {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.35rem 0.75rem;
    border: 1px solid var(--border);
    border-radius: 20px;
    background: var(--input-bg);
    cursor: pointer;
    font-size: 0.85rem;
    transition: all 0.15s;
    user-select: none;
  }
  .checkbox-pill:has(input:checked) {
    border-color: var(--accent);
    background: #1a2640;
    color: var(--accent);
  }
  .checkbox-pill input { display: none; }

  .tag-input-wrap {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.4rem 0.55rem;
    min-height: 38px;
    align-items: center;
    cursor: text;
  }
  .tag-input-wrap:focus-within { border-color: var(--accent); }
  .tag {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    background: #1a2640;
    color: var(--accent);
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-size: 0.8rem;
  }
  .tag button {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 0.9rem;
    line-height: 1;
    padding: 0;
  }
  .tag button:hover { color: var(--danger); }
  .tag-input {
    border: none;
    background: none;
    color: var(--text);
    font-size: 0.85rem;
    outline: none;
    flex: 1;
    min-width: 80px;
    padding: 0.15rem 0;
  }

  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem 0;
  }
  .toggle-label { font-size: 0.9rem; }
  .toggle {
    position: relative;
    width: 44px;
    height: 24px;
  }
  .toggle input { display: none; }
  .toggle-slider {
    position: absolute;
    inset: 0;
    background: var(--border);
    border-radius: 12px;
    cursor: pointer;
    transition: background 0.2s;
  }
  .toggle-slider::after {
    content: '';
    position: absolute;
    width: 18px;
    height: 18px;
    background: var(--text);
    border-radius: 50%;
    top: 3px;
    left: 3px;
    transition: transform 0.2s;
  }
  .toggle input:checked + .toggle-slider { background: var(--accent); }
  .toggle input:checked + .toggle-slider::after { transform: translateX(20px); }

  .vendor-section { display: none; }
  .vendor-section.active { display: block; }

  .actions {
    display: flex;
    gap: 0.75rem;
    justify-content: flex-end;
    margin-top: 1.5rem;
  }
  .btn {
    padding: 0.6rem 1.5rem;
    border: none;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
  }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-warning { background: var(--warning); color: #000; }
  .btn-warning:hover { background: #ffc04d; }
  .btn-warning:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-secondary {
    background: transparent;
    color: var(--text-muted);
    border: 1px solid var(--border);
  }
  .btn-secondary:hover { border-color: var(--text-muted); color: var(--text); }

  .toast {
    position: fixed;
    bottom: 2rem;
    right: 2rem;
    padding: 0.75rem 1.25rem;
    border-radius: 6px;
    font-size: 0.9rem;
    font-weight: 500;
    color: #fff;
    opacity: 0;
    transform: translateY(10px);
    transition: all 0.3s;
    pointer-events: none;
    z-index: 100;
  }
  .toast.show { opacity: 1; transform: translateY(0); }
  .toast.success { background: var(--success); }
  .toast.error { background: var(--danger); }

  .file-upload-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-top: 0.5rem;
  }
  .file-upload-row label.file-btn {
    padding: 0.45rem 1rem;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-size: 0.85rem;
    cursor: pointer;
    text-transform: none;
    letter-spacing: 0;
    transition: border-color 0.15s;
  }
  .file-upload-row label.file-btn:hover { border-color: var(--accent); }
  .file-upload-row input[type="file"] { display: none; }
  .file-name {
    font-size: 0.8rem;
    color: var(--text-muted);
  }
  .cert-status {
    font-size: 0.8rem;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
  }
  .cert-status.found { background: #1a3a1a; color: var(--success); }
  .cert-status.missing { background: #3a1a1a; color: var(--danger); }
  .ssl-fields { margin-top: 1rem; }
  .ssl-fields.hidden { display: none; }

  .status-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  .status-box {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
  }
  .status-box-title {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--text-muted);
    margin-bottom: 0.5rem;
  }
  .status-indicator {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.9rem;
    font-weight: 600;
  }
  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
  }
  .status-dot.active { background: var(--success); }
  .status-dot.inactive { background: var(--danger); }
  .status-dot.unknown { background: var(--text-muted); }
  .status-detail {
    font-size: 0.8rem;
    color: var(--text-muted);
    margin-top: 0.25rem;
  }
  .config-summary-wrap {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-top: 1rem;
  }
  .config-summary-section {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem 1rem;
  }
  .config-summary-section-title {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--accent);
    margin-bottom: 0.5rem;
    padding-bottom: 0.35rem;
    border-bottom: 1px solid var(--border);
  }
  .config-summary-item {
    display: flex;
    justify-content: space-between;
    font-size: 0.8rem;
    padding: 0.2rem 0;
  }
  .config-summary-item .key { color: var(--text-muted); }
  .config-summary-item .val { color: var(--text); font-weight: 500; }
  .config-summary-section.full { grid-column: 1 / -1; }
  .status-refresh {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 0.25rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.15s;
  }
  .status-refresh:hover { border-color: var(--accent); color: var(--accent); }

  .tabs {
    display: flex;
    gap: 0;
    margin-bottom: 1.5rem;
    border-bottom: 2px solid var(--border);
  }
  .tab-btn {
    padding: 0.65rem 1.5rem;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    color: var(--text-muted);
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
  }
  .tab-btn:hover { color: var(--text); }
  .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  .alerts-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }
  .alerts-toolbar .count { font-size: 0.85rem; color: var(--text-muted); }
  .alert-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.8rem;
  }
  .alert-table th {
    text-align: left;
    padding: 0.5rem 0.6rem;
    border-bottom: 2px solid var(--border);
    color: var(--text-muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    font-weight: 600;
  }
  .alert-table td {
    padding: 0.45rem 0.6rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  .alert-table tr:hover td { background: var(--input-bg); }
  .severity-badge {
    font-size: 0.7rem;
    padding: 0.15rem 0.45rem;
    border-radius: 3px;
    font-weight: 600;
    text-transform: uppercase;
  }
  .severity-critical { background: #5c0a0a; color: #ff6b6b; }
  .severity-high { background: #4a1a0a; color: #ff8c42; }
  .severity-medium { background: #4a3a0a; color: #ffc04d; }
  .severity-low { background: #1a3a1a; color: #6dff6d; }
  .status-badge {
    font-size: 0.7rem;
    padding: 0.15rem 0.45rem;
    border-radius: 3px;
    font-weight: 600;
  }
  .status-sent { background: #1a3a1a; color: var(--success); }
  .status-filtered { background: #3a3a1a; color: var(--warning); }
  .type-badge {
    font-size: 0.7rem;
    padding: 0.15rem 0.45rem;
    border-radius: 3px;
    font-weight: 500;
  }
  .type-zone { background: #1e3a5f; color: #6da3ff; }
  .type-adam { background: #3a1e5f; color: #b06dff; }
  .alert-empty {
    text-align: center;
    padding: 3rem;
    color: var(--text-muted);
    font-size: 0.9rem;
  }
  .docs h2 {
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--accent);
    margin-top: 1.5rem;
    margin-bottom: 0.5rem;
    padding-bottom: 0.35rem;
    border-bottom: 1px solid var(--border);
  }
  .docs h2:first-child { margin-top: 0; }
  .docs h3 {
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--text);
    margin-top: 1rem;
    margin-bottom: 0.4rem;
  }
  .docs p, .docs li {
    font-size: 0.85rem;
    color: var(--text-muted);
    line-height: 1.6;
  }
  .docs ul { padding-left: 1.25rem; margin: 0.4rem 0; }
  .docs li { margin-bottom: 0.25rem; }
  .docs code {
    background: var(--input-bg);
    border: 1px solid var(--border);
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    font-size: 0.8rem;
    color: var(--accent);
  }
  .docs .note {
    background: #1a2640;
    border-left: 3px solid var(--accent);
    padding: 0.6rem 0.75rem;
    border-radius: 0 4px 4px 0;
    margin: 0.75rem 0;
    font-size: 0.8rem;
    color: var(--text);
  }
  .docs ol { padding-left: 1.25rem; margin: 0.4rem 0; }
  .docs ol li { margin-bottom: 0.35rem; }
  .docs strong { color: var(--text); }
  .docs pre {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem;
    font-size: 0.78rem;
    overflow-x: auto;
    margin: 0.5rem 0;
    color: var(--text-muted);
    line-height: 1.5;
  }
  .user-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    margin-bottom: 0.75rem;
  }
  .user-table th {
    text-align: left;
    padding: 0.4rem 0.6rem;
    border-bottom: 2px solid var(--border);
    color: var(--text-muted);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  .user-table td {
    padding: 0.4rem 0.6rem;
    border-bottom: 1px solid var(--border);
  }
  .user-table tr:hover td { background: var(--input-bg); }
  .user-actions { display: flex; gap: 0.4rem; }
  .user-actions button {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.15s;
  }
  .user-actions button:hover { border-color: var(--accent); color: var(--accent); }
  .user-actions button.delete:hover { border-color: var(--danger); color: var(--danger); }
  .command-preview {
    margin-top: 1rem;
    display: none;
  }
  .command-preview.show { display: block; }
  .command-card {
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem 1rem;
    margin-bottom: 0.75rem;
  }
  .command-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
  }
  .command-action {
    font-weight: 600;
    font-size: 0.85rem;
    color: var(--accent);
  }
  .command-endpoint {
    font-size: 0.75rem;
    color: var(--text-muted);
    font-family: monospace;
  }
  .command-json {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.6rem 0.75rem;
    font-family: monospace;
    font-size: 0.78rem;
    color: var(--text);
    white-space: pre-wrap;
    word-break: break-word;
    overflow-x: auto;
    max-height: 300px;
    overflow-y: auto;
  }
  .command-json .json-key { color: #6da3ff; }
  .command-json .json-string { color: #98c379; }
  .command-json .json-number { color: #d19a66; }
  .command-json .json-bool { color: #c678dd; }

  .test-type-select {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }
  .test-type-btn {
    flex: 1;
    padding: 0.6rem;
    border: 2px solid var(--border);
    border-radius: 8px;
    background: var(--input-bg);
    color: var(--text-muted);
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
    text-align: center;
  }
  .test-type-btn:hover { border-color: var(--accent); color: var(--text); }
  .test-type-btn.active { border-color: var(--accent); color: var(--accent); background: #1a2640; }
  .test-fields { display: none; }
  .test-fields.active { display: block; }
  .test-result {
    margin-top: 0.75rem;
    padding: 0.75rem;
    border-radius: 6px;
    font-size: 0.85rem;
    font-family: monospace;
    display: none;
    word-break: break-all;
  }
  .test-result.show { display: block; }
  .test-result.ok { background: #1a3a1a; color: var(--success); border: 1px solid #2a4a2a; }
  .test-result.fail { background: #3a1a1a; color: var(--danger); border: 1px solid #4a2a2a; }
  .color-swatch {
    display: flex;
    gap: 0.4rem;
    flex-wrap: wrap;
  }
  .swatch {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    border: 2px solid transparent;
    cursor: pointer;
    transition: border-color 0.15s;
  }
  .swatch:hover { border-color: var(--text-muted); }
  .swatch.active { border-color: #fff; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>Bastille</span> Display Integration <span style="font-size: 0.7rem; color: var(--text-muted); font-weight: 400;">v__VERSION__</span></h1>
    <span class="badge" id="vendorBadge">-</span>
  </header>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('status')">Status</button>
    <button class="tab-btn" onclick="switchTab('config')">Configuration</button>
    <button class="tab-btn" onclick="switchTab('testing')">Testing</button>
    <button class="tab-btn" onclick="switchTab('alerts')">Alerts</button>
    <button class="tab-btn" onclick="switchTab('docs')">Documentation</button>
  </div>

  <div class="tab-content active" id="tabStatus">

  <!-- Status Dashboard -->
  <div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
      <div class="card-title" style="margin-bottom: 0;">Status</div>
      <div style="display: flex; align-items: center; gap: 0.75rem;">
        <span style="font-size: 0.75rem; color: var(--text-muted);">Version: <strong id="statusVersion" style="color: var(--accent);">-</strong></span>
        <button class="status-refresh" onclick="loadStatus()">Refresh</button>
      </div>
    </div>
    <div class="status-grid" style="grid-template-columns: 1fr 1fr 1fr;">
      <div class="status-box">
        <div class="status-box-title">Integration Service</div>
        <div class="status-indicator">
          <span class="status-dot unknown" id="intStatusDot"></span>
          <span id="intStatusText">Loading...</span>
        </div>
        <div class="status-detail" id="intStatusDetail"></div>
      </div>
      <div class="status-box">
        <div class="status-box-title">Config UI Service</div>
        <div class="status-indicator">
          <span class="status-dot unknown" id="uiStatusDot"></span>
          <span id="uiStatusText">Loading...</span>
        </div>
        <div class="status-detail" id="uiStatusDetail"></div>
      </div>
      <div class="status-box">
        <div class="status-box-title">Display Target</div>
        <div class="status-indicator">
          <span class="status-dot unknown" id="targetStatusDot"></span>
          <span id="targetStatusText">Checking...</span>
        </div>
        <div class="status-detail" id="targetStatusDetail"></div>
      </div>
    </div>
    <div class="config-summary-wrap" id="configSummary"></div>
  </div>

  </div><!-- end tabStatus -->

  <div class="tab-content" id="tabConfig">

  <!-- Vendor Selection -->
  <div class="card">
    <div class="card-title">Display Vendor</div>
    <div class="vendor-select">
      <button class="vendor-btn" data-vendor="Algo" onclick="selectVendor('Algo')">Algo</button>
      <button class="vendor-btn" data-vendor="Freeport" onclick="selectVendor('Freeport')">Freeport</button>
    </div>
  </div>

  <!-- Global Settings -->
  <div class="card">
    <div class="card-title">Global Settings</div>
    <div class="form-grid">
      <div class="form-group">
        <label>Log File</label>
        <input type="text" id="log_file" placeholder="e.g. app.log">
      </div>
      <div class="form-group">
        <label>Clear Time (seconds)</label>
        <input type="number" id="clear_time" min="1" placeholder="Seconds before display clears (e.g. 60)">
      </div>
      <div class="form-group">
        <label>Listener Host</label>
        <input type="text" id="source_host" placeholder="0.0.0.0 to listen on all interfaces">
      </div>
      <div class="form-group">
        <label>Listener Port</label>
        <input type="number" id="source_port" min="1" max="65535" placeholder="e.g. 8001">
      </div>
      <div class="form-group">
        <label>Zone Detections Path</label>
        <input type="text" id="source_path" placeholder="e.g. /zone-detections">
      </div>
      <div class="form-group">
        <label>ADAM Findings Path</label>
        <input type="text" id="adam_path" placeholder="e.g. /adam-findings">
      </div>
    </div>
  </div>

  <!-- Listener SSL/TLS -->
  <div class="card">
    <div class="card-title">Webhook Listener Protocol &mdash; <span id="protoLabel" style="color: var(--accent);">HTTP</span></div>
    <div class="vendor-select">
      <button class="vendor-btn" data-proto="http" onclick="selectProto('http')">HTTP</button>
      <button class="vendor-btn" data-proto="https" onclick="selectProto('https')">HTTPS</button>
    </div>
    <div class="ssl-fields hidden" id="sslFields">
      <div style="margin-bottom: 0.75rem;">
        <span class="cert-status" id="certStatus">Checking...</span>
      </div>
      <div class="form-group">
        <label>Upload SSL Certificate &amp; Key</label>
        <div class="file-upload-row">
          <label class="file-btn">
            Certificate (.pem)
            <input type="file" id="certFile" accept=".pem,.crt,.cer">
          </label>
          <span class="file-name" id="certFileName">No file chosen</span>
        </div>
        <div class="file-upload-row" style="margin-top: 0.5rem;">
          <label class="file-btn">
            Private Key (.pem)
            <input type="file" id="keyFile" accept=".pem,.key">
          </label>
          <span class="file-name" id="keyFileName">No file chosen</span>
        </div>
        <button class="btn btn-primary" style="margin-top: 0.75rem;" onclick="uploadCert()">Upload Certificate</button>
      </div>
    </div>
  </div>

  <!-- Monitored Protocols -->
  <div class="card">
    <div class="card-title">Monitored Protocols</div>
    <div class="checkbox-group" id="protocols"></div>
    <div style="display: flex; gap: 0.5rem; margin-top: 0.75rem; align-items: center;">
      <input type="text" id="newProtoInput" placeholder="Add protocol..." style="flex: 1;">
      <button class="btn btn-primary" style="padding: 0.5rem 1rem;" onclick="addProtocol()">Add</button>
    </div>
  </div>

  <!-- Display Messages -->
  <div class="card">
    <div class="card-title">Display Message Templates</div>
    <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.75rem;">
      Variables: <code>{protocol}</code> <code>{zone}</code> <code>{vendor}</code> <code>{tags}</code> &mdash;
      ADAM only: <code>{severity}</code> <code>{reasons}</code>
    </p>
    <div class="form-grid">
      <div class="form-group full">
        <label>Zone Detection Template</label>
        <input type="text" id="zone_detection_template" placeholder="e.g. ALERT - {protocol} in {zone} - Vendor: {vendor}">
      </div>
      <div class="form-group full">
        <label>ADAM Finding Template</label>
        <input type="text" id="adam_finding_template" placeholder="e.g. ADAM ALERT - {severity} - {reasons} - {protocol} in {zone}">
      </div>
    </div>
  </div>

  <!-- Allowed Tags -->
  <div class="card">
    <div class="card-title">Allowed Tags (devices with these tags will NOT alert)</div>
    <div class="tag-input-wrap" id="tagWrap" onclick="this.querySelector('input').focus()">
      <input class="tag-input" id="tagInput" placeholder="Type and press Enter...">
    </div>
  </div>

  <!-- Algo Settings -->
  <div class="vendor-section" id="algoSection">
    <div class="card">
      <div class="card-title">Algo Connection</div>
      <div class="form-grid">
        <div class="form-group">
          <label>Target Host</label>
          <input type="text" id="algo_target_host" placeholder="http://&lt;IP of Algo&gt; or https://&lt;IP of Algo&gt;">
        </div>
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="algo_username" placeholder="Algo API username (e.g. admin)">
        </div>
        <div class="form-group">
          <label>API Password</label>
          <input type="password" id="algo_password" placeholder="Algo API password">
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Algo Display</div>
      <div class="form-grid">
        <div class="form-group">
          <label>Text Color</label>
          <select id="algo_text_color">
            <option value="red">Red</option>
            <option value="orange">Orange</option>
            <option value="yellow">Yellow</option>
            <option value="green">Green</option>
            <option value="blue">Blue</option>
            <option value="white">White</option>
          </select>
        </div>
        <div class="form-group">
          <label>Text Font</label>
          <select id="algo_text_font">
            <option value="roboto">Roboto</option>
            <option value="arial">Arial</option>
            <option value="courier">Courier</option>
            <option value="times">Times</option>
            <option value="verdana">Verdana</option>
          </select>
        </div>
        <div class="form-group">
          <label>Text Size</label>
          <select id="algo_text_size">
            <option value="small">Small</option>
            <option value="medium">Medium</option>
            <option value="large">Large</option>
          </select>
        </div>
        <div class="form-group">
          <label>Text Position</label>
          <select id="algo_text_position">
            <option value="top">Top</option>
            <option value="middle">Middle</option>
            <option value="bottom">Bottom</option>
          </select>
        </div>
        <div class="form-group">
          <label>Text Scroll</label>
          <select id="algo_text_scroll">
            <option value="0">Off</option>
            <option value="1">On</option>
          </select>
        </div>
        <div class="form-group">
          <label>Scroll Speed</label>
          <select id="algo_text_scroll_speed">
            <option value="1">1 - Slowest</option>
            <option value="2">2 - Slow</option>
            <option value="3">3 - Medium</option>
            <option value="4">4 - Fast</option>
            <option value="5">5 - Fastest</option>
          </select>
        </div>
        <div class="form-group">
          <label>Strobe Pattern</label>
          <select id="algo_strobe_pattern">
            <option value="1">1 - Slow</option>
            <option value="2">2 - Medium</option>
            <option value="3">3 - Fast</option>
            <option value="4">4 - Pulse</option>
          </select>
        </div>
        <div class="form-group">
          <label>Strobe Color</label>
          <select id="algo_strobe_color">
            <option value="red">Red</option>
            <option value="orange">Orange</option>
            <option value="yellow">Yellow</option>
            <option value="green">Green</option>
            <option value="blue">Blue</option>
            <option value="white">White</option>
          </select>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Algo Audio</div>
      <div class="toggle-row">
        <span class="toggle-label">Enable Tone</span>
        <label class="toggle">
          <input type="checkbox" id="algo_tone">
          <span class="toggle-slider"></span>
        </label>
      </div>
      <div class="form-group" id="toneWavGroup" style="margin-top: 0.75rem;">
        <label>Tone Sound</label>
        <select id="algo_tone_wav"></select>
      </div>
    </div>
  </div>

  <!-- Freeport Settings -->
  <div class="vendor-section" id="freeportSection">
    <div class="card">
      <div class="card-title">Freeport Connection</div>
      <div class="form-grid">
        <div class="form-group">
          <label>Target Host</label>
          <input type="text" id="freeport_target_host" placeholder="&lt;IP of Freeport&gt; - https:// not required, as TLS connection">
        </div>
        <div class="form-group">
          <label>Target Port</label>
          <input type="number" id="freeport_target_port" min="1" max="65535" placeholder="e.g. 2311">
        </div>
        <div class="form-group">
          <label>API Username</label>
          <input type="text" id="freeport_username" placeholder="Freeport API username">
        </div>
        <div class="form-group">
          <label>API Password</label>
          <input type="password" id="freeport_password" placeholder="Freeport API password">
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Freeport Display</div>
      <div class="form-grid">
        <div class="form-group">
          <label>Alert Detail Font Size</label>
          <input type="number" id="freeport_detail_font_size" min="20" max="500" value="160" placeholder="Default: 160">
        </div>
      </div>
    </div>
  </div>

  <div class="actions">
    <button class="btn btn-secondary" onclick="loadConfig()">Discard Changes</button>
    <button class="btn btn-primary" onclick="saveConfig()">Save Configuration</button>
    <button class="btn btn-warning" id="restartBtn" onclick="saveAndRestart()">Save &amp; Restart Service</button>
  </div>

  <div class="card">
    <div class="card-title">User Management</div>
    <div id="userTable"></div>
    <div class="form-grid" style="margin-top: 0.5rem;">
      <div class="form-group">
        <label>Username</label>
        <input type="text" id="new_user_name" placeholder="Username">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" id="new_user_pass" placeholder="Password">
      </div>
    </div>
    <button class="btn btn-primary" style="margin-top: 0.5rem;" onclick="addUser()">Add User</button>
  </div>

  <div class="card">
    <div class="card-title">Backup &amp; Restore</div>
    <div style="display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap;">
      <button class="btn btn-secondary" onclick="exportConfig()">Export Config</button>
      <label class="btn btn-secondary" style="cursor: pointer;">
        Restore Config
        <input type="file" id="restoreFile" accept=".yaml,.yml,.zip" style="display: none;" onchange="restoreConfig()">
      </label>
    </div>
  </div>

  </div><!-- end tabConfig -->

  <div class="tab-content" id="tabTesting">

  <!-- Test Alert -->
  <div class="card">
    <div class="card-title">Test Alert</div>
    <div class="test-type-select">
      <button class="test-type-btn" data-test="zone_detection" onclick="selectTestType('zone_detection')">Zone Detection</button>
      <button class="test-type-btn" data-test="adam_finding" onclick="selectTestType('adam_finding')">ADAM Finding</button>
    </div>

    <!-- Zone Detection Test Fields -->
    <div class="test-fields" id="testZoneFields">
      <div class="form-grid">
        <div class="form-group">
          <label>Protocol</label>
          <select id="test_zd_protocol"></select>
        </div>
        <div class="form-group">
          <label>Zone Name</label>
          <input type="text" id="test_zd_zone" value="Training 1A">
        </div>
        <div class="form-group">
          <label>Vendor</label>
          <input type="text" id="test_zd_vendor" value="LGInnotek">
        </div>
        <div class="form-group">
          <label>Manufacturer</label>
          <input type="text" id="test_zd_manufacturer" value="Unknown">
        </div>
        <div class="form-group">
          <label>Transmitter ID</label>
          <input type="text" id="test_zd_transmitter" value="f8:96:fe:3c:a3:c3">
        </div>
        <div class="form-group">
          <label>Tags (comma-separated)</label>
          <input type="text" id="test_zd_tags" value="Connected, Unknown Connected Wi-Fi Network">
        </div>
      </div>
      <button class="btn btn-primary" style="margin-top: 1rem;" onclick="sendTest('zone_detection')">Send Zone Detection Test</button>
    </div>

    <!-- ADAM Finding Test Fields -->
    <div class="test-fields" id="testAdamFields">
      <div class="form-grid">
        <div class="form-group">
          <label>Protocol</label>
          <select id="test_adam_protocol"></select>
        </div>
        <div class="form-group">
          <label>Severity</label>
          <select id="test_adam_severity">
            <option value="critical">Critical</option>
            <option value="high" selected>High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div class="form-group">
          <label>Reason</label>
          <input type="text" id="test_adam_reason" value="malicious_device_pineapple">
        </div>
        <div class="form-group">
          <label>Zone (from tag)</label>
          <input type="text" id="test_adam_zone" value="Training 1A">
        </div>
        <div class="form-group">
          <label>Vendor</label>
          <input type="text" id="test_adam_vendor" value="LGInnotek">
        </div>
        <div class="form-group">
          <label>Transmitter ID</label>
          <input type="text" id="test_adam_transmitter" value="f8:96:fe:3c:a3:c3">
        </div>
        <div class="form-group">
          <label>Network Name</label>
          <input type="text" id="test_adam_network" value="NXP Micro AP">
        </div>
        <div class="form-group">
          <label>Tags (comma-separated)</label>
          <input type="text" id="test_adam_tags" value="Connected, zone:Training 1A">
        </div>
        <div class="form-group">
          <label>Severity Score (1-5)</label>
          <input type="number" id="test_adam_score" value="3" min="1" max="5">
        </div>
        <div class="form-group">
          <label>Webhook Name</label>
          <input type="text" id="test_adam_webhook_name" value="Test Data">
        </div>
      </div>
      <button class="btn btn-primary" style="margin-top: 1rem;" onclick="sendTest('adam_finding')">Send ADAM Finding Test</button>
    </div>

    <div class="test-result" id="testResult"></div>
  </div>

  <div class="card">
    <div class="card-title">Preview Display Commands</div>
    <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.75rem;">Shows the exact commands and payloads that will be sent to the display target based on your current test data and configuration.</p>
    <div style="display: flex; gap: 0.5rem;">
      <button class="btn btn-secondary" onclick="previewCommands('zone_detection')">Preview Zone Detection</button>
      <button class="btn btn-secondary" onclick="previewCommands('adam_finding')">Preview ADAM Finding</button>
    </div>
    <div class="command-preview" id="commandPreview"></div>
  </div>

  <div class="card">
    <div class="card-title">Clear Display</div>
    <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">Send a clear command to the display target, removing any active alert and stopping strobes/tones.</p>
    <button class="btn btn-secondary" style="color: var(--warning); border-color: var(--warning);" onclick="clearDisplay()">Clear Display</button>
  </div>

  </div><!-- end tabTesting -->

  <div class="tab-content" id="tabAlerts">
    <div class="card">
      <div class="alerts-toolbar">
        <span class="count" id="alertCount">0 alerts</span>
        <div style="display: flex; gap: 0.5rem;">
          <button class="status-refresh" onclick="loadAlerts()">Refresh</button>
          <button class="status-refresh" style="color: var(--danger); border-color: var(--danger);" onclick="clearAlerts()">Clear All</button>
        </div>
      </div>
      <div id="alertsContainer">
        <div class="alert-empty">No alerts recorded yet.</div>
      </div>
    </div>
  </div><!-- end tabAlerts -->

  <div class="tab-content" id="tabDocs">
    <div class="card docs">

      <h2>Overview</h2>
      <p>The Bastille Display Integration receives webhook alerts from the Bastille platform and triggers visual and audio alerts on connected display hardware. It supports two webhook types and two display vendors:</p>
      <ul>
        <li><strong>Zone Detections</strong> &mdash; triggered when Bastille detects wireless devices in monitored zones (ndjson format)</li>
        <li><strong>ADAM Findings</strong> &mdash; triggered when Bastille ADAM identifies security threats with severity ratings (json format)</li>
        <li><strong>Algo</strong> &mdash; controlled via HTTP REST API (screen text, strobe lights, audio tones)</li>
        <li><strong>Freeport</strong> &mdash; controlled via TLS socket commands (screen text, clock visibility)</li>
      </ul>

      <h2>Global Settings</h2>
      <ul>
        <li><strong>Log File</strong> &mdash; path to the application log file (default: <code>app.log</code>)</li>
        <li><strong>Listener Host</strong> &mdash; IP address to bind the webhook listener. Use <code>0.0.0.0</code> to listen on all interfaces (default: <code>0.0.0.0</code>)</li>
        <li><strong>Listener Port</strong> &mdash; port for the webhook listener (default: <code>8001</code>)</li>
        <li><strong>Zone Detections Path</strong> &mdash; URL path for zone detection webhooks (default: <code>/zone-detections</code>)</li>
        <li><strong>ADAM Findings Path</strong> &mdash; URL path for ADAM finding webhooks (default: <code>/adam-findings</code>)</li>
        <li><strong>Clear Time</strong> &mdash; seconds to wait before clearing the display after the last alert. If a new alert arrives during this window, the timer resets (default: <code>60</code>)</li>
        <li><strong>Monitored Protocols</strong> &mdash; only alerts matching these protocols will trigger the display. Custom protocols can be added (default: <code>cellular, wifi, ble</code>)</li>
        <li><strong>Allowed Tags</strong> &mdash; devices tagged with any of these tags will not trigger alerts (default: <code>authorized, exclude</code>)</li>
      </ul>

      <h2>Applying Changes</h2>
      <p>Most configuration changes require the integration service to be <strong>restarted</strong> before they take effect. This includes changes to:</p>
      <ul>
        <li>Listener settings (host, port, webhook paths)</li>
        <li>Vendor selection (switching between Algo and Freeport)</li>
        <li>Connection settings (target host, port, credentials)</li>
        <li>SSL settings (enabling/disabling HTTPS, certificate changes)</li>
        <li>Monitored protocols and allowed tags</li>
      </ul>
      <p>Use the <strong>Save &amp; Restart Service</strong> button in the Configuration tab to save and restart in one step. The config UI will briefly disconnect during the restart.</p>
      <div class="note"><strong>Exception:</strong> Display message templates and Algo text display settings (font, size, scroll, position) are read live from the config file on each alert and take effect immediately after saving &mdash; no restart required.</div>

      <h2>How It Works</h2>
      <p>When a webhook is received, the integration:</p>
      <ol>
        <li>Parses the incoming payload to extract protocol, zone, vendor, and device information</li>
        <li>Checks if the protocol is in the monitored protocols list &mdash; if not, the alert is filtered</li>
        <li>Checks if the device has any allowed tags &mdash; if so, the alert is filtered</li>
        <li>Applies the configured display message template to build the alert text</li>
        <li>Sends the alert to the configured display device (Algo or Freeport)</li>
        <li>Schedules an automatic clear after the configured clear time, unless new alerts arrive</li>
      </ol>
      <p>All alerts (sent and filtered) are logged and visible in the <strong>Alerts</strong> tab.</p>

      <h2>Configuring Display Devices</h2>

      <h3>Algo Setup</h3>
      <ol>
        <li>Open the Algo web interface in a browser: <code>http://&lt;algo-ip&gt;</code></li>
        <li>Log in with the Algo admin credentials</li>
        <li>Navigate to <strong>API</strong> or <strong>Advanced Settings</strong></li>
        <li><strong>Enable the API</strong> &mdash; ensure the REST API is turned on</li>
        <li>Note the username and password for API access (default is typically <code>admin</code> / <code>algo</code>)</li>
        <li>In the <strong>Configuration</strong> tab, enter the Algo target host (e.g., <code>http://&lt;algo-ip&gt;</code>), port, and credentials under <strong>Algo Connection</strong></li>
      </ol>
      <div class="note">The integration sends HTTP POST requests to the Algo REST API for screen text, strobe control, and audio tones. Self-signed certificates on the Algo are accepted automatically.</div>

      <h3>Freeport Setup</h3>
      <ol>
        <li>Log in to the Freeport management interface</li>
        <li>Navigate to <strong>User Management</strong> or <strong>Administration</strong></li>
        <li><strong>Create a new user</strong> with API privileges:
          <ul>
            <li>Set a username and password (e.g., <code>bn</code> / <code>bn</code>)</li>
            <li>Ensure the user has <strong>API access</strong> permissions enabled</li>
          </ul>
        </li>
        <li>Navigate to <strong>API Settings</strong> or <strong>System Configuration</strong></li>
        <li><strong>Enable the API</strong> &mdash; ensure the TLS API interface is turned on and note the port (default is typically <code>80</code>)</li>
        <li>In the <strong>Configuration</strong> tab, enter the Freeport target host (IP address, not URL), port, and credentials under <strong>Freeport Connection</strong></li>
      </ol>
      <div class="note">The integration connects to the Freeport via TLS socket, authenticates with the API user credentials, and sends display commands. Certificate verification is disabled for self-signed certificates.</div>

      <h3>Verifying Display Connectivity</h3>
      <ol>
        <li>Go to the <strong>Status</strong> tab &mdash; the <strong>Display Target</strong> box should show "Reachable"</li>
        <li>Go to the <strong>Testing</strong> tab and use <strong>Preview Display Commands</strong> to verify the payloads look correct</li>
        <li>Send a test alert to confirm the display responds</li>
        <li>Use <strong>Clear Display</strong> to reset the display after testing</li>
      </ol>

      <h2>Configuring Bastille Webhooks</h2>

      <h3>Zone Detection Webhook</h3>
      <ol>
        <li>Log in to the Bastille command console</li>
        <li>Navigate to <strong>Settings &gt; Webhooks</strong></li>
        <li>Click <strong>Add Webhook</strong></li>
        <li>Configure the webhook:
          <ul>
            <li><strong>Name</strong>: Display Integration - Zone Detections</li>
            <li><strong>Type</strong>: HTTP(s)</li>
            <li><strong>URL</strong>: Use <code>http://</code> or <code>https://</code> to match the integration's listener protocol (see <strong>Status</strong> tab for the exact URL)</li>
            <li><strong>Event Type</strong>: Zone Detections</li>
            <li><strong>Output Type</strong>: NDJSON</li>
          </ul>
        </li>
        <li>Configure any filters as needed (zones, protocols, etc.)</li>
        <li>Save the webhook</li>
      </ol>

      <h3>ADAM Finding Webhook</h3>
      <ol>
        <li>Log in to the Bastille command console</li>
        <li>Navigate to <strong>Settings &gt; Webhooks</strong></li>
        <li>Click <strong>Add Webhook</strong></li>
        <li>Configure the webhook:
          <ul>
            <li><strong>Name</strong>: Display Integration - ADAM Findings</li>
            <li><strong>Type</strong>: HTTP(s)</li>
            <li><strong>URL</strong>: Use <code>http://</code> or <code>https://</code> to match the integration's listener protocol (see <strong>Status</strong> tab for the exact URL)</li>
            <li><strong>Event Type</strong>: Findings</li>
            <li><strong>Output Type</strong>: NDJSON</li>
          </ul>
        </li>
        <li>Configure any filters or policy rules as needed</li>
        <li>Save the webhook</li>
      </ol>
      <div class="note">The port and paths shown above are defaults. If you changed them in the <strong>Configuration</strong> tab, use the values shown on the <strong>Status</strong> tab under <strong>Webhook Listener</strong>.</div>

      <h2>Display Message Templates</h2>
      <p>Templates control the text sent to the display. They use variables that are replaced with actual alert data:</p>

      <h3>Zone Detection Variables</h3>
      <ul>
        <li><code>{protocol}</code> &mdash; the wireless protocol (e.g., wifi, cellular, ble)</li>
        <li><code>{zone}</code> &mdash; the zone name where the device was detected</li>
        <li><code>{vendor}</code> &mdash; the device vendor/manufacturer</li>
        <li><code>{tags}</code> &mdash; comma-separated list of device tags</li>
      </ul>

      <h3>ADAM Finding Variables</h3>
      <p>All zone detection variables plus:</p>
      <ul>
        <li><code>{severity}</code> &mdash; the finding severity (CRITICAL, HIGH, MEDIUM, LOW)</li>
        <li><code>{reasons}</code> &mdash; comma-separated list of finding reasons (e.g., malicious_device_pineapple)</li>
      </ul>

      <h3>Examples</h3>
      <pre>Zone Detection: ALERT - {protocol} in {zone} - Vendor: {vendor} - ALERT
ADAM Finding:   ADAM ALERT - {severity} - {reasons} - {protocol} in {zone}</pre>

      <h2>Filtering</h2>
      <p>Alerts can be filtered in two ways:</p>
      <ul>
        <li><strong>Monitored Protocols</strong> &mdash; only alerts matching the selected protocols will trigger the display. Unmonitored protocols are logged as "filtered" in the Alerts tab.</li>
        <li><strong>Allowed Tags</strong> &mdash; devices tagged with any of the allowed tags (e.g., "authorized", "exclude") will not trigger alerts. These are also logged as "filtered".</li>
      </ul>

      <h2>Webhook Endpoints</h2>
      <ul>
        <li><code>POST /zone-detections</code> &mdash; receives Bastille zone detection webhooks (ndjson format)</li>
        <li><code>POST /adam-findings</code> &mdash; receives Bastille ADAM finding webhooks (json format)</li>
      </ul>
      <p>Both paths and the listener port are configurable in the <strong>Configuration</strong> tab.</p>

      <h2>HTTPS / SSL</h2>
      <p>The webhook listener can be configured to use HTTPS:</p>
      <ol>
        <li>In the <strong>Configuration</strong> tab, toggle the listener protocol to <strong>HTTPS</strong></li>
        <li>Upload an SSL certificate and private key using the file upload controls</li>
        <li>Save and restart the service</li>
      </ol>
      <p>When HTTPS is enabled, ensure the Bastille platform is configured to send webhooks to the <code>https://</code> URL and can trust the certificate (or has verification disabled).</p>

    </div>
  </div><!-- end tabDocs -->

</div>

<div class="toast" id="toast"></div>

<script>
const TONE_OPTIONS = __TONE_OPTIONS__;
let currentTags = [];
let currentVendor = 'Algo';

// Populate tone select
const toneSelect = document.getElementById('algo_tone_wav');
TONE_OPTIONS.forEach(t => {
  const opt = document.createElement('option');
  opt.value = t;
  opt.textContent = t.replace('.wav', '');
  toneSelect.appendChild(opt);
});

// Tone toggle visibility
document.getElementById('algo_tone').addEventListener('change', function() {
  document.getElementById('toneWavGroup').style.display = this.checked ? 'flex' : 'none';
});

// Vendor selection
function selectVendor(v) {
  currentVendor = v;
  document.querySelectorAll('.vendor-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.vendor === v);
  });
  document.getElementById('algoSection').classList.toggle('active', v === 'Algo');
  document.getElementById('freeportSection').classList.toggle('active', v === 'Freeport');
  const badge = document.getElementById('vendorBadge');
  badge.textContent = v;
  badge.className = 'badge ' + (v === 'Algo' ? 'badge-algo' : 'badge-freeport');
}

// Protocol management
const defaultProtocols = ['cellular', 'wifi', 'ble', 'bt', 'ieee_802_15_4'];
let allProtocols = [...defaultProtocols];
let enabledProtocols = [];

function renderProtocols() {
  const container = document.getElementById('protocols');
  container.innerHTML = '';
  allProtocols.forEach(proto => {
    const label = document.createElement('label');
    label.className = 'checkbox-pill';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.value = proto;
    cb.checked = enabledProtocols.includes(proto);
    cb.addEventListener('change', function() {
      if (this.checked) {
        if (!enabledProtocols.includes(proto)) enabledProtocols.push(proto);
      } else {
        enabledProtocols = enabledProtocols.filter(p => p !== proto);
      }
    });
    label.appendChild(cb);
    label.appendChild(document.createTextNode(' ' + proto));
    if (!defaultProtocols.includes(proto)) {
      const rm = document.createElement('button');
      rm.textContent = '\u00d7';
      rm.style.cssText = 'background:none;border:none;color:var(--text-muted);cursor:pointer;margin-left:0.3rem;font-size:0.9rem;';
      rm.onclick = function(e) {
        e.preventDefault();
        allProtocols = allProtocols.filter(p => p !== proto);
        enabledProtocols = enabledProtocols.filter(p => p !== proto);
        renderProtocols();
      };
      label.appendChild(rm);
    }
    container.appendChild(label);
  });
  populateTestProtocolSelects();
}

function addProtocol() {
  const input = document.getElementById('newProtoInput');
  const val = input.value.trim().toLowerCase();
  if (val && !allProtocols.includes(val)) {
    allProtocols.push(val);
    enabledProtocols.push(val);
    renderProtocols();
  }
  input.value = '';
}

document.getElementById('newProtoInput').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') { e.preventDefault(); addProtocol(); }
});

function populateTestProtocolSelects() {
  ['test_zd_protocol', 'test_adam_protocol'].forEach(id => {
    const sel = document.getElementById(id);
    const prev = sel.value;
    sel.innerHTML = '';
    allProtocols.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p;
      opt.textContent = p;
      sel.appendChild(opt);
    });
    if (prev && allProtocols.includes(prev)) sel.value = prev;
  });
}

// Tag management
function renderTags() {
  const wrap = document.getElementById('tagWrap');
  wrap.querySelectorAll('.tag').forEach(t => t.remove());
  const input = document.getElementById('tagInput');
  currentTags.forEach((tag, i) => {
    const el = document.createElement('span');
    el.className = 'tag';
    el.innerHTML = tag + ' <button onclick="removeTag(' + i + ')">&times;</button>';
    wrap.insertBefore(el, input);
  });
}

function removeTag(i) {
  currentTags.splice(i, 1);
  renderTags();
}

document.getElementById('tagInput').addEventListener('keydown', function(e) {
  if (e.key === 'Enter' && this.value.trim()) {
    e.preventDefault();
    const v = this.value.trim();
    if (!currentTags.includes(v)) {
      currentTags.push(v);
      renderTags();
    }
    this.value = '';
  }
  if (e.key === 'Backspace' && !this.value && currentTags.length) {
    currentTags.pop();
    renderTags();
  }
});

// Toast notification
function toast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast ' + type + ' show';
  setTimeout(() => el.classList.remove('show'), 3000);
}

// Load config from server
async function loadConfig() {
  try {
    const res = await fetch('/api/config');
    const cfg = await res.json();

    document.getElementById('log_file').value = cfg.log_file || '';
    document.getElementById('clear_time').value = cfg.clear_time || 60;
    document.getElementById('source_host').value = cfg.source_host || '0.0.0.0';
    document.getElementById('source_port').value = cfg.source_port || 8001;
    document.getElementById('source_path').value = cfg.source_path || '/zone-detections';
    document.getElementById('adam_path').value = cfg.adam_path || '/adam-findings';

    // SSL
    selectProto(cfg.source_ssl ? 'https' : 'http');

    // Message templates
    document.getElementById('zone_detection_template').value = cfg.zone_detection_template || 'ALERT - {protocol} in {zone} - Vendor: {vendor} - ALERT';
    document.getElementById('adam_finding_template').value = cfg.adam_finding_template || 'ADAM ALERT - {severity} - {reasons} - {protocol} in {zone} - Vendor: {vendor}';

    // Protocols
    const protos = cfg.monitored_protocols || [];
    allProtocols = [...new Set([...defaultProtocols, ...protos])];
    enabledProtocols = [...protos];
    renderProtocols();

    // Tags
    currentTags = cfg.allowed_tags || [];
    renderTags();

    // Vendor
    selectVendor(cfg.vendor || 'Algo');

    // Algo fields
    document.getElementById('algo_target_host').value = cfg.target_host || '';
    document.getElementById('algo_username').value = cfg.auth_username || '';
    document.getElementById('algo_password').value = cfg.auth_password || '';
    document.getElementById('algo_text_color').value = cfg.algo_text_color || cfg.text_color || 'orange';
    document.getElementById('algo_text_font').value = cfg.algo_text_font || 'roboto';
    document.getElementById('algo_text_size').value = cfg.algo_text_size || 'medium';
    document.getElementById('algo_text_position').value = cfg.algo_text_position || 'middle';
    document.getElementById('algo_text_scroll').value = String(cfg.algo_text_scroll != null ? cfg.algo_text_scroll : '1');
    document.getElementById('algo_text_scroll_speed').value = String(cfg.algo_text_scroll_speed || '4');
    document.getElementById('algo_strobe_pattern').value = String(cfg.strobe_pattern || 2);
    document.getElementById('algo_strobe_color').value = cfg.strobe_color || 'red';
    document.getElementById('algo_tone').checked = cfg.tone === true || cfg.tone === 'True';
    document.getElementById('algo_tone_wav').value = cfg.tone_wav || 'bell-na.wav';
    document.getElementById('toneWavGroup').style.display =
      document.getElementById('algo_tone').checked ? 'flex' : 'none';

    // Freeport fields
    document.getElementById('freeport_target_host').value = cfg.target_host || '';
    document.getElementById('freeport_target_port').value = cfg.target_port || 2311;
    document.getElementById('freeport_username').value = cfg.auth_username || '';
    document.getElementById('freeport_password').value = cfg.auth_password || '';
    document.getElementById('freeport_detail_font_size').value = cfg.freeport_detail_font_size || 160;

  } catch (e) {
    toast('Failed to load configuration', 'error');
  }
}

// Save config to server
async function saveConfig() {
  const cfg = {
    log_file: document.getElementById('log_file').value,
    source_host: document.getElementById('source_host').value,
    source_path: document.getElementById('source_path').value,
    adam_path: document.getElementById('adam_path').value,
    source_port: parseInt(document.getElementById('source_port').value),
    clear_time: parseInt(document.getElementById('clear_time').value),
    monitored_protocols: enabledProtocols,
    allowed_tags: currentTags,
    vendor: currentVendor,
    zone_detection_template: document.getElementById('zone_detection_template').value,
    adam_finding_template: document.getElementById('adam_finding_template').value,
    source_ssl: currentProto === 'https',
    source_ssl_cert: 'certs/integration_cert.pem',
    source_ssl_key: 'certs/integration_key.pem',
  };

  if (currentVendor === 'Algo') {
    cfg.target_host = document.getElementById('algo_target_host').value;
    cfg.auth_username = document.getElementById('algo_username').value;
    cfg.auth_password = document.getElementById('algo_password').value;
    cfg.text_color = document.getElementById('algo_text_color').value;
    cfg.algo_text_color = document.getElementById('algo_text_color').value;
    cfg.algo_text_font = document.getElementById('algo_text_font').value;
    cfg.algo_text_size = document.getElementById('algo_text_size').value;
    cfg.algo_text_position = document.getElementById('algo_text_position').value;
    cfg.algo_text_scroll = document.getElementById('algo_text_scroll').value;
    cfg.algo_text_scroll_speed = document.getElementById('algo_text_scroll_speed').value;
    cfg.strobe_pattern = parseInt(document.getElementById('algo_strobe_pattern').value);
    cfg.strobe_color = document.getElementById('algo_strobe_color').value;
    cfg.tone = document.getElementById('algo_tone').checked;
    cfg.tone_wav = document.getElementById('algo_tone_wav').value;
  } else {
    cfg.target_host = document.getElementById('freeport_target_host').value;
    cfg.target_port = parseInt(document.getElementById('freeport_target_port').value);
    cfg.auth_username = document.getElementById('freeport_username').value;
    cfg.auth_password = document.getElementById('freeport_password').value;
    cfg.freeport_detail_font_size = parseInt(document.getElementById('freeport_detail_font_size').value) || 160;
  }

  try {
    const res = await fetch('/api/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg)
    });
    if (res.ok) {
      toast('Configuration saved. Restart the integration service to apply changes.', 'success');
    } else {
      toast('Failed to save configuration', 'error');
    }
  } catch (e) {
    toast('Failed to save configuration', 'error');
  }
}

// SSL protocol selection
let currentProto = 'http';
function selectProto(p) {
  currentProto = p;
  document.querySelectorAll('[data-proto]').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.proto === p);
  });
  document.getElementById('sslFields').classList.toggle('hidden', p === 'http');
  document.getElementById('protoLabel').textContent = p.toUpperCase();
  if (p === 'https') checkCertStatus();
}

// File name display
document.getElementById('certFile').addEventListener('change', function() {
  document.getElementById('certFileName').textContent = this.files[0]?.name || 'No file chosen';
});
document.getElementById('keyFile').addEventListener('change', function() {
  document.getElementById('keyFileName').textContent = this.files[0]?.name || 'No file chosen';
});

// Upload cert and key
async function uploadCert() {
  const certFile = document.getElementById('certFile').files[0];
  const keyFile = document.getElementById('keyFile').files[0];
  if (!certFile || !keyFile) {
    toast('Please select both a certificate and key file.', 'error');
    return;
  }
  const formData = new FormData();
  formData.append('cert', certFile);
  formData.append('key', keyFile);
  try {
    const res = await fetch('/api/upload-cert', { method: 'POST', body: formData });
    if (res.ok) {
      toast('Certificate and key uploaded.', 'success');
      checkCertStatus();
    } else {
      toast('Failed to upload certificate.', 'error');
    }
  } catch (e) {
    toast('Failed to upload certificate.', 'error');
  }
}

// Check cert status
async function checkCertStatus() {
  try {
    const res = await fetch('/api/cert-status');
    const data = await res.json();
    const el = document.getElementById('certStatus');
    if (data.cert_exists && data.key_exists) {
      el.textContent = 'Certificate and key found';
      el.className = 'cert-status found';
    } else {
      el.textContent = 'Certificate or key missing - upload required';
      el.className = 'cert-status missing';
    }
  } catch (e) {}
}

// Save config and restart the integration service
async function saveAndRestart() {
  const btn = document.getElementById('restartBtn');
  btn.disabled = true;
  btn.textContent = 'Saving...';

  // Save first
  await saveConfig();

  btn.textContent = 'Restarting...';
  try {
    const res = await fetch('/api/restart', { method: 'POST' });
    if (res.ok) {
      toast('Configuration saved and service restarting.', 'success');
    } else {
      const data = await res.json();
      toast('Restart failed: ' + (data.detail || 'unknown error'), 'error');
    }
  } catch (e) {
    toast('Restart failed: could not reach server (service may be restarting)', 'success');
  }
  btn.disabled = false;
  btn.textContent = 'Save & Restart Service';
}

// Test type selection
let currentTestType = null;
function selectTestType(t) {
  currentTestType = t;
  document.querySelectorAll('.test-type-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.test === t);
  });
  document.getElementById('testZoneFields').classList.toggle('active', t === 'zone_detection');
  document.getElementById('testAdamFields').classList.toggle('active', t === 'adam_finding');
  document.getElementById('testResult').classList.remove('show');
}

// Build and send test payloads
function buildZoneDetectionPayload() {
  const now = Math.floor(Date.now() / 1000);
  return {
    payload: {
      emitter: {
        transmitter_id: document.getElementById('test_zd_transmitter').value,
        protocol: document.getElementById('test_zd_protocol').value,
        vendor: document.getElementById('test_zd_vendor').value,
      },
      device_info: {
        manufacturer: document.getElementById('test_zd_manufacturer').value,
      },
      zone_name: document.getElementById('test_zd_zone').value,
      tags: document.getElementById('test_zd_tags').value.split(',').map(s => s.trim()).filter(Boolean),
      time_s: now,
    }
  };
}

function buildAdamFindingPayload() {
  const now = Math.floor(Date.now() / 1000);
  const tags = document.getElementById('test_adam_tags').value.split(',').map(s => s.trim()).filter(Boolean);
  const reason = document.getElementById('test_adam_reason').value.trim();
  return {
    id: 'test-' + now,
    event_type: 'findings',
    payload: {
      status: 'new',
      detected_at: now,
      reasons: reason ? reason.split(',').map(s => s.trim()) : [],
      severity: document.getElementById('test_adam_severity').value,
      severity_score: parseInt(document.getElementById('test_adam_score').value),
      finding_id: 'test-' + now,
      published_at: now,
      area: { site_id: 'test_site', concentrator_id: 'test', map_id: 'test' },
      area_id: 'test_site-test-test',
      reference_snapshot: {
        emitter: {
          transmitter_id: document.getElementById('test_adam_transmitter').value,
          protocol: document.getElementById('test_adam_protocol').value,
          vendor: document.getElementById('test_adam_vendor').value,
          network: { name: document.getElementById('test_adam_network').value },
        },
        tags: tags,
        time_s: now,
        device_info: { manufacturer: '', user: '', model: '', name: '' },
      },
      reason_details: {},
    },
    webhook_name: document.getElementById('test_adam_webhook_name').value,
    filter_name: 'Test',
  };
}

async function sendTest(type) {
  const resultEl = document.getElementById('testResult');
  resultEl.classList.remove('show', 'ok', 'fail');

  let payload;
  if (type === 'zone_detection') {
    payload = buildZoneDetectionPayload();
  } else {
    payload = buildAdamFindingPayload();
  }

  try {
    const res = await fetch('/api/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ test_type: type, payload: payload })
    });
    const data = await res.json();
    if (res.ok && data.status === 'ok') {
      resultEl.textContent = 'Test sent successfully (HTTP ' + data.code + ')';
      resultEl.className = 'test-result show ok';
    } else {
      resultEl.textContent = 'Test failed: ' + (data.detail || 'HTTP ' + data.code);
      resultEl.className = 'test-result show fail';
    }
  } catch (e) {
    resultEl.textContent = 'Test failed: ' + e.message;
    resultEl.className = 'test-result show fail';
  }
}

// Status dashboard
function setServiceStatus(dotId, textId, detailId, info) {
  const dot = document.getElementById(dotId);
  const text = document.getElementById(textId);
  const detail = document.getElementById(detailId);
  const state = info.ActiveState;
  const sub = info.SubState;

  if (state === 'active') {
    dot.className = 'status-dot active';
    text.textContent = 'Running';
    text.style.color = 'var(--success)';
  } else if (state === 'inactive' || state === 'failed') {
    dot.className = 'status-dot inactive';
    text.textContent = state === 'failed' ? 'Failed' : 'Stopped';
    text.style.color = 'var(--danger)';
  } else {
    dot.className = 'status-dot unknown';
    text.textContent = state || 'Unknown';
    text.style.color = 'var(--text-muted)';
  }

  let details = sub ? 'State: ' + sub : '';
  if (info.MainPID && info.MainPID !== '0') details += ' | PID: ' + info.MainPID;
  if (info.ActiveEnterTimestamp && info.ActiveEnterTimestamp !== '') details += ' | Since: ' + info.ActiveEnterTimestamp;
  detail.textContent = details;
}

function renderConfigSummary(s) {
  const el = document.getElementById('configSummary');
  function fmt(v) {
    if (typeof v === 'boolean') return v ? 'Enabled' : 'Disabled';
    if (Array.isArray(v)) return v.length ? v.join(', ') : 'None';
    return v != null ? v : 'N/A';
  }
  function row(key, val) {
    return '<div class="config-summary-item"><span class="key">' + key + '</span><span class="val">' + fmt(val) + '</span></div>';
  }
  function section(title, rows, full) {
    return '<div class="config-summary-section' + (full ? ' full' : '') + '">' +
      '<div class="config-summary-section-title">' + title + '</div>' + rows + '</div>';
  }

  el.innerHTML =
    section('Webhook Listener',
      row('Protocol', s.listener_protocol) +
      row('Host', s.source_host) +
      row('Port', s.source_port) +
      row('Zone Detections URL', (s.source_ssl ? 'https' : 'http') + '://' + (s.source_host === '0.0.0.0' ? s.host_ip : s.source_host) + ':' + s.source_port + s.source_path) +
      row('ADAM Findings URL', (s.source_ssl ? 'https' : 'http') + '://' + (s.source_host === '0.0.0.0' ? s.host_ip : s.source_host) + ':' + s.source_port + s.adam_path)
    ) +
    section('Display Target',
      row('Vendor', s.vendor) +
      row('Host', s.target_host) +
      row('Port', s.target_port) +
      row('Clear Time', s.clear_time + 's') +
      (s.vendor === 'Algo' ?
        row('Strobe', s.strobe_color + ' / pattern ' + s.strobe_pattern) +
        row('Tone', s.tone ? s.tone_wav : 'Disabled')
        : '')
    ) +
    section('Filtering',
      row('Protocols', s.monitored_protocols) +
      row('Allowed Tags', s.allowed_tags),
      true
    );
}

async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    document.getElementById('statusVersion').textContent = data.version || '-';
    setServiceStatus('intStatusDot', 'intStatusText', 'intStatusDetail', data.services.integration);
    setServiceStatus('uiStatusDot', 'uiStatusText', 'uiStatusDetail', data.services.config_ui);
    // Display target health
    const th = data.target_health || {};
    const tDot = document.getElementById('targetStatusDot');
    const tText = document.getElementById('targetStatusText');
    const tDetail = document.getElementById('targetStatusDetail');
    if (th.reachable) {
      tDot.className = 'status-dot active';
      tText.textContent = 'Reachable';
      tText.style.color = 'var(--success)';
    } else {
      tDot.className = 'status-dot inactive';
      tText.textContent = 'Unreachable';
      tText.style.color = 'var(--danger)';
    }
    tDetail.textContent = th.detail || '';
    renderConfigSummary(data.config_summary);
  } catch (e) {
    document.getElementById('intStatusText').textContent = 'Error';
    document.getElementById('uiStatusText').textContent = 'Error';
  }
}

// User management
async function loadUsers() {
  try {
    const res = await fetch('/api/users');
    const users = await res.json();
    const el = document.getElementById('userTable');
    if (!users.length) {
      el.innerHTML = '<p style="font-size: 0.85rem; color: var(--text-muted);">No users configured.</p>';
      return;
    }
    let html = '<table class="user-table"><thead><tr><th>Username</th><th>Actions</th></tr></thead><tbody>';
    users.forEach(u => {
      html += '<tr><td>' + u.username + '</td><td><div class="user-actions">' +
        '<button onclick="changePassword(\'' + u.username + '\')">Change Password</button>' +
        '<button class="delete" onclick="deleteUser(\'' + u.username + '\')">Delete</button>' +
        '</div></td></tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;
  } catch (e) {}
}

async function addUser() {
  const username = document.getElementById('new_user_name').value.trim();
  const password = document.getElementById('new_user_pass').value.trim();
  if (!username || !password) { toast('Username and password required.', 'error'); return; }
  try {
    const res = await fetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (res.ok) {
      toast('User "' + username + '" added.', 'success');
      document.getElementById('new_user_name').value = '';
      document.getElementById('new_user_pass').value = '';
      loadUsers();
    } else {
      toast(data.detail || 'Failed to add user.', 'error');
    }
  } catch (e) { toast('Failed to add user.', 'error'); }
}

async function changePassword(username) {
  const newPass = prompt('Enter new password for "' + username + '":');
  if (!newPass) return;
  try {
    const res = await fetch('/api/users/password', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, new_password: newPass })
    });
    const data = await res.json();
    if (res.ok) {
      toast('Password changed for "' + username + '". You may need to re-authenticate.', 'success');
    } else {
      toast(data.detail || 'Failed to change password.', 'error');
    }
  } catch (e) { toast('Failed to change password.', 'error'); }
}

async function deleteUser(username) {
  if (!confirm('Delete user "' + username + '"?')) return;
  try {
    const res = await fetch('/api/users', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    const data = await res.json();
    if (res.ok) {
      toast('User "' + username + '" deleted.', 'success');
      loadUsers();
    } else {
      toast(data.detail || 'Failed to delete user.', 'error');
    }
  } catch (e) { toast('Failed to delete user.', 'error'); }
}

// Export config
function exportConfig() {
  window.location.href = '/api/config/export';
}

// Restore config from file
async function restoreConfig() {
  const file = document.getElementById('restoreFile').files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append('file', file);
  try {
    const res = await fetch('/api/config/restore', { method: 'POST', body: formData });
    const data = await res.json();
    if (res.ok) {
      toast('Configuration restored. Current config backed up to config.yaml.bak', 'success');
      loadConfig();
      loadStatus();
    } else {
      toast('Restore failed: ' + (data.detail || 'unknown error'), 'error');
    }
  } catch (e) {
    toast('Restore failed: ' + e.message, 'error');
  }
  document.getElementById('restoreFile').value = '';
}

// JSON syntax highlighting
function syntaxHighlight(json) {
  const str = JSON.stringify(json, null, 2);
  return str.replace(/("(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function(match) {
    let cls = 'json-number';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'json-key';
      } else {
        cls = 'json-string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'json-bool';
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
}

// Preview display commands
async function previewCommands(type) {
  let payload;
  if (type === 'zone_detection') {
    payload = buildZoneDetectionPayload();
  } else {
    payload = buildAdamFindingPayload();
  }

  const preview = document.getElementById('commandPreview');
  preview.classList.remove('show');

  try {
    const res = await fetch('/api/preview-commands', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ test_type: type, payload: payload })
    });
    const data = await res.json();

    let html = '<div style="margin-top: 0.75rem; margin-bottom: 0.5rem; font-size: 0.8rem; color: var(--text-muted);">Vendor: <strong style="color: var(--text);">' + data.vendor + '</strong></div>';

    data.commands.forEach(cmd => {
      html += '<div class="command-card">';
      html += '<div class="command-card-header">';
      html += '<span class="command-action">' + cmd.action + '</span>';
      html += '<span class="command-endpoint">' + cmd.endpoint + '</span>';
      html += '</div>';
      if (Array.isArray(cmd.payload)) {
        html += '<div class="command-json">' + cmd.payload.map(l => l).join('\n') + '</div>';
      } else {
        html += '<div class="command-json">' + syntaxHighlight(cmd.payload) + '</div>';
      }
      html += '</div>';
    });

    preview.innerHTML = html;
    preview.classList.add('show');
  } catch (e) {
    preview.innerHTML = '<div class="test-result show fail">Failed to preview: ' + e.message + '</div>';
    preview.classList.add('show');
  }
}

// Clear display target
async function clearDisplay() {
  try {
    const res = await fetch('/api/clear-display', { method: 'POST' });
    if (res.ok) {
      toast('Clear command sent to display.', 'success');
    } else {
      const data = await res.json();
      toast('Failed to clear display: ' + (data.detail || 'unknown error'), 'error');
    }
  } catch (e) {
    toast('Failed to clear display: ' + e.message, 'error');
  }
}

// Tab switching
function switchTab(tab) {
  const tabMap = { status: 'tabStatus', config: 'tabConfig', testing: 'tabTesting', alerts: 'tabAlerts', docs: 'tabDocs' };
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
  document.querySelector('[onclick="switchTab(\'' + tab + '\')"]').classList.add('active');
  document.getElementById(tabMap[tab]).classList.add('active');
  if (tab === 'status') loadStatus();
  if (tab === 'alerts') loadAlerts();
}

// Alerts
function formatTimestamp(iso) {
  const d = new Date(iso);
  return d.toLocaleString();
}

function severityClass(s) {
  if (!s) return '';
  return 'severity-badge severity-' + s.toLowerCase();
}

function statusBadge(s) {
  if (s === 'sent') return '<span class="status-badge status-sent">Sent</span>';
  if (s && s.startsWith('filtered')) return '<span class="status-badge status-filtered">Filtered</span>';
  return '<span class="status-badge">' + (s || '') + '</span>';
}

function typeBadge(t) {
  if (t === 'zone_detection') return '<span class="type-badge type-zone">Zone Detection</span>';
  if (t === 'adam_finding') return '<span class="type-badge type-adam">ADAM Finding</span>';
  return t || '';
}

async function loadAlerts() {
  try {
    const res = await fetch('/api/alerts');
    const alerts = await res.json();
    const container = document.getElementById('alertsContainer');
    document.getElementById('alertCount').textContent = alerts.length + ' alert' + (alerts.length !== 1 ? 's' : '');

    if (alerts.length === 0) {
      container.innerHTML = '<div class="alert-empty">No alerts recorded yet.</div>';
      return;
    }

    let html = '<table class="alert-table"><thead><tr>' +
      '<th>Time</th><th>Type</th><th>Protocol</th><th>Zone</th><th>Vendor</th><th>Severity</th><th>Status</th>' +
      '</tr></thead><tbody>';
    alerts.forEach(a => {
      html += '<tr>' +
        '<td>' + formatTimestamp(a.timestamp) + '</td>' +
        '<td>' + typeBadge(a.type) + '</td>' +
        '<td>' + (a.protocol || '-') + '</td>' +
        '<td>' + (a.zone || '-') + '</td>' +
        '<td>' + (a.vendor || '-') + '</td>' +
        '<td>' + (a.severity ? '<span class="' + severityClass(a.severity) + '">' + a.severity + '</span>' : '-') + '</td>' +
        '<td>' + statusBadge(a.status) + '</td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    container.innerHTML = html;
  } catch (e) {
    document.getElementById('alertsContainer').innerHTML = '<div class="alert-empty">Failed to load alerts.</div>';
  }
}

async function clearAlerts() {
  try {
    await fetch('/api/alerts', { method: 'DELETE' });
    loadAlerts();
    toast('Alerts cleared.', 'success');
  } catch (e) {
    toast('Failed to clear alerts.', 'error');
  }
}

// Initial load
loadConfig();
loadStatus();
loadUsers();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    generate_self_signed_cert()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=UI_PORT,
        ssl_keyfile=KEY_FILE,
        ssl_certfile=CERT_FILE,
    )
