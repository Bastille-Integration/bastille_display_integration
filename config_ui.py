from fastapi import FastAPI, Request, Depends, HTTPException, status, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
import yaml
import os
import subprocess
import logging
import uvicorn

INTEGRATION_CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yaml")
CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
CERT_FILE = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE = os.path.join(CERT_DIR, "key.pem")
UI_PORT = 8443

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

# UI credentials from config, default to bn/bn
_cfg = yaml.safe_load(open(CONFIG_PATH, "r"))
UI_USERNAME = _cfg.get("ui_username", "bn")
UI_PASSWORD = _cfg.get("ui_password", "bn")


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    username_correct = secrets.compare_digest(credentials.username, UI_USERNAME)
    password_correct = secrets.compare_digest(credentials.password, UI_PASSWORD)
    if not (username_correct and password_correct):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials


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


@app.get("/api/config", response_class=JSONResponse)
async def get_config(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    return load_config()


@app.put("/api/config", response_class=JSONResponse)
async def put_config(request: Request, credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    body = await request.json()
    save_config(body)
    logger.info("Configuration saved.")
    return {"status": "ok"}


@app.post("/api/restart", response_class=JSONResponse)
async def restart_service(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "restart", "bastille_display_integration.service"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            logger.info("Integration service restarted.")
            return {"status": "ok"}
        else:
            logger.error("Failed to restart service: %s", result.stderr)
            return JSONResponse(status_code=500, content={"status": "error", "detail": result.stderr.strip()})
    except subprocess.TimeoutExpired:
        logger.error("Restart command timed out.")
        return JSONResponse(status_code=500, content={"status": "error", "detail": "Restart command timed out"})


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


@app.get("/", response_class=HTMLResponse)
async def config_page(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    config = load_config()
    tone_options_json = str(TONE_OPTIONS).replace("'", '"')
    return HTML_PAGE.replace("__TONE_OPTIONS__", tone_options_json)


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
    <h1><span>Bastille</span> Display Integration</h1>
    <span class="badge" id="vendorBadge">-</span>
  </header>

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
        <input type="text" id="log_file">
      </div>
      <div class="form-group">
        <label>Clear Time (seconds)</label>
        <input type="number" id="clear_time" min="1">
      </div>
      <div class="form-group">
        <label>Listener Host</label>
        <input type="text" id="source_host">
      </div>
      <div class="form-group">
        <label>Listener Port</label>
        <input type="number" id="source_port" min="1" max="65535">
      </div>
      <div class="form-group">
        <label>Zone Detections Path</label>
        <input type="text" id="source_path">
      </div>
      <div class="form-group">
        <label>ADAM Findings Path</label>
        <input type="text" id="adam_path">
      </div>
    </div>
  </div>

  <!-- Listener SSL/TLS -->
  <div class="card">
    <div class="card-title">Webhook Listener Protocol</div>
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
    <div class="checkbox-group" id="protocols">
      <label class="checkbox-pill"><input type="checkbox" value="cellular"> Cellular</label>
      <label class="checkbox-pill"><input type="checkbox" value="wifi"> Wi-Fi</label>
      <label class="checkbox-pill"><input type="checkbox" value="ble"> BLE</label>
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
          <input type="text" id="algo_target_host" placeholder="http://172.30.2.119">
        </div>
        <div class="form-group">
          <label>Target Port</label>
          <input type="number" id="algo_target_port" min="1" max="65535">
        </div>
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="algo_username">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="algo_password">
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
          <label>Strobe Pattern</label>
          <select id="algo_strobe_pattern">
            <option value="1">1 - Slow</option>
            <option value="2">2 - Medium</option>
            <option value="3">3 - Fast</option>
            <option value="4">4 - Pulse</option>
          </select>
        </div>
        <div class="form-group full">
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
          <input type="text" id="freeport_target_host" placeholder="10.35.44.51">
        </div>
        <div class="form-group">
          <label>Target Port</label>
          <input type="number" id="freeport_target_port" min="1" max="65535">
        </div>
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="freeport_username">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="freeport_password">
        </div>
      </div>
    </div>
  </div>

  <div class="actions">
    <button class="btn btn-secondary" onclick="loadConfig()">Discard Changes</button>
    <button class="btn btn-primary" onclick="saveConfig()">Save Configuration</button>
    <button class="btn btn-warning" id="restartBtn" onclick="saveAndRestart()">Save &amp; Restart Service</button>
  </div>
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

    // Protocols
    const protos = cfg.monitored_protocols || [];
    document.querySelectorAll('#protocols input').forEach(cb => {
      cb.checked = protos.includes(cb.value);
    });

    // Tags
    currentTags = cfg.allowed_tags || [];
    renderTags();

    // Vendor
    selectVendor(cfg.vendor || 'Algo');

    // Algo fields
    document.getElementById('algo_target_host').value = cfg.target_host || '';
    document.getElementById('algo_target_port').value = cfg.target_port || 80;
    document.getElementById('algo_username').value = cfg.auth_username || '';
    document.getElementById('algo_password').value = cfg.auth_password || '';
    document.getElementById('algo_text_color').value = cfg.text_color || 'red';
    document.getElementById('algo_strobe_pattern').value = String(cfg.strobe_pattern || 2);
    document.getElementById('algo_strobe_color').value = cfg.strobe_color || 'red';
    document.getElementById('algo_tone').checked = cfg.tone === true || cfg.tone === 'True';
    document.getElementById('algo_tone_wav').value = cfg.tone_wav || 'bell-na.wav';
    document.getElementById('toneWavGroup').style.display =
      document.getElementById('algo_tone').checked ? 'flex' : 'none';

    // Freeport fields
    document.getElementById('freeport_target_host').value = cfg.target_host || '';
    document.getElementById('freeport_target_port').value = cfg.target_port || 80;
    document.getElementById('freeport_username').value = cfg.auth_username || '';
    document.getElementById('freeport_password').value = cfg.auth_password || '';

  } catch (e) {
    toast('Failed to load configuration', 'error');
  }
}

// Save config to server
async function saveConfig() {
  const protocols = [];
  document.querySelectorAll('#protocols input:checked').forEach(cb => protocols.push(cb.value));

  const cfg = {
    log_file: document.getElementById('log_file').value,
    source_host: document.getElementById('source_host').value,
    source_path: document.getElementById('source_path').value,
    adam_path: document.getElementById('adam_path').value,
    source_port: parseInt(document.getElementById('source_port').value),
    clear_time: parseInt(document.getElementById('clear_time').value),
    monitored_protocols: protocols,
    allowed_tags: currentTags,
    vendor: currentVendor,
    source_ssl: currentProto === 'https',
    source_ssl_cert: 'certs/integration_cert.pem',
    source_ssl_key: 'certs/integration_key.pem',
  };

  if (currentVendor === 'Algo') {
    cfg.target_host = document.getElementById('algo_target_host').value;
    cfg.target_port = parseInt(document.getElementById('algo_target_port').value);
    cfg.auth_username = document.getElementById('algo_username').value;
    cfg.auth_password = document.getElementById('algo_password').value;
    cfg.text_color = document.getElementById('algo_text_color').value;
    cfg.strobe_pattern = parseInt(document.getElementById('algo_strobe_pattern').value);
    cfg.strobe_color = document.getElementById('algo_strobe_color').value;
    cfg.tone = document.getElementById('algo_tone').checked;
    cfg.tone_wav = document.getElementById('algo_tone_wav').value;
  } else {
    cfg.target_host = document.getElementById('freeport_target_host').value;
    cfg.target_port = parseInt(document.getElementById('freeport_target_port').value);
    cfg.auth_username = document.getElementById('freeport_username').value;
    cfg.auth_password = document.getElementById('freeport_password').value;
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

// Initial load
loadConfig();
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
