from fastapi import FastAPI, HTTPException, Request, BackgroundTasks  # Import Request and BackgroundTasks
import yaml
import logging
import asyncio
import json
import os
from datetime import datetime, timezone
from ndjson_to_json import NDJson
from bastille_webhook_parser import BastilleWebhookParser
from adam_webhook_parser import AdamWebhookParser
from algo import Algo
from freeport import Freeport

reset_task=None

# Read configuration values from the YAML file
with open("config.yaml", "r") as config_file:
    config = yaml.safe_load(config_file)

# Extract configuration values
vendor = config["vendor"]
log_file = config["log_file"]
source_host = config["source_host"]
source_path = config["source_path"]
adam_path = config["adam_path"]
source_port = config["source_port"]
source_ssl = config.get("source_ssl", False)
source_ssl_cert = config.get("source_ssl_cert")
source_ssl_key = config.get("source_ssl_key")
target_host = config["target_host"]
target_port = config["target_port"]
auth_username = config["auth_username"]
auth_password = config["auth_password"]
clear_time = config["clear_time"]
monitored_protocols = config["monitored_protocols"]
allowed_tags = config["allowed_tags"]

# Algo-specific configuration
strobe_pattern = config.get("strobe_pattern")
strobe_color = config.get("strobe_color")
tone = config.get("tone", False)
tone_wav = config.get("tone_wav")

# Configure logging
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("Main")

app = FastAPI()
# Create Algo or Freeport object
if vendor == "Algo":
    a = Algo(host=target_host, username=auth_username, password=auth_password, log_file=log_file)
if vendor == "Freeport":
    f = Freeport(host=target_host, port= target_port, username=auth_username, password=auth_password, log_file=log_file)

ALERTS_FILE = os.path.join(os.path.dirname(__file__), "alerts.json")
MAX_ALERTS = 500

def save_alert(alert_type, protocol, zone, vendor_name, severity=None, reasons=None, tags=None, status="sent"):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": alert_type,
        "protocol": protocol,
        "zone": zone,
        "vendor": vendor_name,
        "severity": severity,
        "reasons": reasons,
        "tags": tags,
        "status": status,
        "display_vendor": vendor,
    }
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, "r") as af:
                alerts = json.load(af)
        else:
            alerts = []
        alerts.insert(0, alert)
        alerts = alerts[:MAX_ALERTS]
        with open(ALERTS_FILE, "w") as af:
            json.dump(alerts, af)
    except Exception as e:
        logger.error(f"Failed to save alert: {e}")

def create_alert(body):
    #Covert NDjson to json
    payload = NDJson(log_file=log_file)
    #Review each json line individually
    for i in payload.ndjson_to_json(body):
        #Parse Bastille webhook
        i = BastilleWebhookParser(i)
        protocol = i.parse("protocol")
        zone = i.parse("zone")
        manufacturer = i.parse("vendor")
        tags = i.parse("tags")
        #Prepare and send Algo text
        if protocol not in monitored_protocols:
            logger.info(f'Not sending alert due to unknown protocol {protocol}.')
            save_alert("zone_detection", protocol, zone, manufacturer, tags=tags, status="filtered_protocol")
        elif any(i in tags for i in allowed_tags):
            logger.info(f'Not sending alert due to known tags {tags}')
            save_alert("zone_detection", protocol, zone, manufacturer, tags=tags, status="filtered_tag")
        else:
            save_alert("zone_detection", protocol, zone, manufacturer, tags=tags)
            target_payload = {
                "type": "image",
                "text1": f"ALERT - {protocol} in {zone} - Vendor: {manufacturer} - ALERT",
                "textColor": "orange",
                "textFont": "roboto",
                "textPosition": "middle",
                "textScroll": "1",
                "textScrollSpeed": "4",
                "textSize": "medium"
            }
        if vendor == "Algo":
            logger.info(f'Sending alert to Algo')
            a.alert_screen(target_payload)
            # Algo strobe
            strobe_on_payload = {
                "pattern": strobe_pattern,
                "color1": strobe_color
            }
            a.strobe_on(strobe_on_payload)
            # Tone
            if tone:
                tone_payload = {
                    "path": tone_wav,
                    "loop": "false"
                }
                a.tone(tone_payload=tone_payload)
        if vendor == "Freeport":
            logger.info(f'Sending alert to Freeport')
            f.screen_change(option="alert", protocol=protocol, device=manufacturer, zone=zone)

def create_adam_alert(body):
    parsed = AdamWebhookParser(body)
    protocol = parsed.parse("protocol")
    zone = parsed.parse("zone")
    manufacturer = parsed.parse("vendor")
    severity = parsed.parse("severity")
    reasons = parsed.parse("reasons")
    tags = parsed.parse("tags")

    if protocol and protocol not in monitored_protocols:
        logger.info(f'ADAM: Not sending alert due to unmonitored protocol {protocol}.')
        save_alert("adam_finding", protocol, zone, manufacturer, severity=severity, reasons=reasons, tags=tags, status="filtered_protocol")
        return
    if any(i in tags for i in allowed_tags):
        logger.info(f'ADAM: Not sending alert due to known tags {tags}')
        save_alert("adam_finding", protocol, zone, manufacturer, severity=severity, reasons=reasons, tags=tags, status="filtered_tag")
        return

    save_alert("adam_finding", protocol, zone, manufacturer, severity=severity, reasons=reasons, tags=tags)
    reason_text = ", ".join(reasons) if reasons else "unknown"
    alert_text = f"ADAM ALERT - {severity.upper() if severity else 'UNKNOWN'} - {reason_text} - {protocol} in {zone} - Vendor: {manufacturer}"

    target_payload = {
        "type": "image",
        "text1": alert_text,
        "textColor": "red" if severity in ("high", "critical") else "orange",
        "textFont": "roboto",
        "textPosition": "middle",
        "textScroll": "1",
        "textScrollSpeed": "4",
        "textSize": "medium"
    }
    if vendor == "Algo":
        logger.info(f'Sending ADAM alert to Algo')
        a.alert_screen(target_payload)
        strobe_on_payload = {
            "pattern": strobe_pattern,
            "color1": strobe_color
        }
        a.strobe_on(strobe_on_payload)
        if tone:
            tone_payload = {
                "path": tone_wav,
                "loop": "false"
            }
            a.tone(tone_payload=tone_payload)
    if vendor == "Freeport":
        logger.info(f'Sending ADAM alert to Freeport')
        f.screen_change(option="alert", protocol=protocol, device=manufacturer, zone=zone)

async def turn_off_alert():
    await asyncio.sleep(clear_time)  # Sleep for X seconds
    global new_query_made
    if not new_query_made:
        # Algo clear text
        clear_target_payload = {
            "type": "image",
            "text1": "CLEAR",
            "textColor": "green",
            "textFont": "roboto",
            "textPosition": "middle",
            "textScroll": "0",
            "textScrollSpeed": "4",
            "textSize": "medium"
        }
        if vendor == "Algo":
            a.alert_clear(clear_target_payload)
            # Algo strobe off
            a.strobe_off()
        if vendor == "Freeport":
            f.screen_change(option="clear")

async def reset_new_query_flag():
    global new_query_made

    # Sleep for X seconds - reduce by 1 to ensure new_query_made turns false before CLEAR starts
    await asyncio.sleep(clear_time-1)

    #Turning False will allow CLEAR to run
    new_query_made = False

@app.post(source_path)
async def receive_ndjson(request: Request, background_tasks: BackgroundTasks):
    global reset_task
    # Indicate a new webhook has been received
    global new_query_made
    new_query_made = True

    # Create alert based on Bastille webhook
    webhook = await request.body()
    create_alert(webhook)

    # try:
    #     create_alert(webhook)
    #     return "success"
    # except Exception as e:
    #     return "failure"

    # Cancel any previously scheduled reset_new_query_flag task
    if reset_task and not reset_task.done():
        reset_task.cancel()

    # Schedule the reset_new_query_flag function to run in the background after 30 seconds
    reset_task = asyncio.create_task(reset_new_query_flag())
    logger.info("Resetting wait time before CLEARing alerts.")

    # Start a background job to CLEAR alerts
    background_tasks.add_task(turn_off_alert)

@app.post(adam_path)
async def receive_adam_finding(request: Request, background_tasks: BackgroundTasks):
    global reset_task
    global new_query_made
    new_query_made = True

    # Parse ADAM finding JSON
    body = await request.json()
    create_adam_alert(body)

    # Cancel any previously scheduled reset_new_query_flag task
    if reset_task and not reset_task.done():
        reset_task.cancel()

    # Schedule the reset_new_query_flag function to run in the background
    reset_task = asyncio.create_task(reset_new_query_flag())
    logger.info("ADAM: Resetting wait time before CLEARing alerts.")

    # Start a background job to CLEAR alerts
    background_tasks.add_task(turn_off_alert)


if __name__ == "__main__":
    import uvicorn
    kwargs = {"host": source_host, "port": source_port}
    if source_ssl and source_ssl_cert and source_ssl_key:
        kwargs["ssl_keyfile"] = source_ssl_key
        kwargs["ssl_certfile"] = source_ssl_cert
    uvicorn.run(app, **kwargs)
