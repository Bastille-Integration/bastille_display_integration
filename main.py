from fastapi import FastAPI, HTTPException, Request, BackgroundTasks  # Import Request and BackgroundTasks
import yaml
import logging
import asyncio
from ndjson_to_json import NDJson
from bastille_webhook_parser import BastilleWebhookParser
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
source_port = config["source_port"]
target_host = config["target_host"]
target_port = config["target_port"]
strobe_pattern = config["strobe_pattern"]
strobe_color = config["strobe_color"]
auth_username = config["auth_username"]
auth_password = config["auth_password"]
clear_time = config["clear_time"]
monitored_protocols = config["monitored_protocols"]
allowed_tags = config["allowed_tags"]
tone = config["tone"]
tone_wav = config["tone_wav"]

# Configure logging
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("Main")

app = FastAPI()
# Create Algo or Freeport object
if vendor == "Algo":
    a = Algo(host=target_host, username=auth_username, password=auth_password, log_file=log_file)
if vendor == "Freeport":
    f = Freeport(host=target_host, port= target_port, username=auth_username, password=auth_password, log_file=log_file)

def create_alert(body):
    #Covert NDjson to json
    payload = NDJson(log_file=log_file)
    #Review each json line individually
    for i in payload.ndjson_to_json(body):
        #Parse Bastille webhook
        i = BastilleWebhookParser(i)
        protocol = i.parse("protocol")
        zone = i.parse("zone")
        vendor = i.parse("vendor")
        tags = i.parse("tags")
        #Prepare and send Algo text
        if protocol not in monitored_protocols:
            logger.info(f'Not sending alert due to unknown protocol {protocol}.')
        elif any(i in tags for i in allowed_tags):
            logger.info(f'Not sending alert due to known tags {tags}')
        else:
            target_payload = {
                "type": "image",
                "text1": f"ALERT - {protocol} in {zone} - Vendor: {vendor} - ALERT",
                "textColor": "orange",
                "textFont": "roboto",
                "textPosition": "middle",
                "textScroll": "1",
                "textScrollSpeed": "4",
                "textSize": "medium"
            }
        if vendor == "Algo":
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
        else:
            f.screen_change(option="alert", protocol=protocol, device=vendor, zone=zone)

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

    # Cancel any previously scheduled reset_new_query_flag task
    if reset_task and not reset_task.done():
        reset_task.cancel()

    # Schedule the reset_new_query_flag function to run in the background after 30 seconds
    reset_task = asyncio.create_task(reset_new_query_flag())
    logger.info("Resetting wait time before CLEARing alerts.")

    # Start a background job to CLEAR alerts
    background_tasks.add_task(turn_off_alert)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=source_host, port=source_port)
