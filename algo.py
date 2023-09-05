import logging
import hashlib
import base64
from logging.handlers import RotatingFileHandler
from fastapi import FastAPI, BackgroundTasks
import httpx
import asyncio
import json
import ndjson

# Configure logging
log_file = "app.log"  # Specify the log file name here
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Create a rotating file handler to write logs to a file
file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))

# Create a logger and add the file handler
logger = logging.getLogger(__name__)
logger.addHandler(file_handler)

app = FastAPI()

# Read configuration values from the JSON file
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Extract configuration values
source_host = config["source_host"]
source_path = config["source_path"]
target_host = config["target_host"]
target_path = config["target_path"]
strobe_on_path = config["strobe_on_path"]
strobe_off_path = config["strobe_off_path"]
strobe_on_payload = config["strobe_on_payload"]
default_target_payload = config["default_target_payload"]

# Define Basic Authentication credentials
auth_username = config["auth_username"]
auth_password = config["auth_password"]

# Create Basic Authentication credentials
auth = (auth_username, auth_password)

# Set the Content-Type header to application/json
headers = {"Content-Type": "application/json"}

# Define a flag to track whether a new source query has been made
new_query_made = False

reset_task = None

async def reset_new_query_flag():
    await asyncio.sleep(10)  # Sleep for X seconds
    global new_query_made
    new_query_made = False

async def send_default_payload():
    await asyncio.sleep(20)  # Sleep for X seconds
    global new_query_made
    logger.info("new_query_made value: %s", new_query_made) 
    if not new_query_made:
        async with httpx.AsyncClient() as client:
            # Construct the complete target URL
            target_url = f"http://{target_host}{target_path}"

            # Construct the complete target URL for strobe
            target_strobe_off_url = f"http://{target_host}{strobe_off_path}"

            # Calculate the MD5 hash of the default target payload
            payload_json = json.dumps(default_target_payload, separators=(',', ':'), sort_keys=True)
            md5_hash = hashlib.md5(payload_json.encode()).digest()
            md5_base64 = base64.b64encode(md5_hash).decode()

            # Add the Content-MD5 header to the request
            headers["Content-MD5"] = md5_base64

            # Send the default target payload
            response = await client.post(target_url, json=default_target_payload, auth=auth, headers=headers)
            response = await client.post(target_strobe_off_url, auth=auth, headers=headers)

            # Log the headers of the target request
            logger.info("Headers of the target request: %s", response.request.headers)
            logger.info("JSON: %s", default_target_payload)

            # Check if the request was successful
            if response.status_code == 200:
                logger.info("Default payload sent due to inactivity.")
            else:
                logger.error("Failed to send the default payload due to inactivity.")

@app.post("/zone-detections")
async def transfer_data(payload: dict, background_tasks: BackgroundTasks):
    # Log the incoming JSON payload for debugging
    logger.info("Received JSON payload: %s", payload)
    global new_query_made
    new_query_made = True  # Set the flag to True when a new source query is made

    background_tasks.add_task(send_default_payload)

    global reset_task

    # Cancel any previously scheduled reset_new_query_flag task
    if reset_task and not reset_task.done():
        reset_task.cancel()

    # Schedule the reset_new_query_flag function to run in the background after 30 seconds
    reset_task = asyncio.create_task(reset_new_query_flag())

    async with httpx.AsyncClient() as client:
        # Construct the complete source URL
        source_url = f"http://{source_host}{source_path}"

        # Construct the complete target URL for text
        target_url = f"http://{target_host}{target_path}"

        # Construct the complete target URL for strobe
        target_strobe_on_url = f"http://{target_host}{strobe_on_path}"

        # Access the nested value 'emitter' within 'devices'
        emitter = payload.get("payload", {}).get("emitter", {})
        logging.info("emitter details: %s", emitter)

        # Access the nested value 'protocol' within 'emitter'
        protocol = emitter.get("protocol")
        logging.info("protocol details: %s", protocol)  

        # Access to tags
        tags = payload.get("payload", {}).get("tags", {})
        logging.info("tags details: %s", tags)

        #Access to zones
        zone_name = payload.get("payload", {}).get("zone_name", {})
        logging.info("zone_name details: %s", zone_name) 

        # Check if the "protocol" value is "wifi" in the source payload
        if protocol in ["cellular", "wifi", "bluetooth"] and "authorized" not in tags: 
            # Create the target payload with "text1" set to "ALERT - Cellular in Conference Rm - ALERT"
            target_payload = {
                "type": "image",
                "text1": f"ALERT - {protocol} in {zone_name} - ALERT",
                "textColor": "orange",
                "textFont": "roboto",
                "textPosition": "middle",
                "textScroll": "1",
                "textScrollSpeed": "4",
                "textSize": "medium"
            }
        else:
            # If "protocol" is not above, keep the target payload as is
            target_payload = default_target_payload

        # Calculate the MD5 hash of the default target payload
        payload_json = json.dumps(default_target_payload, separators=(',', ':'), sort_keys=True)
        md5_hash = hashlib.md5(payload_json.encode()).digest()
        md5_base64 = base64.b64encode(md5_hash).decode()

        # Add the Content-MD5 header to the request
        headers["Content-MD5"] = md5_base64

        #Log
        logger.info("JSON: %s", target_payload)

        # Send the modified JSON payload to the target URL
        response = await client.post(target_url, json=target_payload, auth=auth, headers=headers)
        response = await client.post(target_strobe_on_url, json=strobe_on_payload, auth=auth, headers=headers)

        # Log the headers of the target request
        logger.info("Headers of the target request: %s", response.request.headers)

        # Check if the request was successful
        if response.status_code == 200:
            logger.info("Data transferred successfully.")
            return {"message": "Data transferred successfully."}
        else:
            logger.info("Response: %s", response) 
            error_text = response.text
            logger.error("Failed to send data to the target URL. Error text: %s", error_text)
            return {"error": "Failed to send data to the target URL."}

    # await asyncio.sleep(10)  # Wait for X seconds
    new_query_made = False

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
