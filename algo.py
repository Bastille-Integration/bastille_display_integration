import logging
import hashlib
import base64
from logging.handlers import RotatingFileHandler
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks  # Import Request and BackgroundTasks
import httpx
import asyncio
import json
import ndjson
import yaml

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

# Read configuration values from the YAML file
with open("config.yaml", "r") as config_file:
    config = yaml.safe_load(config_file)

# Extract configuration values
source_host = config["source_host"]
source_path = config["source_path"]
source_port = config["source_port"]
target_host = config["target_host"]
strobe_pattern = config["strobe_pattern"]
strobe_color = config["strobe_color"]
auth_username = config["auth_username"]
auth_password = config["auth_password"]
clear_time = config["clear_time"]
monitored_protocols = config["monitored_protocols"]
allowed_tags = config["allowed_tags"]

# Algo paths defined
target_path = "/api/controls/screen/start"
strobe_on_path = "/api/controls/strobe/start"
strobe_off_path = "/api/controls/strobe/stop"

#Algo CLEAR JSON defined
default_target_payload = {
    "type": "image",
    "text1": "CLEAR",
    "textColor": "green",
    "textFont": "roboto",
    "textPosition": "middle",
    "textScroll": "0",
    "textScrollSpeed": "4",
    "textSize": "medium"
    }

#Algo strobe JSON defined
strobe_on_payload = {
    "pattern": strobe_pattern,
    "color1": strobe_color
    }

# Create Basic Authentication credentials
auth = (auth_username, auth_password)

# Set the Content-Type header to application/json
headers = {"Content-Type": "application/json"}

# Define a flag to track whether a new source query has been made
new_query_made = False

reset_task = None

# Resets new alert flag to false. Triggers screen CLEAR after configured seconds.
async def reset_new_query_flag():
    await asyncio.sleep(clear_time)  # Sleep for X seconds
    global new_query_made
    new_query_made = False

# Resets screen to clear.
async def send_default_payload():
    await asyncio.sleep(clear_time)  # Sleep for X seconds
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
                logger.info("Clearing alerts due to not receiving new Zone Detections for %s seconds.", clear_time)
            else:
                logger.error("Failed to clear alerts due to error. Recommend checking Algo.")

#Handles JSON payload. Communicates to Algo based on logic/filters..
async def transfer_data(payload: dict, background_tasks: BackgroundTasks):
    # Log the incoming JSON payload for debugging
    logger.info("Received JSON payload: %s", payload)
    global new_query_made
    new_query_made = True  # Set the flag to True when a new source query is made

    global reset_task

    async with httpx.AsyncClient() as client:
        # Construct the complete source URL
        source_url = f"http://{source_host}{source_path}"

        # Construct the complete target URL for text
        target_url = f"http://{target_host}{target_path}"

        # Construct the complete target URL for strobe
        target_strobe_on_url = f"http://{target_host}{strobe_on_path}"

        # Access the nested value 'emitter' within 'devices'
        emitter = payload.get("payload", {}).get("emitter", {})
        logger.info("emitter details: %s", emitter)

        # Access the nested value 'protocol' within 'emitter'
        protocol = emitter.get("protocol")
        logger.info("protocol details: %s", protocol)  

        # Access the nested value 'device_info' within 'payload'
        device_info = payload.get("payload", {}).get("device_info", {})
        logger.info("device info: %s", device_info)

        # Access the nested value 'manufacturer' within 'device_info'
        manufacturer = device_info.get("manufacturer")
        logger.info("manufacturer details: %s", manufacturer)

        # Access the nested value 'vendor' within 'emitter'
        vendor = emitter.get("vendor")
        logger.info("vendor details: %s", vendor)

        # Access to tags
        tags = payload.get("payload", {}).get("tags", {})
        logger.info("tags details: %s", tags)

        #Access to zones
        zone_name = payload.get("payload", {}).get("zone_name", {})
        logger.info("zone_name details: %s", zone_name) 

        # Check if the "protocol" value is "wifi" in the source payload
        if protocol in monitored_protocols and allowed_tags not in tags: 
            if all(tag not in tags for tag in allowed_tags):
                # Create the target payload with "text1" set to "ALERT - [protocol] in [zone] - ALERT"
                target_payload = {
                    "type": "image",
                    "text1": f"ALERT - {protocol} in {zone_name} - Vendor: {vendor} - ALERT",
                    "textColor": "orange",
                    "textFont": "roboto",
                    "textPosition": "middle",
                    "textScroll": "1",
                    "textScrollSpeed": "4",
                    "textSize": "medium"
                }

                # Cancel any previously scheduled reset_new_query_flag task
                if reset_task and not reset_task.done():
                    reset_task.cancel()

                # Schedule the reset_new_query_flag function to run in the background after 30 seconds
                reset_task = asyncio.create_task(reset_new_query_flag())
                
                # Start a background job to CLEAR alerts
                background_tasks.add_task(send_default_payload)

                # Calculate the MD5 hash of the default target payload
                payload_json = json.dumps(target_payload, separators=(',', ':'), sort_keys=True)
                md5_hash = hashlib.md5(payload_json.encode()).digest()
                md5_base64 = base64.b64encode(md5_hash).decode()

                # Add the Content-MD5 header to the request
                headers["Content-MD5"] = md5_base64

                #Log
                logger.info("Target JSON: %s", target_payload)

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
        
            else:
                # If "tag" is not above, keep the target payload as is
                target_payload = default_target_payload
                logger.info("Not sending alert due to known tag.")

        else:
            # If "protocol" is not above, keep the target payload as is
            target_payload = default_target_payload
            logger.info("Not sending alert due to unknown protocol.")

# Listener. Converts NDJSON to JSON.
@app.post(source_path)
async def receive_ndjson(request: Request, background_tasks: BackgroundTasks):
    try:
        # Read the request body as bytes
        body = await request.body()

        # Convert the bytes to a string and split it by newline to get individual NDJSON lines
        ndjson_lines = body.decode().split('\n')

        # Process each NDJSON line
        results = []
        for line in ndjson_lines:
            try:
                payload = json.loads(line)
                # Call the transfer_data function to process the payload asynchronously
                await transfer_data(payload, background_tasks)
            except json.JSONDecodeError as e:
                # Handle invalid JSON format in a line
                results.append({"error": f"Invalid JSON format: {line}"})
        
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error processing data. Please ensure Algo is connected and API enabled.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=source_host, port=source_port)
