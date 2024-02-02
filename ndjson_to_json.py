import json
import logging

class NDJson:
    def __init__(self, log_file):
        logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("ndjson Class")
    def ndjson_to_json(self, payload):
        self.payload = payload
        ndjson_lines = payload.decode().split('\n')
        for line in ndjson_lines:
            try:
                output = json.loads(line)
                yield output
            except json.JSONDecodeError as e:
                self.logger.error("Invalid JSON format: %s", line)