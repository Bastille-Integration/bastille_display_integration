import requests
import logging

headers = {"Content-Type": "application/json"}
target_path = "/api/controls/screen/start"
strobe_on_path = "/api/controls/strobe/start"
strobe_off_path = "/api/controls/strobe/stop"
tone_path = "/api/controls/tone/start"


class Algo:
    def __init__(self, host, username, password, log_file):
        self.host = host
        self.auth = (username, password)
        logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("Algo Class")

    def alert_screen(self, target_payload):
        response = requests.post(url=f'{self.host}{target_path}', auth=self.auth, headers=headers, json=target_payload)
        if response.status_code == 200:
            self.logger.info("Sending alerts with payload: %s", target_payload)
        else:
            self.logger.error("Failed to send alerts due to error. Recommend checking Algo. Received: %s", response.status_code)

    def strobe_on(self, strobe_payload):
        response = requests.post(url=f'{self.host}{strobe_on_path}', auth=self.auth, headers=headers, json=strobe_payload)
        if response.status_code == 200:
            self.logger.info("Turning on strobe.")
        else:
            self.logger.error("Failed to turn on strobe. Recommend checking Algo. Received: %s", response.status_code)

    def tone(self, tone_payload):
        response = requests.post(url=f'{self.host}{tone_path}', auth=self.auth, headers=headers, json=tone_payload)
        if response.status_code == 200:
            self.logger.info("Starting tone.")
        else:
            self.logger.error("Failed to turn on tone. Recommend checking Algo. Received: %s", response.status_code)

    def alert_clear(self, clear_payload):
        response = requests.post(url=f'{self.host}{target_path}', auth=self.auth, headers=headers, json=clear_payload)
        if response.status_code == 200:
            self.logger.info("Clearing alerts due to not receiving new Zone Detections.")
        else:
            self.logger.error("Failed to clear alerts due to error. Recommend checking Algo. Received: %s", response.status_code)

    def strobe_off(self):
        response = requests.post(url=f'{self.host}{strobe_off_path}', auth=self.auth, headers=headers)
        if response.status_code == 200:
            self.logger.info("Turning strobe off.")
        else:
            self.logger.error("Failed to turn strobe off due to error. Recommend checking Algo. Received: %s", response.status_code)