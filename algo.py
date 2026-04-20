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
        try:
            response = requests.post(url=f'{self.host}{target_path}', auth=self.auth, headers=headers, json=target_payload, verify=False)
            if response.status_code == 200:
                self.logger.info("Sending alerts with payload: %s", target_payload)
                return {"success": True}
            else:
                self.logger.error("Failed to send alerts due to error. Recommend checking Algo. Received: %s", response.status_code)
                return {"success": False, "error": f"HTTP {response.status_code}"}
        except requests.exceptions.ConnectionError as e:
            self.logger.error("Failed to connect to Algo: %s", e)
            return {"success": False, "error": f"Connection failed: {e}"}
        except Exception as e:
            self.logger.error("Algo alert_screen error: %s", e)
            return {"success": False, "error": str(e)}

    def strobe_on(self, strobe_payload):
        try:
            response = requests.post(url=f'{self.host}{strobe_on_path}', auth=self.auth, headers=headers, json=strobe_payload, verify=False)
            if response.status_code == 200:
                self.logger.info("Turning on strobe.")
                return {"success": True}
            else:
                self.logger.error("Failed to turn on strobe. Recommend checking Algo. Received: %s", response.status_code)
                return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            self.logger.error("Algo strobe_on error: %s", e)
            return {"success": False, "error": str(e)}

    def tone(self, tone_payload):
        try:
            response = requests.post(url=f'{self.host}{tone_path}', auth=self.auth, headers=headers, json=tone_payload, verify=False)
            if response.status_code == 200:
                self.logger.info("Starting tone.")
                return {"success": True}
            else:
                self.logger.error("Failed to turn on tone. Recommend checking Algo. Received: %s", response.status_code)
                return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            self.logger.error("Algo tone error: %s", e)
            return {"success": False, "error": str(e)}

    def alert_clear(self, clear_payload):
        try:
            response = requests.post(url=f'{self.host}{target_path}', auth=self.auth, headers=headers, json=clear_payload, verify=False)
            if response.status_code == 200:
                self.logger.info("Clearing alerts due to not receiving new Zone Detections.")
                return {"success": True}
            else:
                self.logger.error("Failed to clear alerts due to error. Recommend checking Algo. Received: %s", response.status_code)
                return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            self.logger.error("Algo alert_clear error: %s", e)
            return {"success": False, "error": str(e)}

    def strobe_off(self):
        try:
            response = requests.post(url=f'{self.host}{strobe_off_path}', auth=self.auth, headers=headers, verify=False)
            if response.status_code == 200:
                self.logger.info("Turning strobe off.")
                return {"success": True}
            else:
                self.logger.error("Failed to turn strobe off due to error. Recommend checking Algo. Received: %s", response.status_code)
                return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            self.logger.error("Algo strobe_off error: %s", e)
            return {"success": False, "error": str(e)}
