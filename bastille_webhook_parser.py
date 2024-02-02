

class BastilleWebhookParser:
    def __init__(self, json_webhook):
        self.json_webhook = json_webhook

    def parse(self, option):
        self.option = option
        emitter = self.json_webhook.get("payload", {}).get("emitter", {})
        device_info = self.json_webhook.get("payload", {}).get("device_info", {})
        if option == "manufacturer":
            value = device_info.get("manufacturer")
            return value
        if option == "protocol":
            value = emitter.get("protocol")
            return value
        if option == "vendor":
            value = emitter.get("vendor")
            return value
        if option == "tags":
            value = self.json_webhook.get("payload", {}).get("tags", {})
            return value
        if option == "zone":
            value = self.json_webhook.get("payload", {}).get("zone_name", {})
            return value
