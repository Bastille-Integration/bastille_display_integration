


class AdamWebhookParser:
    def __init__(self, json_webhook):
        self.json_webhook = json_webhook

    def parse(self, option):
        payload = self.json_webhook.get("payload", {})
        snapshot = payload.get("reference_snapshot", {})
        emitter = snapshot.get("emitter", {})

        if option == "protocol":
            return emitter.get("protocol")
        if option == "vendor":
            return emitter.get("vendor")
        if option == "transmitter_id":
            return emitter.get("transmitter_id")
        if option == "severity":
            return payload.get("severity")
        if option == "reasons":
            return payload.get("reasons", [])
        if option == "zone":
            # Extract zone from tags like "zone:Training 1A"
            tags = snapshot.get("tags", [])
            for tag in tags:
                if tag.lower().startswith("zone:"):
                    return tag[5:]
            return None
        if option == "tags":
            return snapshot.get("tags", [])
        if option == "network_name":
            network = emitter.get("network", {})
            return network.get("name")
