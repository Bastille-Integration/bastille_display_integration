"""
Webhook test suite for bastille_display_integration.

Covers:
  - NDJson NDJSON parsing
  - BastilleWebhookParser field extraction
  - AdamWebhookParser field extraction
  - POST /zone-detections (single, multi-NDJSON, filtered, edge cases)
  - POST /adam-findings  (single, multi-NDJSON, filtered, severity color, edge cases)
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from ndjson_to_json import NDJson
from bastille_webhook_parser import BastilleWebhookParser
from adam_webhook_parser import AdamWebhookParser


# ── Helpers ──────────────────────────────────────────────────────────────────

def zone_detection(protocol="wifi", zone="Zone A", manufacturer="Apple", tags=None):
    return {
        "payload": {
            "emitter": {"protocol": protocol, "vendor": manufacturer},
            "device_info": {"manufacturer": manufacturer},
            "tags": tags if tags is not None else [],
            "zone_name": zone,
        }
    }


def adam_finding(protocol="wifi", zone="Zone A", vendor="LGInnotek",
                 severity="high", reasons=None, extra_tags=None):
    tags = [f"zone:{zone}"] + (extra_tags or [])
    return {
        "payload": {
            "severity": severity,
            "reasons": reasons or ["malicious_device_pineapple"],
            "reference_snapshot": {
                "emitter": {
                    "protocol": protocol,
                    "vendor": vendor,
                    "transmitter_id": "aa:bb:cc:dd:ee:ff",
                    "network": {"name": "TestNetwork"},
                },
                "tags": tags,
            },
        }
    }


def ndjson(*objects):
    return "\n".join(json.dumps(o) for o in objects).encode()


CONFIG_VALUES = {
    "zone_detection_template": "ALERT - {protocol} in {zone} - Vendor: {vendor} - ALERT",
    "adam_finding_template": "ADAM ALERT - {severity} - {reasons} - {tags} - Vendor: {vendor}",
    "algo_text_color": "orange",
    "algo_text_font": "roboto",
    "algo_text_position": "middle",
    "algo_text_scroll": "1",
    "algo_text_scroll_speed": "4",
    "algo_text_size": "medium",
}


@pytest.fixture()
def mock_algo():
    m = MagicMock()
    m.alert_screen.return_value = {"success": True}
    m.strobe_on.return_value = {"success": True}
    m.tone.return_value = {"success": True}
    m.alert_clear.return_value = {"success": True}
    m.strobe_off.return_value = {"success": True}
    return m


async def _noop(*args, **kwargs):
    pass


@pytest.fixture()
def client(mock_algo):
    import main
    with patch.object(main, "a", mock_algo), \
         patch.object(main, "vendor", "Algo"), \
         patch.object(main, "monitored_protocols", ["wifi", "ble", "cellular", "bt", "ieee_802_15_4"]), \
         patch.object(main, "allowed_tags", ["authorized", "exclude"]), \
         patch.object(main, "save_alert", MagicMock()), \
         patch.object(main, "get_config_value", lambda key, default=None: CONFIG_VALUES.get(key, default)), \
         patch.object(main, "turn_off_alert", _noop), \
         patch.object(main, "reset_new_query_flag", _noop):
        yield TestClient(main.app)


# ── NDJson ────────────────────────────────────────────────────────────────────

class TestNDJson:
    def _parse(self, data: bytes):
        return list(NDJson(log_file="app.log").ndjson_to_json(data))

    def test_single_line(self):
        obj = {"key": "value"}
        assert self._parse(json.dumps(obj).encode()) == [obj]

    def test_multiple_lines(self):
        objs = [{"n": 1}, {"n": 2}, {"n": 3}]
        assert self._parse(ndjson(*objs)) == objs

    def test_trailing_newline(self):
        obj = {"k": "v"}
        assert self._parse((json.dumps(obj) + "\n").encode()) == [obj]

    def test_empty_body(self):
        assert self._parse(b"") == []

    def test_whitespace_only(self):
        assert self._parse(b"   \n\n  ") == []

    def test_invalid_line_skipped(self):
        valid = {"k": "v"}
        data = b"not json\n" + json.dumps(valid).encode()
        assert self._parse(data) == [valid]

    def test_mixed_valid_invalid(self):
        objs = [{"n": 1}, {"n": 3}]
        data = json.dumps(objs[0]).encode() + b"\nbad\n" + json.dumps(objs[1]).encode()
        assert self._parse(data) == objs

    def test_nested_object(self):
        obj = {"payload": {"emitter": {"protocol": "wifi"}, "zone_name": "A"}}
        assert self._parse(json.dumps(obj).encode()) == [obj]


# ── BastilleWebhookParser ─────────────────────────────────────────────────────

class TestBastilleWebhookParser:
    def _parser(self, **kwargs):
        return BastilleWebhookParser(zone_detection(**kwargs))

    def test_protocol(self):
        assert self._parser(protocol="ble").parse("protocol") == "ble"

    def test_zone(self):
        assert self._parser(zone="Lab 2B").parse("zone") == "Lab 2B"

    def test_vendor(self):
        assert self._parser(manufacturer="Samsung").parse("vendor") == "Samsung"

    def test_tags(self):
        assert self._parser(tags=["authorized"]).parse("tags") == ["authorized"]

    def test_empty_tags(self):
        assert self._parser().parse("tags") == []

    def test_missing_payload(self):
        p = BastilleWebhookParser({})
        assert p.parse("protocol") is None
        assert p.parse("zone") is None
        assert p.parse("vendor") is None
        assert p.parse("tags") == []

    def test_null_payload_value(self):
        p = BastilleWebhookParser({"payload": None})
        assert p.parse("protocol") is None

    def test_null_emitter(self):
        p = BastilleWebhookParser({"payload": {"emitter": None, "zone_name": "Z"}})
        assert p.parse("protocol") is None
        assert p.parse("zone") == "Z"


# ── AdamWebhookParser ─────────────────────────────────────────────────────────

class TestAdamWebhookParser:
    def _parser(self, **kwargs):
        return AdamWebhookParser(adam_finding(**kwargs))

    def test_protocol(self):
        assert self._parser(protocol="cellular").parse("protocol") == "cellular"

    def test_vendor(self):
        assert self._parser(vendor="Cisco").parse("vendor") == "Cisco"

    def test_severity(self):
        assert self._parser(severity="critical").parse("severity") == "critical"

    def test_reasons(self):
        reasons = ["malicious_device_pineapple", "rogue_ap"]
        assert self._parser(reasons=reasons).parse("reasons") == reasons

    def test_zone_extracted_from_tags(self):
        assert self._parser(zone="Training 1A").parse("zone") == "Training 1A"

    def test_zone_missing_from_tags(self):
        p = AdamWebhookParser({"payload": {"reference_snapshot": {"tags": ["other_tag"]}}})
        assert p.parse("zone") is None

    def test_tags_returned(self):
        p = self._parser(zone="Zone A", extra_tags=["known_device"])
        tags = p.parse("tags")
        assert "zone:Zone A" in tags
        assert "known_device" in tags

    def test_empty_reasons_default(self):
        obj = adam_finding()
        obj["payload"]["reasons"] = None
        p = AdamWebhookParser(obj)
        assert p.parse("reasons") == []

    def test_missing_payload(self):
        p = AdamWebhookParser({})
        assert p.parse("protocol") is None
        assert p.parse("severity") is None

    def test_null_payload_value(self):
        p = AdamWebhookParser({"payload": None})
        assert p.parse("protocol") is None


# ── POST /zone-detections ─────────────────────────────────────────────────────

class TestZoneDetections:
    ENDPOINT = "/zone-detections"

    def test_single_detection_returns_200(self, client):
        r = client.post(self.ENDPOINT, content=ndjson(zone_detection()))
        assert r.status_code == 200

    def test_single_detection_ok_status(self, client):
        r = client.post(self.ENDPOINT, content=ndjson(zone_detection()))
        assert r.json() == {"status": "ok"}

    def test_algo_screen_called(self, client, mock_algo):
        client.post(self.ENDPOINT, content=ndjson(zone_detection(protocol="wifi")))
        mock_algo.alert_screen.assert_called_once()

    def test_algo_strobe_called(self, client, mock_algo):
        client.post(self.ENDPOINT, content=ndjson(zone_detection()))
        mock_algo.strobe_on.assert_called_once()

    def test_algo_tone_called(self, client, mock_algo):
        import main
        with patch.object(main, "tone", True):
            client.post(self.ENDPOINT, content=ndjson(zone_detection()))
        mock_algo.tone.assert_called_once()

    def test_multiple_ndjson_lines(self, client, mock_algo):
        payload = ndjson(
            zone_detection(protocol="wifi", zone="Zone A"),
            zone_detection(protocol="ble", zone="Zone B"),
        )
        r = client.post(self.ENDPOINT, content=payload)
        assert r.status_code == 200
        assert mock_algo.alert_screen.call_count == 2

    def test_unmonitored_protocol_filtered(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=ndjson(zone_detection(protocol="zigbee")))
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_authorized_tag_filtered(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=ndjson(zone_detection(tags=["authorized"])))
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_exclude_tag_filtered(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=ndjson(zone_detection(tags=["exclude"])))
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_unknown_tag_not_filtered(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=ndjson(zone_detection(tags=["some_other_tag"])))
        assert r.status_code == 200
        mock_algo.alert_screen.assert_called_once()

    def test_empty_body(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=b"")
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_invalid_json_skipped(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=b"not valid json")
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_mixed_valid_invalid_ndjson(self, client, mock_algo):
        payload = json.dumps(zone_detection(protocol="wifi")).encode() + b"\nbad line\n"
        r = client.post(self.ENDPOINT, content=payload)
        assert r.status_code == 200
        mock_algo.alert_screen.assert_called_once()

    def test_algo_screen_failure_reported(self, client, mock_algo):
        mock_algo.alert_screen.return_value = {"success": False, "error": "HTTP 503"}
        r = client.post(self.ENDPOINT, content=ndjson(zone_detection()))
        assert "Screen: HTTP 503" in r.json().get("errors", [])

    def test_alert_text_contains_protocol_and_zone(self, client, mock_algo):
        client.post(self.ENDPOINT, content=ndjson(zone_detection(protocol="ble", zone="Lab 1")))
        call_payload = mock_algo.alert_screen.call_args[0][0]
        assert "ble" in call_payload["text1"]
        assert "Lab 1" in call_payload["text1"]


# ── POST /adam-findings ───────────────────────────────────────────────────────

class TestAdamFindings:
    ENDPOINT = "/adam-findings"

    def test_single_finding_returns_200(self, client):
        r = client.post(self.ENDPOINT, content=ndjson(adam_finding()))
        assert r.status_code == 200

    def test_single_finding_ok_status(self, client):
        r = client.post(self.ENDPOINT, content=ndjson(adam_finding()))
        assert r.json() == {"status": "ok"}

    def test_algo_screen_called(self, client, mock_algo):
        client.post(self.ENDPOINT, content=ndjson(adam_finding()))
        mock_algo.alert_screen.assert_called_once()

    def test_multiple_ndjson_findings(self, client, mock_algo):
        payload = ndjson(
            adam_finding(protocol="wifi", zone="Zone A"),
            adam_finding(protocol="ble", zone="Zone B"),
        )
        r = client.post(self.ENDPOINT, content=payload)
        assert r.status_code == 200
        assert mock_algo.alert_screen.call_count == 2

    def test_high_severity_uses_red(self, client, mock_algo):
        client.post(self.ENDPOINT, content=ndjson(adam_finding(severity="high")))
        payload = mock_algo.alert_screen.call_args[0][0]
        assert payload["textColor"] == "red"

    def test_critical_severity_uses_red(self, client, mock_algo):
        client.post(self.ENDPOINT, content=ndjson(adam_finding(severity="critical")))
        payload = mock_algo.alert_screen.call_args[0][0]
        assert payload["textColor"] == "red"

    def test_medium_severity_uses_orange(self, client, mock_algo):
        client.post(self.ENDPOINT, content=ndjson(adam_finding(severity="medium")))
        payload = mock_algo.alert_screen.call_args[0][0]
        assert payload["textColor"] == "orange"

    def test_low_severity_uses_orange(self, client, mock_algo):
        client.post(self.ENDPOINT, content=ndjson(adam_finding(severity="low")))
        payload = mock_algo.alert_screen.call_args[0][0]
        assert payload["textColor"] == "orange"

    def test_unmonitored_protocol_filtered(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=ndjson(adam_finding(protocol="zigbee")))
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_authorized_tag_filtered(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=ndjson(adam_finding(extra_tags=["authorized"])))
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_exclude_tag_filtered(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=ndjson(adam_finding(extra_tags=["exclude"])))
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_empty_body(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=b"")
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_invalid_json_body(self, client, mock_algo):
        r = client.post(self.ENDPOINT, content=b"not valid json")
        assert r.status_code == 200
        mock_algo.alert_screen.assert_not_called()

    def test_malformed_ndjson_partial(self, client, mock_algo):
        payload = json.dumps(adam_finding(protocol="wifi")).encode() + b"\nbad line\n"
        r = client.post(self.ENDPOINT, content=payload)
        assert r.status_code == 200
        mock_algo.alert_screen.assert_called_once()

    def test_alert_text_contains_severity_and_vendor(self, client, mock_algo):
        client.post(self.ENDPOINT, content=ndjson(adam_finding(severity="high", vendor="Cisco")))
        payload = mock_algo.alert_screen.call_args[0][0]
        assert "HIGH" in payload["text1"]
        assert "Cisco" in payload["text1"]

    def test_algo_screen_failure_reported(self, client, mock_algo):
        mock_algo.alert_screen.return_value = {"success": False, "error": "HTTP 503"}
        r = client.post(self.ENDPOINT, content=ndjson(adam_finding()))
        assert "Screen: HTTP 503" in r.json().get("errors", [])

    def test_errors_collected_across_findings(self, client, mock_algo):
        mock_algo.alert_screen.return_value = {"success": False, "error": "timeout"}
        payload = ndjson(adam_finding(protocol="wifi"), adam_finding(protocol="ble"))
        r = client.post(self.ENDPOINT, content=payload)
        errors = r.json().get("errors", [])
        assert len(errors) == 2
