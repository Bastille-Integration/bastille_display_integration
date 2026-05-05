#!/usr/bin/env python3
"""Quick test script for Freeport display. Sends an alert then clears after a delay."""

import argparse
import time
import yaml
import sys
from freeport import Freeport

DEFAULTS = {
    "target_host": "10.35.44.51",
    "target_port": 2311,
    "username": "admin",
    "password": "admin",
    "detail_font_size": 160,
    "alert_text": "TEST ALERT - BLE detected in Zone A - Vendor: TestCo",
}


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f) or {}


def main():
    parser = argparse.ArgumentParser(description="Test Freeport display alert and clear")
    parser.add_argument("-c", "--config", help="Path to YAML config file", default=None)
    parser.add_argument("--host", help="Freeport target host")
    parser.add_argument("--port", type=int, help="Freeport target port")
    parser.add_argument("--username", help="API username")
    parser.add_argument("--password", help="API password")
    parser.add_argument("--alert-text", help="Alert message text")
    parser.add_argument("--font-size", type=int, help="Detail font size")
    parser.add_argument("--clear-delay", type=int, default=5, help="Seconds before sending clear (default: 5)")
    parser.add_argument("--no-clear", action="store_true", help="Send alert only, skip clear")
    parser.add_argument("--clear-only", action="store_true", help="Send clear only, skip alert")
    args = parser.parse_args()

    cfg = dict(DEFAULTS)
    if args.config:
        cfg.update(load_config(args.config))

    # CLI flags override config file
    if args.host:        cfg["target_host"]       = args.host
    if args.port:        cfg["target_port"]        = args.port
    if args.username:    cfg["username"]            = args.username
    if args.password:    cfg["password"]            = args.password
    if args.alert_text:  cfg["alert_text"]          = args.alert_text
    if args.font_size:   cfg["detail_font_size"]    = args.font_size

    fp = Freeport(
        host=cfg["target_host"],
        port=cfg["target_port"],
        username=cfg["username"],
        password=cfg["password"],
        log_file="test_freeport.log",
    )

    if not args.clear_only:
        print(f"Sending ALERT to {cfg['target_host']}:{cfg['target_port']} ...")
        print(f"  Text: {cfg['alert_text']}")
        fp.screen_change("alert", alert_text=cfg["alert_text"], detail_font_size=cfg["detail_font_size"])
        print("Alert sent. Check test_freeport.log for details.")

    if not args.no_clear and not args.clear_only:
        print(f"Waiting {args.clear_delay}s before clear...")
        time.sleep(args.clear_delay)

    if not args.no_clear:
        print(f"Sending CLEAR to {cfg['target_host']}:{cfg['target_port']} ...")
        fp.screen_change("clear")
        print("Clear sent.")


if __name__ == "__main__":
    main()
