"""
Alert Dispatcher for NIDRA
Handles dispatching of alerts to log files and (eventually) the dashboard UI.

Author: Alok Sharma
Date: July 2025
"""
import json
import os
from flask import request, make_response

HONEYPOT_FILE = "data/config/honeypots.json"

class HoneypotManager:
    def __init__(self):
        if not os.path.exists(HONEYPOT_FILE):
            os.makedirs(os.path.dirname(HONEYPOT_FILE), exist_ok=True)
            with open(HONEYPOT_FILE, "w") as f:
                json.dump([], f)

        with open(HONEYPOT_FILE, "r") as f:
            self.honeypots = json.load(f)

    def get_visible_honeypots(self):
        return [hp for hp in self.honeypots if hp.get("visible", True)]

    def handle_trigger(self, path):
        ip = request.remote_addr
        self.block_ip(ip)
        self.raise_alert(ip, path)

        fake_response = self.get_fake_response(path)
        return make_response(fake_response, 200)

    def get_fake_response(self, path):
        for hp in self.honeypots:
            if hp['path'] == path:
                return hp.get("fake_content", "<h1>Access Denied</h1><p>You are being watched.</p>")
        return "<h1>Trap Triggered</h1>"

    def block_ip(self, ip):
        # TODO: Replace with actual IP blocking logic
        with open("data/logs/blocked_ips.txt", "a") as f:
            f.write(f"{ip}\n")

    def raise_alert(self, ip, path):
        # TODO: Replace with alert_dispatcher integration
        with open("data/logs/events.txt", "a") as f:
            f.write(f"[HONEYPOT] IP {ip} triggered honeypot at {path}\n")
