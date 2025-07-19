"""
Honeypot Manager for NIDRA
Detects access to honeypot paths and triggers alerts and blocking.

Author: Alok Sharma
Date: July 2025
"""

import os
import json
from datetime import datetime
from flask import request, make_response
# from core.utils import append_json_log
from core.alert_dispatcher import log_to_file, send_dashboard
from core.severity_classifier import SeverityClassifier

HONEYPOT_FILE = "data/honeypots.json"
BLOCKED_IPS_FILE = "data/log/blocked_ips.txt"


class HoneypotManager:
    def __init__(self):
        self.classifier = SeverityClassifier()
        self.honeypots = []

        # Ensure honeypot config exists
        os.makedirs(os.path.dirname(HONEYPOT_FILE), exist_ok=True)
        if not os.path.exists(HONEYPOT_FILE):
            with open(HONEYPOT_FILE, "w") as f:
                json.dump([], f)

        self.load_honeypots()

    def load_honeypots(self):
        try:
            with open(HONEYPOT_FILE, "r") as f:
                self.honeypots = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            self.honeypots = []

    def get_visible_honeypots(self):
        return [hp for hp in self.honeypots if hp.get("visible", True)]

    def handle_trigger(self, path):
        ip = request.remote_addr
        self.block_ip(ip)

        alert_data = {
            "source": "honeypot",
            "ip": ip,
            "path": path,
            "method": request.method,
            "timestamp": self.get_timestamp(),
            "rule": f"Honeypot Path Accessed: {path}",
        }

        # Classify severity
        alert_data["severity"] = self.classifier.classify(alert_data)

        # Log & Dispatch
        log_to_file(alert_data)
        send_dashboard(alert_data)


        return make_response(self.get_fake_response(path), 200)

    def get_fake_response(self, path):
        for hp in self.honeypots:
            if hp.get('path') == path:
                return hp.get("fake_content", "<h1>Access Denied</h1><p>You are being watched.</p>")
        return "<h1>Trap Triggered</h1>"

    def block_ip(self, ip):
        os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(f"{ip}\n")
        print(f"[HoneypotManager] IP blocked: {ip}")

    def get_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


manager = HoneypotManager()

def register_all_honeypots(app):
    print("[HoneypotManager] Honeypots registered.")