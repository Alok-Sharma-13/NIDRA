"""
Alert Dispatcher for NIDRA
Handles dispatching of alerts to log files and (eventually) the dashboard UI.

Author: Alok Sharma
Date: July 2025
"""

import os
import json
from datetime import datetime

ALERT_FILE = "data/log/events.json"

def log_to_file(alert: dict):
    print("[Dispatcher] Writing alert to file...")

    try:
        os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)

        try:
            if os.path.exists(ALERT_FILE):
                with open(ALERT_FILE, "r") as f:
                    data = json.load(f)
            else:
                data = []
        except json.JSONDecodeError:
            print("[Dispatcher] events.json is invalid, resetting file.")
            data = []

        data.append(alert)

        with open(ALERT_FILE, "w") as f:
            json.dump(data, f, indent=2)

        print("[Dispatcher] Alert logged to events.json.")

    except Exception as e:
        print(f"[Dispatcher] Failed to write alert: {e}")


def send_dashboard(alert: dict):
    """
    Placeholder to send alert to the dashboard via WebSocket or API.
    """
    print(f"[Dispatcher] (Future) Alert sent to dashboard: {alert['rule']} - {alert['severity']}")
