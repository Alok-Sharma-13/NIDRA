"""
Alert Dispatcher for NIDRA
Handles dispatching of alerts to log files and (eventually) the dashboard UI.

Author: Alok Sharma
Date: July 2025
"""

import os 
import json 
from datetime import datetime

LOG_FILE = "data/log/events.txt"

def log_to_gile(alert: dict):
    """
    Appends an alert dictionary to the events.txt file JSON Format.

    Args: 
        alert(dict): The alert data to log.

    """
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")
        print("[Dispatcher] Alert logged to events.txt.")
    except Exception as e:
        print(f"[Dispatcher] Failed to write alert: {e}")

def send_dashboard(alert: dict):
    """
    Placeholder to send alert to the dashboard via WebSocket or API.
    This will be implemented in Semester 6.

    Args:
        alert (dict): The alert data to dispatch.
    """
    
    print(f"[Dispatcher] (Future) Alert sent to dashboard: {alert['rule']} - {alert['severity']}")