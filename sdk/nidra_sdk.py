"""
NIDRA SDK Interface - Modular Version

Provides methods to sniff traffic, check honeypots, analyze logs with rule engine,
block malicious IPs, and log events in a structured way.

Author: Alok
Date: July 2025
"""

import os
import json
from functools import wraps
from flask import request
from datetime import datetime

from core.traffic_sniffer import sniff_request
from core.rule_engine import RuleEngine
from core.honeypot_manager import manager as honeypot_manager
from core.alert_dispatcher import dispatch_alert
from backend import database_config


class NidraSDK:
    def __init__(self):
        self.db_type = database_config.DB_TYPE
        self.db = database_config.db if self.db_type == "mongodb" else None
        self.SessionLocal = database_config.SessionLocal if self.db_type == "postgresql" else None
        self.engine = RuleEngine()
        self.rule_state = {}

    def capture_request(self, request_obj):
        log = sniff_request(request_obj)
        if not log:
            return None

        self.log_traffic(log)

        # Check for honeypot path
        honeypot_response = self.check_honeypot(request_obj.path)
        if honeypot_response:
            return honeypot_response

        # Run rule engine
        self.analyze_with_rules(log)
        return log

    def check_honeypot(self, path):
        visible_paths = [hp["path"] for hp in honeypot_manager.get_visible_honeypots()]
        if path in visible_paths:
            return honeypot_manager.handle_trigger(path)
        return None

    def analyze_with_rules(self, log):
        alerts = self.engine.analyze(log, self.rule_state)
        for alert in alerts:
            full_alert = {**alert, **log}
            self.log_alert(full_alert)

    def log_traffic(self, log):
        try:
            os.makedirs("data/log", exist_ok=True)
            with open("data/log/all_traffic.json", "a") as f:
                f.write(json.dumps(log) + "\n")
        except Exception as e:
            print(f"[NIDRA SDK] Failed to write all traffic: {e}")

    def log_alert(self, alert):
        try:
            dispatch_alert(alert)
        except Exception as e:
            print(f"[NIDRA SDK] Failed to log alert: {e}")


def sniff_request_decorator(sdk_instance):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = sdk_instance.capture_request(request)
            if result and isinstance(result, tuple):  # Honeypot response
                return result
            return func(*args, **kwargs)
        return wrapper
    return decorator
