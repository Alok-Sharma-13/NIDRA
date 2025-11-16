"""
NIDRA SDK Interface - Modular Version

Provides methods to sniff traffic, check honeypots, analyze logs with rule engine,
block malicious IPs, and log events in a structured way.

Author: Alok
Date: August 2025
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

from core.country_blocker import CountryBlocker     # ✅ ADDED

BLOCKED_IPS_FILE = "data/log/blocked_ips.txt"


class NidraSDK:
    def __init__(self):
        self.db_type = database_config.DB_TYPE
        self.db = database_config.db if self.db_type == "mongodb" else None
        self.SessionLocal = database_config.SessionLocal if self.db_type == "postgresql" else None
        self.engine = RuleEngine()
        self.rule_state = {}
        self.country_blocker = CountryBlocker()      # ✅ ADDED

    def capture_request(self, request_obj):
        log = sniff_request(request_obj)
        if not log:
            return None

        ip = log["ip_address"]

        # --------------- COUNTRY BLOCKING (ADDED) ---------------- #
        if not self.country_blocker.is_ip_allowed(ip):
            self.block_ip(ip)
            return "403 Forbidden - Country Blocked", 403
        # --------------------------------------------------------- #

        # Check if IP is blocked
        if self.is_ip_blocked(ip):
            return "403 Forbidden - IP Blocked", 403

        self.log_traffic(log)

        honeypot_response = self.check_honeypot(request_obj.path)
        if honeypot_response:
            return honeypot_response

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

    # === IP Blocker Methods ===
    def block_ip(self, ip):
        os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
        if not self.is_ip_blocked(ip):
            with open(BLOCKED_IPS_FILE, "a") as f:
                f.write(f"{ip}\n")
            print(f"[IPBlocker] IP blocked: {ip}")
        else:
            print(f"[IPBlocker] IP already blocked: {ip}")

    def unblock_ip(self, ip):
        if not os.path.exists(BLOCKED_IPS_FILE):
            return
        with open(BLOCKED_IPS_FILE, "r") as f:
            lines = f.readlines()
        with open(BLOCKED_IPS_FILE, "w") as f:
            for line in lines:
                if line.strip() != ip:
                    f.write(line)
        print(f"[IPBlocker] IP unblocked: {ip}")

    def is_ip_blocked(self, ip):
        if not os.path.exists(BLOCKED_IPS_FILE):
            return False
        with open(BLOCKED_IPS_FILE, "r") as f:
            blocked_ips = [line.strip() for line in f.readlines()]
        return ip in blocked_ips


# === Decorator for Clients ===
def sniff_request_decorator(sdk_instance):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = sdk_instance.capture_request(request)
            if result and isinstance(result, tuple):  # Honeypot response or blocked IP
                return result
            return func(*args, **kwargs)
        return wrapper
    return decorator
