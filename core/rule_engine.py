"""
Rule Engine for NIDRA
Analyzes incoming traffic logs and applies detection rules to identify suspicious activity.

Author: Alok
Date: July 2025
"""

from datetime import datetime, timedelta
import re
import json
import os 
from typing import Optional, Dict, List, Any
# from core.alert_dispatcher import log_to_file, send_dashboard

# === Base Rule Classes ===

class Rule:
    """
    Abstract base class for all detection rules.
    Each rule must implement the evaluate method.
    """
    def __init__(self, name: str, description: str, severity: str = "low"):
        self.name = name
        self.description = description
        self.severity = severity

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raise NotImplementedError("Each rule must implement the evaluate method")


class SignatureRule(Rule):
    """
    Rule that matches request path or headers against known malicious patterns.
    """
    def __init__(self, name: str, pattern: str, target: str = "path", severity: str = "medium"):
        super().__init__(name, f"Signature match for pattern: {pattern}", severity)
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.target = target

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        data = log.get(self.target, "")
        if isinstance(data, dict):
            data = str(data)
        if self.pattern.search(data):
            return {
                "rule": self.name,
                "description": self.description,
                "severity": self.severity,
                "timestamp": datetime.utcnow().isoformat(),
            }
        return None


class ThresholdRule(Rule):
    """
    Rule that detects repeated events from the same key (e.g., IP flooding).
    """
    def __init__(self, name: str, threshold: int, window_seconds: int = 60, key: str = "ip_address", severity: str = "high"):
        super().__init__(name, f"Threshold exceeded: {threshold} in {window_seconds}s for {key}", severity)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.key = key

    def evaluate(self, log: Dict[str, Any], state: Dict[str, List[datetime]]) -> Optional[Dict[str, Any]]:
        value = log.get(self.key)
        if not value:
            return None

        now = datetime.utcnow()
        state.setdefault(value, []).append(now)

        state[value] = [ts for ts in state[value] if now - ts <= timedelta(seconds=self.window_seconds)]

        if len(state[value]) > self.threshold:
            return {
                "rule": self.name,
                "description": self.description,
                "severity": self.severity,
                "timestamp": now.isoformat(),
            }
        return None


# === Rule Engine ===

class RuleEngine:
    """
    The main rule engine that holds and runs detection rules.
    """
    def __init__(self):
        self.signature_rules: List[Rule] = []
        self.threshold_rules: List[ThresholdRule] = []
        self._load_default_rules()

    def _load_default_rules(self):
        """Registers a collection of core rules based on rules.json."""
        rules_path = os.path.join("data", "rules.json")
        enabled_rules = {}

        try:
            with open(rules_path, "r") as f:
                config = json.load(f)
                enabled_rules = config.get("enabled_rules", {})
        except Exception as e:
            print(f"[RuleEngine] Failed to load rules.json: {e}")
            # Fallback: enable all by default
            enabled_rules = {
                "SQL Injection": True,
                "XSS Attempt": True,
                "Suspicious User-Agent": True,
                "IP Flood": True,
                "Broken Authentication": True,                              #New Rule
                "Broken Access Control / IDOR": True,                       #New Rule
                "Remote Code Execution / Command Injection": True,          #New Rule
                "File Upload Abuse": True,                                  #New Rule
                "Insecure Deserialization": True                            #New Rule
            }

        # Signature Rules
        if enabled_rules.get("SQL Injection", False):
            self.signature_rules.append(
                SignatureRule("SQL Injection", r"(union select|drop table|--)", target="path", severity="high")
            )

        if enabled_rules.get("XSS Attempt", False):
            self.signature_rules.append(
                SignatureRule("XSS Attempt", r"<script.*?>", target="path", severity="high")
            )

        if enabled_rules.get("Suspicious User-Agent", False):
            self.signature_rules.append(
                SignatureRule("Suspicious User-Agent", r"sqlmap|nmap|curl", target="user_agent", severity="medium")
            )

        # Threshold Rule
        if enabled_rules.get("IP Flood", False):
            self.threshold_rules.append(
                ThresholdRule("IP Flood", threshold=20, window_seconds=60, key="ip_address", severity="critical")
            )

        if enabled_rules.get("Broken Authentication", False):
            self.threshold_rules.append(
                ThresholdRule("Broken Authentication", threshold=5, window_seconds=120, key="username", severity="high")
            )

        if enabled_rules.get("Broken Access Control / IDOR", False):
            self.signature_rules.append(
                SignatureRule("Broken Access Control / IDOR", r"/user/\d+|/profile/\d+|/invoice/\d+", target="path", severity="critical")
            )

        if enabled_rules.get("Remote Code Execution / Command Injection", False):
            self.signature_rules.append(
                SignatureRule("Remote Code Execution / Command Injection", r"(\b(cat|ls|whoami|curl|wget|bash|sh)\b|;|&&|\|)", target="body", severity="critical")
            )

        if enabled_rules.get("File Upload Abuse", False):
            self.signature_rules.append(
                SignatureRule("File Upload Abuse", r"(\.php$|\.jsp$|\.asp$|\.exe$|\.sh$|\.js$|\.jpg\.php$|\.png\.php$)", target="filename", severity="high")
            )

        if enabled_rules.get("Insecure Deserialization", False):
            self.signature_rules.append(
                SignatureRule("Insecure Deserialization", r"(pickle|object|javaSerialized|Y29tcGxleA==|__reduce__)", target="body", severity="critical")
            )


    def analyze(self, log: Dict[str, Any], state: Optional[Dict[str, List[datetime]]] = None) -> List[Dict[str, Any]]:
        """
        Analyze a log entry using all rules.

        Args:
            log: The incoming traffic log dictionary.
            state: Optional dictionary to track thresholds (required by ThresholdRule).

        Returns:
            List of matched alerts.
        """
        alerts = []

        for rule in self.signature_rules:
            result = rule.evaluate(log)
            if result:
                full_alert = {**result, **log}
                alerts.append(full_alert)

        for rule in self.threshold_rules:
            if state is None:
                continue  # ThresholdRule requires state
            result = rule.evaluate(log, state)
            if result:
                full_alert = {**result, **log}
                alerts.append(full_alert)

        return alerts
