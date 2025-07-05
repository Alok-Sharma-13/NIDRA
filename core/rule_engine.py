"""
Rule Engine for NIDRA
Analyzes incoming traffic logs and applies detection rules to identify suspicious activity.

Author: Alok & Aditya
Date: July 2025
"""

from datetime import datetime
from typing import Optional, Dict, List, Any
import re

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
    """raise
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
    This version is stateless and depends on external counters.
    """
    def __init__(self, name: str, threshold: int, key: str = "ip_address", severity: str = "high"):
        super().__init__(name, f"Threshold exceeded: {threshold} for {key}", severity)
        self.threshold = threshold
        self.key = key

    def evaluate(self, log: Dict[str, Any], state: Dict[str, int]) -> Optional[Dict[str, Any]]:
        value = log.get(self.key)
        if not value:
            return None

        state[value] = state.get(value, 0) + 1
        if state[value] > self.threshold:
            return {
                "rule": self.name,
                "description": self.description,
                "severity": self.severity,
                "timestamp": datetime.utcnow().isoformat(),
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
        """Registers a collection of core rules."""
        self.signature_rules.extend([
            SignatureRule("SQL Injection", r"(union select|drop table|--)", target="path", severity="high"),
            SignatureRule("XSS Attempt", r"<script.*?>", target="path", severity="high"),
            SignatureRule("Suspicious User-Agent", r"sqlmap|nmap|curl", target="headers", severity="medium"),
        ])

        self.threshold_rules.append(
            ThresholdRule("IP Flood", threshold=20, key="ip_address", severity="critical")
        )

    def analyze(self, log: Dict[str, Any], state: Optional[Dict[str, int]] = None) -> List[Dict[str, Any]]:
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
                alerts.append(result)

        for rule in self.threshold_rules:
            if state is None:
                continue  # ThresholdRule requires state
            result = rule.evaluate(log, state)
            if result:
                alerts.append(result)

        return alerts
