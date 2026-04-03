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
        if isinstance(pattern,list):
            pattern = "|".join(pattern)
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.target = target

    def evaluate(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        data = log.get(self.target, "")
        if isinstance(data, (dict,list)):
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
            # self.signature_rules.append(
            #     SignatureRule("SQL Injection", r"(union select|drop table|--)", target="path", severity="high")
            # )
            self.signature_rules.append(
                SignatureRule(
                    "SQL Injection",
                    [
                        r"union select",
                        r"or 1=1",
                        r"or '1'='1",
                        r"or \"1\"=\"1\"",
                        r"sleep\(",
                        r"benchmark\(",
                        r"pg_sleep",
                        r"waitfor delay",
                        r"drop table",
                        r"insert into",
                        r"delete from",
                        r"update .* set",
                        r"information_schema",
                        r"xp_cmdshell",
                        r"exec\(",
                        r"--",
                        r"#",
                        r"/\*.*\*/",
                        r"having 1=1",
                        r"and 1=1",
                        r"load_file",
                        r"outfile",
                        r"0x[0-9a-f]+",
                        r"char\(",
                        r"cast\(",
                        r"convert\(",
                        r"substring\(",
                        r"ascii\(",
                        r"version\(",
                        r"database\(",
                        r"user\(",
                        r"select .* from",
                        r"union all select",
                        r"order by \d+",
                        r"group by",
                        r"limit \d+",
                        r"offset \d+",
                        r"truncate table",
                        r"alter table",
                        r"create table",
                        r"show tables",
                        r"show databases",
                        r"into dumpfile",
                        r"into outfile",
                        r"load data",
                        r"@@version",
                        r"@@datadir",
                        r"@@hostname",
                        r"sysobjects",
                        r"syscolumns"
                    ],
                    target="path",
                    severity="high"
                )
            )

        if enabled_rules.get("XSS Attempt", False):
            # self.signature_rules.append(
            #     SignatureRule("XSS Attempt", r"<script.*?>", target="path", severity="high")
            # )
            self.signature_rules.append(
                SignatureRule(
                    "XSS Attempt",
                    [
                        r"<script",
                        r"</script>",
                        r"alert\(",
                        r"prompt\(",
                        r"confirm\(",
                        r"onerror=",
                        r"onload=",
                        r"onmouseover=",
                        r"onclick=",
                        r"onfocus=",
                        r"onblur=",
                        r"<img",
                        r"<svg",
                        r"<iframe",
                        r"<object",
                        r"<embed",
                        r"<video",
                        r"<audio",
                        r"<details",
                        r"<marquee",
                        r"javascript:",
                        r"vbscript:",
                        r"data:text/html",
                        r"document\.cookie",
                        r"document\.write",
                        r"window\.location",
                        r"eval\(",
                        r"setTimeout",
                        r"setInterval",
                        r"innerHTML",
                        r"outerHTML",
                        r"srcdoc=",
                        r"base64,",
                        r"expression\(",
                        r"<body",
                        r"<link",
                        r"<meta",
                        r"<style",
                        r"&#x",
                        r"%3Cscript",
                        r"%3Cimg",
                        r"%3Csvg",
                        r"onkeydown=",
                        r"onkeyup=",
                        r"onmousedown=",
                        r"onmouseup=",
                        r"onmouseenter=",
                        r"onmouseleave=",
                        r"onwheel=",
                        r"oninput="
                    ],
                    target="path",
                    severity="high"
                )
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
            # self.signature_rules.append(
            #     SignatureRule("Remote Code Execution / Command Injection", r"(\b(cat|ls|whoami|curl|wget|bash|sh)\b|;|&&|\|)", target="body", severity="critical")
            # )
            self.signature_rules.append(
                SignatureRule(
                    "Remote Code Execution / Command Injection",
                    [
                        r";",
                        r"&&",
                        r"\|\|",
                        r"\|",
                        r"\bcat\b",
                        r"\bls\b",
                        r"\bwhoami\b",
                        r"\bpwd\b",
                        r"\bid\b",
                        r"\buname\b",
                        r"\bhostname\b",
                        r"\bwget\b",
                        r"\bcurl\b",
                        r"\bbash\b",
                        r"\bsh\b",
                        r"\bpython\b",
                        r"\bperl\b",
                        r"\bphp\b",
                        r"\bnode\b",
                        r"\bruby\b",
                        r"nc ",
                        r"netcat",
                        r"telnet",
                        r"chmod",
                        r"chown",
                        r"rm -rf",
                        r"mkfs",
                        r"dd if=",
                        r"scp ",
                        r"ssh ",
                        r"ftp ",
                        r"tftp ",
                        r"powershell",
                        r"cmd\.exe",
                        r"system\(",
                        r"exec\(",
                        r"shell_exec",
                        r"popen",
                        r"proc_open",
                        r"subprocess",
                        r"os\.system",
                        r"Runtime\.getRuntime",
                        r"ProcessBuilder",
                        r"/bin/sh",
                        r"/bin/bash",
                        r"/etc/passwd",
                        r"/etc/shadow",
                        r"\\.\\pipe\\",
                        r"\\windows\\system32",
                        r"\\boot\\.ini"
                    ],
                    target="body",
                    severity="critical"
                )
            )

        if enabled_rules.get("File Upload Abuse", False):
            self.signature_rules.append(
                SignatureRule("File Upload Abuse", r"\.(php|jsp|asp|exe|sh|js)", target="files", severity="high")
            )

        if enabled_rules.get("Insecure Deserialization", False):
            # self.signature_rules.append(
            #     SignatureRule("Insecure Deserialization", r"(pickle|object|javaSerialized|Y29tcGxleA==|__reduce__)", target="body", severity="critical")
            # )
            self.signature_rules.append(
                SignatureRule(
                    "Insecure Deserialization",
                    [
                        r"pickle",
                        r"cPickle",
                        r"__reduce__",
                        r"__reduce_ex__",
                        r"__setstate__",
                        r"__getstate__",
                        r"marshal",
                        r"yaml.load",
                        r"!!python/object",
                        r"!!python/object/apply",
                        r"!!python/module",
                        r"!!python/name",
                        r"!!python/object/new",
                        r"javaSerialized",
                        r"ACED0005",
                        r"rO0AB",
                        r"ObjectInputStream",
                        r"readObject",
                        r"writeObject",
                        r"Serializable",
                        r"java.io",
                        r"commons-collections",
                        r"InvokerTransformer",
                        r"TemplatesImpl",
                        r"Runtime.getRuntime",
                        r"ProcessBuilder",
                        r"ysoserial",
                        r"base64",
                        r"Y29tcGxleA==",
                        r"Y3JlYXRl",
                        r"application/x-java-serialized-object",
                        r"application/x-python-serialize",
                        r"application/x-pickle",
                        r"__class__",
                        r"__globals__",
                        r"__builtins__",
                        r"eval\(",
                        r"exec\(",
                        r"subprocess",
                        r"os.system",
                        r"system\(",
                        r"shell_exec",
                        r"php://input",
                        r"phar://",
                        r"unserialize\(",
                        r"serialize\(",
                        r"O:\d+:",
                        r"a:\d+:{",
                        r"s:\d+:",
                        r"b:\d+;",
                        r"i:\d+;",
                        r"d:\d+;",
                        r"C:\d+:",
                        r"N;"
                    ],
                    target="body",
                    severity="critical"
                )
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
        # Reload rules dynamically
        self.signature_rules.clear()
        self.threshold_rules.clear()
        self._load_default_rules()
 
        if "body" in log and isinstance(log["body"], dict):
            log.update(log["body"])
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
