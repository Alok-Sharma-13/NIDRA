"""
Rules API Route for NIDRA
Applies rule engine on incoming traffic logs and returns alerts.

Author: Alok 
Date: July 2025
"""

from flask import Blueprint, request, jsonify
from core.rule_engine import RuleEngine
from core.alert_dispatcher import log_to_file, send_dashboard
from typing import Dict
from datetime import datetime
from core.ip_blocker import IPBlocker

rules_bp = Blueprint("rules", __name__)
engine = RuleEngine()

# Shared state for threshold-based rules (like IP flood detection)
rule_state: Dict[str, int] = {}

@rules_bp.route("/api/rules/analyze", methods=["POST"])
def analyze_log():

    try:
        logs = request.get_json(force=True)

        if not logs or not isinstance(logs, list):
            return jsonify({"success": False, "error": "Request body must be a list of logs"}), 400

        all_alerts = []
        blocked = False
        ip_blocker = IPBlocker()

        for log in logs:
            if "timestamp" not in log:
                log["timestamp"] = datetime.utcnow().isoformat()

            alerts = engine.analyze(log, rule_state)

            for alert in alerts:
                full_alert = {**alert, **log}

                log_to_file(full_alert)
                send_dashboard(full_alert)
                all_alerts.append(full_alert)

                # 🔥 BLOCK ON HIGH OR CRITICAL
                if alert.get("severity") in ["high", "critical"]:
                    ip = log.get("ip_address")
                    if ip:
                        ip_blocker.block(ip)
                        blocked = True

        return jsonify({
            "success": True,
            "alerts": all_alerts,
            "blocked": blocked,
            "message": f"{len(all_alerts)} alert(s) triggered"
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
        