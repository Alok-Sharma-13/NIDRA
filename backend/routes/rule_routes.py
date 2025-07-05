"""
Rules API Route for NIDRA
Applies rule engine on incoming traffic logs and returns alerts.

Author: Alok & Aditya
Date: July 2025
"""

from flask import Blueprint, request, jsonify
from core.rule_engine import RuleEngine
from typing import Dict
from datetime import datetime

rules_bp = Blueprint("rules", __name__)
engine = RuleEngine()

# Shared state for threshold-based rules (like IP flood detection)
rule_state: Dict[str, int] = {}

@rules_bp.route("/api/rules/analyze", methods=["POST"])
def analyze_log():
    """
    Accepts a traffic log and applies detection rules.

    Request:
        JSON body containing a single log entry.

    Response:
        JSON object with alerts triggered (if any).
    """
    try:
        log = request.get_json(force=True)

        if not log:
            return jsonify({"success":False, "error":"Invalid or empty log data"}), 400
        
        # Adding server-side timestamp if missing 
        if "timestamp" not in log:
            log["timestamp"] = datetime.utcnow().isoformat()

        alerts = engine.analyze(log, rule_state)

        return jsonify({
            "success":True,
            "alerts":alerts,
            "message":f"{len(alerts)} alert(s) triggered"
        }),200

    except Exception as e:
        return jsonify({"success":False, "error": str(e)}),500
        