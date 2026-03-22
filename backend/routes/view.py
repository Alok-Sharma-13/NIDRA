from flask import Blueprint, request, jsonify
import json
import os
from backend.database_config import engine
from sqlalchemy import text

viewer_bp = Blueprint("viewer", __name__)

# FIX: point to project root
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

LOG_DIR = os.path.join(BASE_DIR, "data", "log")

EVENTS_FILE = os.path.join(LOG_DIR, "events.json")
TRAFFIC_FILE = os.path.join(LOG_DIR, "all_traffic.ndjson")
BLOCKED_IPS_FILE = os.path.join(LOG_DIR, "blocked_ips.txt")
RULES_FILE = os.path.join(BASE_DIR, "data", "rules.json")

@viewer_bp.route("/api/events", methods=["GET"])
def get_events():
    start = int(request.args.get("start", 0))
    limit = int(request.args.get("limit", 20))

    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as f:
            events = json.load(f)
    except FileNotFoundError:
        events = []

    return jsonify({
        "success": True,
        "data": events[start:start + limit]
    })

#same api above and below or events

@viewer_bp.route("/api/events/db", methods=["GET"])
def get_events_db():

    start = int(request.args.get("start", 0))
    limit = int(request.args.get("limit", 20))

    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT *
                FROM events
                ORDER BY timestamp DESC
                LIMIT :limit OFFSET :start
            """), {"limit": limit, "start": start})

            rows = [dict(row._mapping) for row in result]

        return jsonify({
            "success": True,
            "data": rows
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@viewer_bp.route("/api/traffic", methods=["GET"])
def get_traffic():
    start = int(request.args.get("start", 0))
    limit = int(request.args.get("limit", 50))

    # print("DEBUG TRAFFIC FILE PATH:", TRAFFIC_FILE)
    # print("FILE EXISTS:", os.path.exists(TRAFFIC_FILE))

    logs = []
    try:
        with open(TRAFFIC_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    logs.append(json.loads(line))

        logs.reverse()

    except Exception as e:
        print("ERROR READING TRAFFIC FILE:", e)

    return jsonify({
        "success": True,
        "data": logs[start:start + limit]
    })

#the below and up api are same but above one is for json and below one is for db 
@viewer_bp.route("/api/traffic/db", methods=["GET"])
def get_traffic_db():

    start = int(request.args.get("start", 0))
    limit = int(request.args.get("limit", 50))

    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT *
                FROM traffic_logs
                ORDER BY timestamp DESC
                LIMIT :limit OFFSET :start
            """), {"limit": limit, "start": start})

            rows = [dict(row._mapping) for row in result]

        return jsonify({
            "success": True,
            "data": rows
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# @viewer_bp.route("/api/blocked-ips", methods=["GET"])
# def get_blocked_ips():
#     try:
#         with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
#             ips = [line.strip() for line in f if line.strip()]
#     except FileNotFoundError:
#         ips = []

#     return jsonify({
#         "success": True,
#         "data": ips
#     })


@viewer_bp.route("/api/rules/update", methods=["POST"])
def update_rule():

    data = request.get_json()
    rule_name = data.get("rule")
    enabled = data.get("enabled")

    try:
        # read existing rules
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            rules = json.load(f)

        # update only the specific rule
        if rule_name in rules["enabled_rules"]:
            rules["enabled_rules"][rule_name] = enabled

        # write back to file
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2)

        return jsonify({"success": True, "message": "Rule updated"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    

@viewer_bp.route("/api/events/db/ip/<ip>", methods=["GET"])
def get_events_by_ip(ip):

    start = int(request.args.get("start", 0))
    limit = int(request.args.get("limit", 50))

    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT *
                FROM events
                WHERE ip_address = :ip
                ORDER BY timestamp DESC
                LIMIT :limit OFFSET :start
            """), {
                "ip": ip,
                "limit": limit,
                "start": start
            })

            rows = [dict(row._mapping) for row in result]

        return jsonify({
            "success": True,
            "ip": ip,
            "data": rows
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500