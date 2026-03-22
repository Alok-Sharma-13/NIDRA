import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask_cors import CORS
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from routes.auth_routes import auth_bp
from routes.log_routes import log_bp
from routes.ip_block_routes import ip_blocker_bp
from routes.view import viewer_bp
from routes.country_routes import country_bp

from core.traffic_sniffer import geoIP, sniff_request
from core.rule_engine import RuleEngine
from core.honeypot_manager import register_all_honeypots, manager as honeypot_manager
from core.alert_dispatcher import log_to_file
from core.ip_blocker import IPBlocker
from core.country_blocker import CountryBlocker

from backend.routes.rule_routes import rules_bp
from backend.database_config import engine
from sqlalchemy import text

import json


# ===============================
# Helper function for real IP
# ===============================
def get_real_ip(req):
    forwarded = req.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return req.remote_addr


app = Flask(__name__)

# ===============================
# CORS
# ===============================
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": ["http://localhost:5173"],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    }
)

# ===============================
# Rate Limiter
# ===============================
limiter = Limiter(get_remote_address)
limiter.init_app(app)

# ===============================
# Honeypots
# ===============================
register_all_honeypots(app)

rule_engine = RuleEngine()
rule_state = {}

ip_blocker = IPBlocker()
country_blocker = CountryBlocker()


# =====================================================
# 1️⃣ BLOCKED IP CHECK
# =====================================================
@app.before_request
def check_blocked_ip_first():

    ip = get_real_ip(request)

    ALLOWED_WHEN_BLOCKED = (
        "/api/traffic",
        "/api/events",
        "/api/blocked-ips"
    )

    if ip_blocker.is_blocked(ip):
        if not request.path.startswith(ALLOWED_WHEN_BLOCKED):
            return jsonify({
                "error": "403 Forbidden - IP Blocked by NIDRA"
            }), 403


# =====================================================
# 2️⃣ TRAFFIC ANALYSIS
# =====================================================
@app.before_request
def full_traffic_analysis():

    log = sniff_request(request)

    if log is None:
        return

    # 🔥 single IP source
    ip = get_real_ip(request)
    log["ip_address"] = ip

    # ---------------- COUNTRY BLOCK ----------------
    if ip and not country_blocker.is_ip_allowed(ip):
        ip_blocker.block(ip)
        return "403 Forbidden - Country Blocked", 403

    # ---------------- TRAFFIC LOGGING ----------------
    try:
        os.makedirs("data/log", exist_ok=True)

        with open("data/log/all_traffic.ndjson", "a") as f:
            f.write(json.dumps(log) + "\n")

        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO traffic_logs
                (timestamp, ip_address, country, method, path, user_agent)
                VALUES
                (:timestamp, :ip, :country, :method, :path, :ua)
            """), {
                "timestamp": log.get("timestamp"),
                "ip": ip,
                "country": log.get("country"),
                "method": log.get("method"),
                "path": log.get("path"),
                "ua": log.get("user_agent")
            })

    except Exception as e:
        print(f"[Logger] Failed to log all traffic: {e}")

    # ---------------- HONEYPOT CHECK ----------------
    visible_paths = [hp["path"] for hp in honeypot_manager.get_visible_honeypots()]

    if request.path in visible_paths:
        return honeypot_manager.handle_trigger(request.path)

    # ---------------- RULE ENGINE ----------------
    alerts = rule_engine.analyze(log, {})

    if alerts:

        should_block = False

        for alert in alerts:
            log_to_file(alert)

            if alert.get("severity") in ["high", "critical"]:
                should_block = True

        # 🔥 block AFTER logging but BEFORE return
        if should_block:
            attacker_ip = log.get("ip_address")

            # ALWAYS block (even if duplicate)
            ip_blocker.block(attacker_ip)

            return jsonify({
                "error": "Blocked by NIDRA",
                "severity": "critical"
            }), 403


# =====================================================
# CLOSE GEOIP DATABASE
# =====================================================
@app.teardown_appcontext
def close_geoip(exception=None):
    geoIP.close()


# =====================================================
# REGISTER ROUTES
# =====================================================
app.register_blueprint(auth_bp)
app.register_blueprint(log_bp)
app.register_blueprint(rules_bp)
app.register_blueprint(ip_blocker_bp)
app.register_blueprint(viewer_bp)
app.register_blueprint(country_bp)


# =====================================================
# RUN SERVER
# =====================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)