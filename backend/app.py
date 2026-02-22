import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask_cors import CORS
from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from routes.auth_routes import auth_bp
from routes.log_routes import log_bp  
from routes.ip_block_routes import ip_blocker_bp
from core.traffic_sniffer import geoIP, sniff_request
from core.rule_engine import RuleEngine  
from backend.routes.rule_routes import rules_bp
from core.honeypot_manager import register_all_honeypots, manager as honeypot_manager
from core.alert_dispatcher import log_to_file  
from core.ip_blocker import IPBlocker 
from core.country_blocker import CountryBlocker   # ✅ ADDED
from routes.view import viewer_bp
from routes.country_routes import country_bp

import json

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": ["http://localhost:8551"],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    }
)

limiter = Limiter(get_remote_address)
limiter.init_app(app)
register_all_honeypots(app)

engine = RuleEngine()
rule_state = {}
country_blocker = CountryBlocker()   # ✅ ADDED


@app.before_request
def full_traffic_analysis():
    log = sniff_request(request)

    # 🔴 If request is excluded (e.g. /api/traffic), skip logging & analysis
    if log is None:
        return

    # ---------------- COUNTRY BLOCK CHECK ---------------- #
    ip = log.get("ip_address")
    if ip and not country_blocker.is_ip_allowed(ip):
        IPBlocker().block(ip)
        return "403 Forbidden - Country Blocked", 403
    # ----------------------------------------------------- #

    try:
        os.makedirs("data/log", exist_ok=True)
        with open("data/log/all_traffic.ndjson", "a") as f:
            f.write(json.dumps(log) + "\n")
    except Exception as e:
        print(f"[Logger] Failed to log all traffic: {e}")

    # Honeypot check
    visible_paths = [hp["path"] for hp in honeypot_manager.get_visible_honeypots()]
    if request.path in visible_paths:
        return honeypot_manager.handle_trigger(request.path)

    # Rule analysis
    alerts = engine.analyze(log, rule_state)
    if alerts:
        for alert in alerts:
            log_to_file(alert)


@app.teardown_appcontext
def close_geoip(exception=None):
    geoIP.close()

app.register_blueprint(auth_bp)
app.register_blueprint(log_bp)  
app.register_blueprint(rules_bp)
app.register_blueprint(ip_blocker_bp)  
app.register_blueprint(viewer_bp)
app.register_blueprint(country_bp)


# if __name__ == "__main__":
#     app.run(debug=True)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
