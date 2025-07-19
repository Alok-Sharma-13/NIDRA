import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from routes.auth_routes import auth_bp
from routes.log_routes import log_bp  
from core.traffic_sniffer import geoIP, sniff_request
from core.rule_engine import RuleEngine  
from backend.routes.rule_routes import rules_bp
from core.honeypot_manager import register_all_honeypots, manager as honeypot_manager
from core.alert_dispatcher import log_to_file  # to log alerts in events.json
import json

app = Flask(__name__)
limiter = Limiter(get_remote_address)
limiter.init_app(app)
register_all_honeypots(app)

engine = RuleEngine()
rule_state = {}

@app.before_request
def full_traffic_analysis():
    log = sniff_request(request)
    if log:
        visible_paths = [hp["path"] for hp in honeypot_manager.get_visible_honeypots()]
        if request.path in visible_paths:
            return honeypot_manager.handle_trigger(request.path)

        alerts = engine.analyze(log, rule_state)

        if alerts:
            for alert in alerts:
                log_to_file(alert)

        try:
            os.makedirs("data/log", exist_ok=True)
            with open("data/log/all_traffic.ndjson", "a") as f:
                f.write(json.dumps(log) + "\n")
        except Exception as e:
            print(f"[Logger] Failed to log all traffic: {e}")

@app.teardown_appcontext
def close_geoip(exception=None):
    geoIP.close()

app.register_blueprint(auth_bp)
app.register_blueprint(log_bp)  
app.register_blueprint(rules_bp)

if __name__ == "__main__":
    app.run(debug=True)
