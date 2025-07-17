import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from routes.auth_routes import auth_bp
from routes.log_routes import log_bp  
from core.traffic_sniffer import geoIP  
from backend.routes.rule_routes import rules_bp
from core.honeypot_manager import register_all_honeypots, manager as honeypot_manager


app = Flask(__name__)
limiter = Limiter(get_remote_address)
limiter.init_app(app)
register_all_honeypots(app)
@app.before_request
def check_honeypots():
    visible_paths = [hp["path"] for hp in honeypot_manager.get_visible_honeypots()]
    if request.path in visible_paths:
        return honeypot_manager.handle_trigger(request.path)

# This id for GeoIP 
@app.teardown_appcontext
def close_geoip(exception=None):
    geoIP.close()

app.register_blueprint(auth_bp)
app.register_blueprint(log_bp)  
app.register_blueprint(rules_bp)

if __name__ == "__main__":
    app.run(debug=True)
