import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from routes.auth_routes import auth_bp
from routes.log_routes import log_bp  

app = Flask(__name__)
limiter = Limiter(get_remote_address)
limiter.init_app(app)

app.register_blueprint(auth_bp)
app.register_blueprint(log_bp)  

if __name__ == "__main__":
    app.run(debug=True)
