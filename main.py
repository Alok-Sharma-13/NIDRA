from flask import Flask
from core.honeypot_manager import register_honeypots

app = Flask(__name__)

# Register honeypot routes dynamically
register_honeypots(app)

@app.route("/")
def home():
    return "Welcome to NIDRA!"

if __name__ == "__main__":
    app.run(port=5000)
