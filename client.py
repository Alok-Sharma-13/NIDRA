from flask import Flask
from sdk.nidra_sdk import NidraSDK, sniff_request_decorator  # ✅ Make sure this path is correct

sdk = NidraSDK()
sniff = sniff_request_decorator(sdk)

app = Flask(__name__)

@app.route("/shop")
@sniff
def shop():
    return "Welcome to the shop!"

@app.route("/login")
@sniff
def login():
    return "Login page"

if __name__ == "__main__":
    app.run(port=6000)
