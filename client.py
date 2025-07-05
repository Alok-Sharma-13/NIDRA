# from flask import Flask
# from sdk.nidra_sdk import NidraSDK, sniff_request_decorator  # ✅ Make sure this path is correct

# sdk = NidraSDK()
# sniff = sniff_request_decorator(sdk)

# app = Flask(__name__)

# @app.route("/shop")
# @sniff
# def shop():
#     return "Welcome to the shop!"

# @app.route("/login")
# @sniff
# def login():
#     return "Login page"

# if __name__ == "__main__":
#     app.run(port=6000)
import requests
import json

url = "http://127.0.0.1:5000/api/rules/analyze"
headers = {"Content-Type": "application/json"}
payload = {
    "ip_address": "192.168.1.99",
    "method": "GET",
    "path": "/",
    "headers": {"User-Agent": "Mozilla/5.0"}
}

for i in range(25):
    response = requests.post(url, headers=headers, data=json.dumps(payload))
    if response.status_code == 200:
        print(f"Request {i+1} -", response.json())
    else:
        print(f"Request {i+1} - Failed", response.status_code)
