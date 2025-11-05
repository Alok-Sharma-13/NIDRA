from flask import Flask, request
from core.traffic_sniffer import sniff_request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = sniff_request(request)

    print("Sniffed Request:")
    print(result)

    return "Request sniffed! Check your terminal."

if __name__ == "__main__":
    app.run(debug=True)
