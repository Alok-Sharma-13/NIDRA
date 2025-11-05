# NIDRA — Network Intrusion Detection & Response Assistant

**Developed by**

* Alok Sharma
* Aditya Yadav

---

## 📘 Project Title

**NIDRA — Network Intrusion Detection & Response Assistant**

---

## 🔎 Project Summary

NIDRA is an intelligent intrusion detection and response assistant designed to detect, analyze, and respond to malicious HTTP requests and network activity targeting web applications. Combining traffic sniffing, a configurable rule engine, honeypot traps and alerting, NIDRA is aimed at both real-time defensive actions (blocking, honeypot triggers) and forensic logging for later analysis.

Key capabilities:

* Inspect incoming HTTP requests (headers, query strings, payload)
* Detect common web attacks (XSS, SQLi, automated scanners)
* Trap attackers with honeypot endpoints and record their activity
* Dispatch alerts and persist logs for review
* Provide a developer-friendly Python SDK for easy integration into applications

---

## 🎯 Objectives

* Build a modular SDK to capture and analyze HTTP requests in client apps.
* Implement honeypot endpoints that attract malicious probes and reveal attacker behavior.
* Provide a rule-based engine to detect known malicious patterns (signatures, regex rules).
* Log traffic and alerts in structured formats for auditing and visualization.
* Support both active (block, alert) and passive (logging) defensive workflows.

---

## 🏗 System Architecture (High-level)

NIDRA follows a layered architecture:

1. **SDK / Client Layer**

   * `sdk/nidra_sdk.py` provides a decorator and helper functions to capture requests within a web app.
   * The SDK extracts request metadata (IP, path, headers, UA, body) and forwards structured logs to the backend or the local rule engine.

2. **Backend Layer (Flask)**

   * `backend/app.py` hosts API endpoints, registers honeypots, and connects routing logic with the rule engine and alert dispatcher.
   * Modules under `backend/routes/` expose administration, logging and rule management endpoints.

3. **Core Analysis Layer**

   * `core/traffic_sniffer.py` normalizes and extracts request attributes.
   * `core/rule_engine.py` runs configurable detection logic and raises alerts.
   * `core/honeypot_manager.py` registers protected/honeypot endpoints and handles triggers.
   * `core/alert_dispatcher.py` writes alerts to `data/log/` and prints dashboard-ready messages.

4. **Persistence & Logs**

   * All traffic and alerts are stored under `data/log/` in NDJSON/JSON formats for indexing, review or offline analytics.

---

## 📂 Repository Structure (representative)

NIDRA/
├── backend/
│   ├── app.py
│   ├── database_config.py
│   └── routes/
├── core/
│   ├── traffic_sniffer.py
│   ├── rule_engine.py
│   ├── honeypot_manager.py
│   └── alert_dispatcher.py
├── sdk/
│   └── nidra_sdk.py
├── dashboard/
├── data/
│   └── log/
├── test.json
└── README.md

---

## ⚙️ Requirements

* Python 3.10+
* Flask
* requests
  (Optional: scapy / pyshark for packet-level capture)

Install dependencies:

```bash
pip install -r requirements.txt
```

If you don’t have a `requirements.txt`, install directly:

```bash
pip install flask requests
```

---

## 🚀 Quick Start (Local Testing)

1. From project root:

```bash
cd F:\NIDRA
```

2. Run the backend:

```bash
python backend/app.py
```

or

```bash
python -m backend.app
```

3. Test API endpoints:

* Home / Health: `GET http://127.0.0.1:5000/status`
* Honeypot Example: `/admin/api/v1/user/u1/info/name`
* Rule Analysis: `POST http://127.0.0.1:5000/api/rules/analyze`

---

## 🧪 Testing With `test.json`

A ready-made `test.json` dataset contains simulated request logs.
Replay the data using the included Python runner:

```bash
python replay_to_analyze.py
```

Or using curl:

```bash
curl -X POST http://127.0.0.1:5000/api/rules/analyze \
  -H "Content-Type: application/json" --data-binary "@test.json"
```

---

## 🛡 Honeypots & Rules

* **Honeypots**: Hidden routes that legitimate users never access; requests here are logged as malicious.
* **Rule Engine**: Regex or signature-based analyzer in `core/rule_engine.py` identifies XSS, SQLi, brute-force, and custom attack patterns.
* **Alerts**: Logged via `core/alert_dispatcher.py` → `data/log/events.json`.

---

## 🧩 SDK Integration Example

```python
from sdk.nidra_sdk import NIDRASDK, sniff_request_decorator

sdk = NIDRASDK()
sniffer = sniff_request_decorator(sdk)

@app.route("/login", methods=["POST"])
@sniffer
def login():
    return "Login endpoint active"
```

---

## 🔍 Logs & Alerts

| Log Type     | File Location                 |
| ------------ | ----------------------------- |
| All traffic  | `data/log/all_traffic.ndjson` |
| Alert events | `data/log/events.json`        |
| Blocked IPs  | `data/log/blocked_ips.txt`    |

---

## 🧠 Development Notes

* If `ImportError: cannot import name 'DB_TYPE' from 'config'` occurs, rename your local `config.py` to `app_config.py` to avoid conflict with the `config` PyPI package.
* Always run scripts from the project root.
* Use `python -m backend.app` to respect package paths.

---

## ✅ Git Branching & Deployment

Branches:

* `alok` → Development
* `main` → Stable release

To merge:

```bash
git checkout main
git merge alok
git push origin main
```

---

## 📚 References

* OWASP Top 10 — Web Security Guidelines
* Flask Documentation
* Common Regex Rules for SQLi & XSS Detection

---

## 👥 Developers

* **Alok Sharma**
* **Aditya Yadav**

