import json
import os
from datetime import datetime
from sqlalchemy import text
from backend.database_config import engine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EVENTS_FILE = os.path.join(BASE_DIR, "data", "log", "events.json")
TRAFFIC_FILE = os.path.join(BASE_DIR, "data", "log", "all_traffic.ndjson")
BLOCKED_FILE = os.path.join(BASE_DIR, "data", "log", "blocked_ips.txt")


def sync_events():
    if not os.path.exists(EVENTS_FILE):
        return

    with open(EVENTS_FILE, "r", encoding="utf-8") as f:
        events = json.load(f)

    with engine.begin() as conn:
        for e in events:
            conn.execute(text("""
                INSERT INTO events 
                (rule, description, severity, timestamp, ip_address, country, method, path, user_agent)
                VALUES 
                (:rule, :description, :severity, :timestamp, :ip, :country, :method, :path, :ua)
                ON CONFLICT DO NOTHING
            """), {
                "rule": e.get("rule"),
                "description": e.get("description"),
                "severity": e.get("severity"),
                "timestamp": e.get("timestamp"),
                "ip": e.get("ip_address"),
                "country": e.get("country"),
                "method": e.get("method"),
                "path": e.get("path"),
                "ua": e.get("user_agent")
            })

    print("Events synced")


def sync_traffic():
    if not os.path.exists(TRAFFIC_FILE):
        return

    with open(TRAFFIC_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    with engine.begin() as conn:
        for line in lines:
            t = json.loads(line.strip())

            conn.execute(text("""
                INSERT INTO traffic_logs
                (timestamp, ip_address, country, method, path, user_agent)
                VALUES
                (:timestamp, :ip, :country, :method, :path, :ua)
            """), {
                "timestamp": t.get("timestamp"),
                "ip": t.get("ip_address"),
                "country": t.get("country"),
                "method": t.get("method"),
                "path": t.get("path"),
                "ua": t.get("user_agent")
            })

    print("Traffic synced")


def sync_blocked():
    if not os.path.exists(BLOCKED_FILE):
        return

    with open(BLOCKED_FILE, "r", encoding="utf-8") as f:
        ips = [line.strip() for line in f if line.strip()]

    with engine.begin() as conn:
        for ip in ips:
            conn.execute(text("""
                INSERT INTO blocked_ips (ip_address)
                VALUES (:ip)
                ON CONFLICT (ip_address) DO NOTHING
            """), {"ip": ip})

    print("Blocked IPs synced")


if __name__ == "__main__":
    sync_events()
    sync_traffic()
    sync_blocked()
    print("All data synced successfully")