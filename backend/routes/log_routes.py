from flask import Blueprint, request, jsonify
from core.traffic_sniffer import sniff_request
from config import DB_TYPE
from backend.database_config import db, SessionLocal
from datetime import datetime

log_bp = Blueprint("logs", __name__)

@log_bp.route("/api/log", methods=["POST"])
def receive_log():
    try:
        log_data = request.get_json()

        # Add server-side timestamp if not provided
        if "timestamp" not in log_data:
            log_data["timestamp"] = datetime.utcnow().isoformat()

        if DB_TYPE == "mongodb":
            # db.logs.insert_one(log_data)
            print("[Mock DB] Log received:", log_data)
        elif DB_TYPE == "postgresql":
            session = SessionLocal()
            try:
                # PostgreSQL schema expected: logs table with JSON field "data"
                session.execute(
                    "INSERT INTO logs (data) VALUES (:data)", {"data": log_data}
                )
                session.commit()
            finally:
                session.close()
        else:
            return jsonify({"success": False, "error": "Unsupported DB_TYPE"}), 500

        return jsonify({"success": True, "message": "Log stored successfully."}), 201

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
