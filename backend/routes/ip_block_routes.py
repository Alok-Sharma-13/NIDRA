from flask import Blueprint, request, jsonify
from core.ip_blocker import IPBlocker
from backend.database_config import engine
from sqlalchemy import text

ip_blocker_bp = Blueprint("ip_blocker", __name__)
ip_blocker = IPBlocker()


# =====================================
# FILE VERSION (existing)
# =====================================

@ip_blocker_bp.route("/api/blocked-ips", methods=["GET"])
def get_blocked_ips():
    return jsonify({
        "success": True,
        "data": ip_blocker.get_blocked_ips()
    }), 200


@ip_blocker_bp.route("/api/blocked-ips", methods=["POST"])
def block_ip():
    data = request.get_json()
    ip = data.get("ip")

    if not ip:
        return jsonify({
            "success": False,
            "error": "IP required"
        }), 400

    ip_blocker.block(ip)

    return jsonify({
        "success": True,
        "message": f"{ip} blocked"
    }), 200


@ip_blocker_bp.route("/api/blocked-ips/<ip>", methods=["DELETE"])
def delete_blocked_ip(ip):

    ip_blocker.unblock(ip)

    return jsonify({
        "success": True,
        "message": f"{ip} removed from block list"
    }), 200


# =====================================
# DB VERSION
# =====================================

# GET FROM DB
@ip_blocker_bp.route("/api/blocked-ips/db", methods=["GET"])
def get_blocked_ips_db():

    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT ip_address, blocked_at
                FROM blocked_ips
                ORDER BY blocked_at DESC
            """))

            rows = [dict(row._mapping) for row in result]

        return jsonify({
            "success": True,
            "data": rows
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# BLOCK IN DB
@ip_blocker_bp.route("/api/blocked-ips/db", methods=["POST"])
def block_ip_db():

    data = request.get_json()
    ip = data.get("ip")

    if not ip:
        return jsonify({
            "success": False,
            "error": "IP required"
        }), 400

    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO blocked_ips (ip_address)
                VALUES (:ip)
                ON CONFLICT (ip_address) DO NOTHING
            """), {"ip": ip})

        return jsonify({
            "success": True,
            "message": f"{ip} blocked (DB)"
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# DELETE FROM DB
@ip_blocker_bp.route("/api/blocked-ips/db/<ip>", methods=["DELETE"])
def delete_blocked_ip_db(ip):

    try:
        with engine.begin() as conn:
            conn.execute(text("""
                DELETE FROM blocked_ips
                WHERE ip_address = :ip
            """), {"ip": ip})

        return jsonify({
            "success": True,
            "message": f"{ip} removed from DB"
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500