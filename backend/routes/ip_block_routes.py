from flask import Blueprint, request, jsonify
from core.ip_blocker import IPBlocker

ip_blocker_bp = Blueprint("ip_blocker", __name__)
ip_blocker = IPBlocker()


# =====================================
# GET ALL BLOCKED IPS
# =====================================
@ip_blocker_bp.route("/api/blocked-ips", methods=["GET"])
def get_blocked_ips():
    return jsonify({
        "success": True,
        "data": ip_blocker.get_blocked_ips()
    }), 200


# =====================================
# BLOCK IP
# =====================================
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


# =====================================
# DELETE (UNBLOCK) IP
# =====================================
@ip_blocker_bp.route("/api/blocked-ips/<ip>", methods=["DELETE"])
def delete_blocked_ip(ip):

    ip_blocker.unblock(ip)

    return jsonify({
        "success": True,
        "message": f"{ip} removed from block list"
    }), 200