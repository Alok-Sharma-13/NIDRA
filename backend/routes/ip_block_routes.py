from flask import Blueprint, request, jsonify
from core.ip_blocker import IPBlocker
from core.country_blocker import CountryBlocker

ip_blocker = IPBlocker()
country_blocker = CountryBlocker()

ip_blocker_bp = Blueprint("ip_blocker", __name__)

# ------------------------- IP BLOCKING ------------------------- #

@ip_blocker_bp.route("/api/block", methods=["POST"])
def block_ip():
    data = request.get_json()
    ip = data.get("ip")
    if ip:
        ip_blocker.block(ip)
        return jsonify({"success": True, "message": f"{ip} blocked"}), 200
    return jsonify({"success": False, "error": "IP not provided"}), 400


@ip_blocker_bp.route("/api/unblock", methods=["POST"])
def unblock_ip():
    data = request.get_json()
    ip = data.get("ip")
    if ip:
        ip_blocker.unblock(ip)
        return jsonify({"success": True, "message": f"{ip} unblocked"}), 200
    return jsonify({"success": False, "error": "IP not provided"}), 400


@ip_blocker_bp.route("/api/blocked_ips", methods=["GET"])
def get_blocked_ips():
    return jsonify({"blocked_ips": ip_blocker.get_blocked_ips()}), 200


