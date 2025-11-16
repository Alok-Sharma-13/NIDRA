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


# ---------------------- COUNTRY BLOCKING ------------------------ #

@ip_blocker_bp.route("/api/country/block", methods=["POST"])
def block_country():
    data = request.get_json()
    iso = data.get("country")

    if not iso:
        return jsonify({"success": False, "error": "Country ISO missing"}), 400

    ok = country_blocker.block_country(iso)
    if not ok:
        return jsonify({"success": False, "error": "Invalid country code"}), 400

    return jsonify({"success": True, "message": f"Country {iso} blocked"}), 200


@ip_blocker_bp.route("/api/country/unblock", methods=["POST"])
def unblock_country():
    data = request.get_json()
    iso = data.get("country")

    if not iso:
        return jsonify({"success": False, "error": "Country ISO missing"}), 400

    ok = country_blocker.unblock_country(iso)
    if not ok:
        return jsonify({"success": False, "error": "Invalid country code"}), 400

    return jsonify({"success": True, "message": f"Country {iso} allowed"}), 200


@ip_blocker_bp.route("/api/country/list", methods=["GET"])
def list_countries():
    return jsonify({"countries": country_blocker.get_rules()}), 200
