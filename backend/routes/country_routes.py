from flask import Blueprint, request, jsonify
from core.country_blocker import CountryBlocker

country_bp = Blueprint("country", __name__)
country_blocker = CountryBlocker()


# -----------------------------------
# GET ALL COUNTRY RULES
# -----------------------------------
@country_bp.route("/api/countries", methods=["GET"])
def get_countries():
    return jsonify({
        "success": True,
        "data": country_blocker.get_rules()
    })


# -----------------------------------
# BLOCK COUNTRY
# -----------------------------------
@country_bp.route("/api/countries/block", methods=["POST"])
def block_country():
    data = request.get_json()

    if not data or "iso" not in data:
        return jsonify({"success": False, "error": "ISO code required"}), 400

    iso = data["iso"]

    if country_blocker.block_country(iso):
        return jsonify({"success": True, "message": f"{iso} blocked"})
    
    return jsonify({"success": False, "error": "Country not found"}), 404


# -----------------------------------
# UNBLOCK COUNTRY
# -----------------------------------
@country_bp.route("/api/countries/unblock", methods=["POST"])
def unblock_country():
    data = request.get_json()

    if not data or "iso" not in data:
        return jsonify({"success": False, "error": "ISO code required"}), 400

    iso = data["iso"]

    if country_blocker.unblock_country(iso):
        return jsonify({"success": True, "message": f"{iso} unblocked"})
    
    return jsonify({"success": False, "error": "Country not found"}), 404