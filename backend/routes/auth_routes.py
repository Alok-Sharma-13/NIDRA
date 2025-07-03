from flask import Blueprint, jsonify, request
from security.auth_manager import verify

auth_bp = Blueprint("auth", __name__)

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and Password required"}), 400

    if verify(username, password):
        return jsonify({"success": True, "message": "Login Successful"}), 200
    else:
        return jsonify({"success": False, "message": "Invalid Credentials"}), 401

@auth_bp.route('/api/logout', methods=['POST'])
def logout():
    return jsonify({"success": True, "message": "Logged out successfully"}), 200
