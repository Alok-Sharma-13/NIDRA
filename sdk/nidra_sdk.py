import requests
from functools import wraps
from flask import request
from datetime import datetime

NIDRA_BACKEND = "http://localhost:8000"


class NidraSDK:
    def __init__(self):
        pass

    def capture_request(self, request_obj):
        try:
            log_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "ip_address": request_obj.headers.get("X-Forwarded-For") or request_obj.remote_addr,
                "method": request_obj.method,
                "path": request_obj.path,
                "headers": dict(request_obj.headers),
                "user_agent": request_obj.headers.get("User-Agent", "Unknown"),
                # DO NOT send country
                # Backend will calculate it
            }

            requests.post(
                f"{NIDRA_BACKEND}/api/rules/analyze",
                json=[log_data],  # backend expects list
                timeout=2
            )

        except Exception as e:
            print(f"[NIDRA SDK] Failed to send log: {e}")

        return None


def sniff_request_decorator(sdk_instance):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            sdk_instance.capture_request(request)
            return func(*args, **kwargs)
        return wrapper
    return decorator