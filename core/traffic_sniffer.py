"""
Traffic Sniffer for NIDRA
Captures incoming request metadata for logging and threat analysis.

Author: Alok 
Date: June 2025
"""

from datetime import datetime
from core.geoip_lookup import GeoIPService

geoIP = GeoIPService()

# APIs we do NOT want to log
EXCLUDED_PREFIXES = (
    "/api/traffic",
    "/api/events",
    "/api/blocked-ips",
    "/api/rules",
)


def sniff_request(request):
    """
    Extracts key metadata from the incoming HTTP request.
    """

    try:
        path = request.path if hasattr(request, "path") else str(request.url.path)

        # 🔴 Skip internal NIDRA APIs
        if path.startswith(EXCLUDED_PREFIXES):
            return None

        # 🔹 Detect real client IP behind proxies
        forwarded = request.headers.get("X-Forwarded-For")

        if forwarded:
            ip_address = forwarded.split(",")[0].strip()
        else:
            ip_address = request.remote_addr

        # 🔹 If request comes from SDK analyze endpoint, extract client data
        if path == "/api/rules/analyze":
            try:
                data = request.get_json()

                if isinstance(data, list) and len(data) > 0:
                    client_data = data[0]

                    client_path = client_data.get("path")
                    if client_path:
                        path = client_path

                    client_ip = client_data.get("ip_address")
                    if client_ip:
                        ip_address = client_ip

            except Exception:
                pass

        country = geoIP.lookup_country(ip_address)

        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": ip_address,
            "country": country,
            "method": request.method,
            "path": path,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
        }

        return log_data

    except Exception as e:
        print(f"[Sniffer Error] Failed to extract request data: {e}")
        return None