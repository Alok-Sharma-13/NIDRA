"""
Traffic Sniffer for NIDRA
Captures incoming request metadata for logging and threat analysis.

Author: Alok 
Date: June 2025
"""

from datetime import datetime
from core.geoip_lookup import GeoIPService


geoIP = GeoIPService()

def sniff_request(request):
    """
    Extracts key metadata from the incoming HTTP request.

    Parameters:
        request (Flask/FastAPI Request): The incoming HTTP request object.

    Returns:
        dict: A structured log containing request metadata.
    """

    try:
        ip_address = (
            request.headers.get("X-Forwarded-For")
            or request.remote_addr
            or request.client.host  # For FastAPI
        )
        
        country = geoIP.lookup_country(ip_address)

        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "ip_address": ip_address,
            "country": country,
            "method": request.method,
            "path": request.path if hasattr(request, "path") else str(request.url.path),
            "headers": dict(request.headers),
            "user_agent": request.headers.get("User-Agent", "Unknown"),
        }

        return log_data

    except Exception as e:
        print(f"[Sniffer Error] Failed to extract request data: {e}")
        return None
