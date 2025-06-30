"""
GeoIP Lookup Module for NIDRA SDK
Provides functions to lookup the country for a given IP address using MaxMind GeoLite2 database.

Author: Alok & Aditya
Date: June 2025
"""

import geoip2.database
import os

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'GeoLite2-Country.mmdb'))

class GeoIPService:
    def __init__(self, db_path: str = DB_PATH):
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"GeoIP database not found at: {db_path}")
        self.reader = geoip2.database.Reader(db_path)

    def lookup_country(self, ip_address: str) -> str:
        """
        Returns the country name for a given IP address.
        If not found or invalid, returns 'Unknown' or 'Invalid IP'.
        """
        try:
            response = self.reader.country(ip_address)
            return response.country.name or "Unknown"
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except ValueError:
            return "Invalid IP"

    def close(self):
        """Closes the GeoIP database reader."""
        self.reader.close()
