import os
import json
import geoip2.database

COUNTRY_JSON = "data/country.json"
GEOIP_DB = "GeoLite2-Country.mmdb"

class CountryBlocker:
    def __init__(self):
        # Ensure necessary folders exist
        os.makedirs("data", exist_ok=True)

        # Load country allow/block rules
        self.rules = self._load_rules()

        # Load MaxMind GeoIP database
        try:
            self.geo = geoip2.database.Reader(GEOIP_DB)
        except FileNotFoundError:
            raise Exception(f"GeoIP database not found: {GEOIP_DB}")

    # -----------------------------
    # JSON RULES LOAD & SAVE
    # -----------------------------
    def _load_rules(self):
        """Load country rules from data/country.json"""
        if not os.path.exists(COUNTRY_JSON):
            raise Exception(f"{COUNTRY_JSON} file not found!")
        
        with open(COUNTRY_JSON, "r") as f:
            return json.load(f)

    def _save_rules(self):
        """Save updated rules back to data/country.json"""
        with open(COUNTRY_JSON, "w") as f:
            json.dump(self.rules, f, indent=4)

    # -----------------------------
    # COUNTRY BLOCKING FUNCTIONS
    # -----------------------------
    def block_country(self, iso):
        iso = iso.upper()
        if iso not in self.rules:
            return False
        
        self.rules[iso]["allowed"] = False
        self._save_rules()
        print(f"[CountryBlocker] Blocked country: {iso}")
        return True

    def unblock_country(self, iso):
        iso = iso.upper()
        if iso not in self.rules:
            return False
        
        self.rules[iso]["allowed"] = True
        self._save_rules()
        print(f"[CountryBlocker] Unblocked country: {iso}")
        return True

    def is_country_allowed(self, iso):
        iso = iso.upper()
        if iso not in self.rules:
            return True   # default allow if country not found
        
        return self.rules[iso]["allowed"]

    # -----------------------------
    # IP → COUNTRY CHECK
    # -----------------------------
    def get_country_from_ip(self, ip: str):
        """Return ISO country code from IPv4/IPv6"""
        try:
            result = self.geo.country(ip)
            return result.country.iso_code  # US, IN, CN etc.
        except:
            return None

    def is_ip_allowed(self, ip: str):
        """Check if an IP belongs to an allowed country"""
        iso = self.get_country_from_ip(ip)

        if iso is None:
            return True  # If lookup fails, allow by default

        return self.is_country_allowed(iso)

    # -----------------------------
    # GET FULL RULE LIST
    # -----------------------------
    def get_rules(self):
        return self.rules
