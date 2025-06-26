"""
Project configuration loader using .env file (dotenv).

Author: Alok & Aditya
Date: June 2025

"""

from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# ==== Database Config ====
DB_TYPE = os.getenv("DB_TYPE", "postgresql")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
POSTGRES_URI = os.getenv("POSTGRES_URI", "postgresql://user:password@localhost:5432/nidra")

# ==== GeoIP ====
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "data/GeoLite2-City.mmdb")

# ==== Encryption ====
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "default-32-byte-key")
USE_ENCRYPTION = os.getenv("USE_ENCRYPTION", "True").lower() == "true"

# ==== Honeypot ====
HONEYPOT_PATH = os.getenv("HONEYPOT_PATH", "/__nidra_honeypot__")

# ==== Logging ====
LOGGING_LEVEL = os.getenv("LOGGING_LEVEL", "INFO")

# ==== Metadata ====
PROJECT_NAME = os.getenv("PROJECT_NAME", "NIDRA")
VERSION = os.getenv("VERSION", "1.0.0")
