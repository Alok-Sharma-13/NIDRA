"""
NIDRA SDK Interface

This SDK provides methods to capture and process incoming HTTP request metadata
for intrusion detection and logging. It acts as the main interface for integrating
NIDRA with any Python-based backend (Flask, FastAPI, etc).

Author: Alok & Aditya
Date: June 2025
"""

from core.traffic_sniffer import sniff_request
from backend import database_config

class NidraSDK:
    def __init__(self):
        """
        Initializes the NIDRA SDK. This sets up the database connection.
        """
        self.db_type = database_config.DB_TYPE
        self.db = database_config.db if self.db_type == "mongodb" else None
        self.SessionLocal = database_config.SessionLocal if self.db_type == "postgresql" else None

    def capture_request(self, request):
        """
        Captures metadata from the HTTP request and stores it in the database.

        Parameters:
            request: Flask/FastAPI request object

        Returns:
            dict: Structured log dictionary
        """
        log_data = sniff_request(request)
        if not log_data:
            print("[NIDRA SDK] Failed to log request")
            return None

        try:
            if self.db_type == "mongodb" and self.db:
                self.db["traffic_logs"].insert_one(log_data)
                print("[NIDRA SDK] Log stored in MongoDB")

            elif self.db_type == "postgresql" and self.SessionLocal:
                # Placeholder: convert log_data to ORM model (to be created later)
                print("[NIDRA SDK] PostgreSQL logging not yet implemented")

        except Exception as e:
            print(f"[NIDRA SDK] Error storing log: {e}")

        return log_data
