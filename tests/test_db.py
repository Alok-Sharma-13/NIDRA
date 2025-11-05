"""
    This is the test file for DB_config

"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend import database_config
import backend.routes.config as config

def test_connection():
    if config.DB_TYPE == "mongodb":
        # Try to insert and fetch from a test collection
        test_coll = database_config.db["test_collection"]
        test_coll.insert_one({"test": "ok"})
        result = test_coll.find_one({"test": "ok"})
        print("MongoDB Test:", result)

    elif config.DB_TYPE == "postgresql":
        session = database_config.SessionLocal()
        print("PostgreSQL session created:", session)
        session.close()

if __name__ == "__main__":
    test_connection()
