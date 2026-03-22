"""
Database connector for NIDRA.
Supports MongoDB and PostgreSQL based on configuration.

Author: Alok 
Date: June 2025
"""

from backend.routes.config import DB_TYPE, MONGO_URI, POSTGRES_URI
from pymongo import MongoClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

db = None
SessionLocal = None
engine = None

# MongoDB Connection 
if DB_TYPE == "mongodb":
    try:
        mongo_client = MongoClient(MONGO_URI)
        db = mongo_client["nidra_logs"]
        print("MongoDB connected")
    except Exception as e:
        print("MongoDB not found", e)

# PostgreSQL Connection
elif DB_TYPE in ["postgres", "postgresql"]:
    try:
        engine = create_engine(POSTGRES_URI)
        SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine
        )

        # test connection
        conn = engine.connect()
        conn.close()

        print("PostgreSQL connected")

    except Exception as e:
        print("PostgreSQL not found", e)

else:
    print(f"[Error] Unsupported DB_TYPE: {DB_TYPE}")