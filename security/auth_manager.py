"""
Auth Manager for NIDRA
Provides basic admin login functionality using credentials from .env file.

Author: Alok 
Date: July 2025
"""
import os
from dotenv import load_dotenv

load_dotenv()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

def verify(USERNAME: str, PASSWORD: str) -> bool:
    """
    Verify if provided credentials match the stored admin credentials.
    Returns:
        bool: True if valid, False otherwise.
    """
    return USERNAME == ADMIN_USERNAME and PASSWORD == ADMIN_PASSWORD
