"""
    This is the test file for config

"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


import config

def test_config():
    print("DB_TYPE:", config.DB_TYPE)
    print("MONGO_URI:", config.MONGO_URI)
    print("POSTGRES_URI:", config.POSTGRES_URI)
    print("ENCRYPTION_KEY:", config.ENCRYPTION_KEY)
    print("HONEYPOT_PATH:", config.HONEYPOT_PATH)

if __name__ == "__main__":
    test_config()
