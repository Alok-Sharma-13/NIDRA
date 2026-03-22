"""
IP Blocker for NIDRA
Handles automatic and manual IP blocking and unblocking.

Author: Alok Sharma
Date: July 2025
"""

import os
from backend.database_config import engine
from sqlalchemy import text

BLOCKED_IPS_FILE = "data/log/blocked_ips.txt"

class IPBlocker:
    def __init__(self):
        os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
        self.blocked_ips = set()
        self._load_blocked_ips()

    def _load_blocked_ips(self):
        """Loads blocked IPs from the file into memory."""
        try:
            with open(BLOCKED_IPS_FILE, "r") as f:
                self.blocked_ips = set(line.strip() for line in f if line.strip())
            print(f"[IPBlocker] Loaded {len(self.blocked_ips)} blocked IPs.")
        except FileNotFoundError:
            self.blocked_ips = set()

    def _save_blocked_ips(self):
        """Saves the current blocked IPs to the file."""
        with open(BLOCKED_IPS_FILE, "w") as f:
            for ip in sorted(self.blocked_ips):
                f.write(ip + "\n")

    # def block(self, ip: str):
    #     """Blocks the given IP and saves it."""
    #     if ip and ip not in self.blocked_ips:
    #         self.blocked_ips.add(ip)
    #         self._save_blocked_ips()
    #         print(f"[IPBlocker] Blocked IP: {ip}")
    def block(self, ip: str):
        """Blocks the given IP and saves it."""

        if ip and ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self._save_blocked_ips()
            print(f"[IPBlocker] Blocked IP: {ip}")

            # -------- DB INSERT --------
            try:
                with engine.begin() as conn:
                    conn.execute(text("""
                        INSERT INTO blocked_ips (ip_address)
                        VALUES (:ip)
                        ON CONFLICT (ip_address) DO NOTHING
                    """), {"ip": ip})
            except Exception as e:
                print("[IPBlocker] DB insert failed:", e)

    # def unblock(self, ip: str):
    #     """Unblocks the given IP and updates the file."""
    #     if ip in self.blocked_ips:
    #         self.blocked_ips.remove(ip)
    #         self._save_blocked_ips()
    #         print(f"[IPBlocker] Unblocked IP: {ip}")

    def unblock(self, ip: str):
        """Unblocks the given IP and updates the file."""

        # reload latest file first
        self._load_blocked_ips()

        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self._save_blocked_ips()
            print(f"[IPBlocker] Unblocked IP: {ip}")
        else:
            print(f"[IPBlocker] IP not found: {ip}")

    def is_blocked(self, ip: str) -> bool:
        """Checks whether the given IP is blocked."""
        return ip in self.blocked_ips

    def get_blocked_ips(self):
        """Returns a list of currently blocked IPs."""
        return sorted(list(self.blocked_ips))
