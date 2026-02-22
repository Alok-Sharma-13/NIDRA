import requests
import time

BASE_URL = "http://localhost:8000"

# === Existing Tests ===

def test_login_logout():
    print("[*] Testing login...")
    r = requests.post(f"{BASE_URL}/api/login", json={"username": "admin", "password": "admin"})
    try:
        print("Login:", r.status_code, r.json())
    except:
        print("Login:", r.status_code, r.text)

    print("[*] Testing logout...")
    r = requests.post(f"{BASE_URL}/api/logout")
    try:
        print("Logout:", r.status_code, r.json())
    except:
        print("Logout:", r.status_code, r.text)

def test_normal_traffic():
    print("[*] Testing normal request (should only log)...")
    r = requests.get(f"{BASE_URL}/home", headers={"User-Agent": "Mozilla/5.0"})
    print("Normal Traffic:", r.status_code, r.text)

def test_xss_detection():
    print("[*] Testing XSS rule...")
    data = [{
        "ip_address": "127.0.0.1",
        "path": "/search?q=<script>alert(1)</script>",
        "user_agent": "curl/8.1",
        "headers": {"X-Test": "XSS-Test"}
    }]
    r = requests.post(f"{BASE_URL}/api/rules/analyze", json=data)
    try:
        print("XSS Rule:", r.status_code, r.json())
    except:
        print("XSS Rule:", r.status_code, r.text)

def test_sqli_detection():
    print("[*] Testing SQL Injection rule...")
    data = [{
        "ip_address": "127.0.0.2",
        "path": "/products?id=1 union select password from users --",
        "user_agent": "Mozilla/5.0",
        "headers": {"X-Test": "SQLi-Test"}
    }]
    r = requests.post(f"{BASE_URL}/api/rules/analyze", json=data)
    try:
        print("SQLi Rule:", r.status_code, r.json())
    except:
        print("SQLi Rule:", r.status_code, r.text)

def test_user_agent_detection():
    print("[*] Testing Suspicious User-Agent rule...")
    data = [{
        "ip_address": "127.0.0.3",
        "path": "/about",
        "user_agent": "sqlmap/1.5",
        "headers": {"X-Test": "UserAgent-Test"}
    }]
    r = requests.post(f"{BASE_URL}/api/rules/analyze", json=data)
    try:
        print("User-Agent Rule:", r.status_code, r.json())
    except:
        print("User-Agent Rule:", r.status_code, r.text)

def test_honeypot_trigger():
    print("[*] Testing honeypot access...")
    r = requests.get(f"{BASE_URL}/api/log/admin", headers={"User-Agent": "attacker"})
    print("Honeypot:", r.status_code, r.text)

def test_ip_block_unblock():
    print("[*] Testing manual IP block...")
    r = requests.post(f"{BASE_URL}/api/ip/block", json={"ip": "127.0.0.99"})
    try:
        print("Block IP:", r.status_code, r.json())
    except:
        print("Block IP:", r.status_code, r.text)

    print("[*] Testing manual IP unblock...")
    r = requests.post(f"{BASE_URL}/api/ip/unblock", json={"ip": "127.0.0.99"})
    try:
        print("Unblock IP:", r.status_code, r.json())
    except:
        print("Unblock IP:", r.status_code, r.text)

# === NEW TESTS for Application-level Rules ===

def test_broken_authentication():
    print("[*] Testing Broken Authentication (brute force)...")
    data = []
    for i in range(7):  # Exceed threshold of 5
        data.append({
            "ip_address": "127.0.0.10",
            "username": "victim",
            "event": "login_failure",
            "path": "/api/login"
        })
        time.sleep(0.2)
    r = requests.post(f"{BASE_URL}/api/rules/analyze", json=data)
    try:
        print("Broken Auth Rule:", r.status_code, r.json())
    except:
        print("Broken Auth Rule:", r.status_code, r.text)

def test_idor_access_control():
    print("[*] Testing Broken Access Control / IDOR...")
    data = [{
        "ip_address": "127.0.0.11",
        "path": "/api/user/12345",
        "username": "attacker",
        "headers": {"X-Test": "IDOR-Test"}
    }]
    r = requests.post(f"{BASE_URL}/api/rules/analyze", json=data)
    try:
        print("IDOR Rule:", r.status_code, r.json())
    except:
        print("IDOR Rule:", r.status_code, r.text)

def test_rce_command_injection():
    print("[*] Testing Remote Code Execution / Command Injection...")
    data = [{
        "ip_address": "127.0.0.12",
        "path": "/api/run",
        "body": "cat /etc/passwd; ls -la && whoami",
        "username": "attacker"
    }]
    r = requests.post(f"{BASE_URL}/api/rules/analyze", json=data)
    try:
        print("RCE Rule:", r.status_code, r.json())
    except:
        print("RCE Rule:", r.status_code, r.text)

def test_file_upload_abuse():
    print("[*] Testing File Upload Abuse...")
    data = [{
        "ip_address": "127.0.0.13",
        "path": "/api/upload",
        "filename": "image.jpg.php",
        "username": "attacker"
    }]
    r = requests.post(f"{BASE_URL}/api/rules/analyze", json=data)
    try:
        print("File Upload Rule:", r.status_code, r.json())
    except:
        print("File Upload Rule:", r.status_code, r.text)

def test_insecure_deserialization():
    print("[*] Testing Insecure Deserialization...")
    data = [{
        "ip_address": "127.0.0.14",
        "path": "/api/import",
        "body": "pickle.loads(b'Y29tcGxleA==')",
        "username": "attacker"
    }]
    r = requests.post(f"{BASE_URL}/api/rules/analyze", json=data)
    try:
        print("Deserialization Rule:", r.status_code, r.json())
    except:
        print("Deserialization Rule:", r.status_code, r.text)


# === MAIN ===
if __name__ == "__main__":
    test_login_logout()
    test_normal_traffic()
    test_xss_detection()
    test_sqli_detection()
    test_user_agent_detection()
    test_honeypot_trigger()
    test_ip_block_unblock()

    # Run new tests
    test_broken_authentication()
    test_idor_access_control()
    test_rce_command_injection()
    test_file_upload_abuse()
    test_insecure_deserialization()
