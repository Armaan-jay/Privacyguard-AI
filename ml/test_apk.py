import requests

BASE = "http://localhost:5000"

tests_apk = [
    # (filename, expected_risk)
    ("Camera_v2.1.apk",              "Low"),
    ("Calculator.apk",               "Low"),
    ("WhatsApp_Mod_Unlimited.apk",   "High"),
    ("RTO_Challan_v10.0.apk",        "Medium"),
    ("SystemUpdate_v999.apk",        "High"),
]

tests_invalid = [
    "Camera",           # no extension
    "photo.png",        # wrong extension
    "something.exe",    # wrong extension
]

print("=== APK Scan Tests ===")
for f, expected in tests_apk:
    r = requests.post(f"{BASE}/api/scan-apk", json={"filename": f})
    d = r.json()
    got = d.get("risk_level", "ERROR")
    icon = "OK" if got == expected else "FAIL"
    print(f"[{icon}] {f:42} expected={expected:6} got={got:6}  score={d.get('risk_score','?')}")

print("\n=== Invalid Input Tests (must return 400) ===")
for f in tests_invalid:
    r = requests.post(f"{BASE}/api/scan-apk", json={"filename": f})
    d = r.json()
    icon = "OK" if r.status_code == 400 else "FAIL"
    print(f"[{icon}] '{f}'  status={r.status_code}  msg={d.get('message', d.get('error','?'))[:60]}")
