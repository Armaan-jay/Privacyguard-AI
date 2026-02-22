
import sys
import pickle
import json
import os
import pandas as pd
import numpy as np

# Set paths
base_dir = os.path.dirname(__file__)
model_path = os.path.join(base_dir, 'malicious_url_model.pkl')
columns_path = os.path.join(base_dir, 'model_columns.json')

# Load Resources
try:
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(columns_path, 'r') as f:
        meta = json.load(f)
    feature_columns = meta.get('_feature_columns', [])
    if not feature_columns:
        raise ValueError("No feature columns found in model_columns.json")
except FileNotFoundError as e:
    print(json.dumps({"error": f"Model file not found: {e}. Run retrain_model.py first."}))
    sys.exit(1)
except Exception as e:
    print(json.dumps({"error": f"Failed to load model: {e}"}))
    sys.exit(1)

# Read input
if len(sys.argv) < 4:
    print(json.dumps({"error": "Usage: python predict.py <name> <description> <permissions>"}))
    sys.exit(1)

name = sys.argv[1]
description = sys.argv[2]
permissions_input = sys.argv[3].upper()

# ── Build Feature Vector ──────────────────────────────────────────────────────
# Initialise all feature columns to 0
input_data = {col: 0 for col in feature_columns}

# Map permission strings → matching feature column
known_perms = [p.strip() for p in permissions_input.split(',') if p.strip()]
for perm in known_perms:
    # Direct match
    if perm in input_data:
        input_data[perm] = 1
    else:
        # Partial match: e.g. "CAMERA" → "android.permission.CAMERA"
        for col in feature_columns:
            col_suffix = col.split('.')[-1].upper()
            if perm == col_suffix or perm in col.upper():
                input_data[col] = 1

df = pd.DataFrame([input_data])

# ── Predict ───────────────────────────────────────────────────────────────────
try:
    prediction = model.predict(df)[0]

    # Normalise prediction → risk label
    if isinstance(prediction, (int, np.integer)):
        risk_level = "High" if int(prediction) == 1 else "Low"
    elif isinstance(prediction, (float, np.floating)):
        risk_level = "High" if prediction >= 0.5 else "Low"
    else:
        label_lower = str(prediction).lower()
        if any(k in label_lower for k in ['malware', 'malicious', '1', 'high', 'bad']):
            risk_level = "High"
        else:
            risk_level = "Low"

    # Get probability scores
    try:
        probs = model.predict_proba(df)[0]
        classes = [str(c) for c in model.classes_]
        confidence = {c: round(float(p), 4) for c, p in zip(classes, probs)}
    except:
        confidence = {}

except Exception as e:
    risk_level = "Unknown"
    confidence = {}

# ── Rule-based Threat Overlay ─────────────────────────────────────────────────
detected_threats = []

risky_perms_map = {
    'SEND_SMS': 'Can send premium SMS messages silently (money theft)',
    'READ_SMS': 'Can read private messages and steal OTP codes',
    'RECEIVE_SMS': 'Can intercept and block incoming SMS messages',
    'READ_CONTACTS': 'Can harvest and exfiltrate your contact list',
    'RECORD_AUDIO': 'Can secretly record microphone audio',
    'SYSTEM_ALERT_WINDOW': 'Can draw overlays on top of other apps (phishing UI)',
    'INSTALL_PACKAGES': 'Can silently install additional apps',
    'PROCESS_OUTGOING_CALLS': 'Can monitor, intercept, or redirect phone calls',
    'GET_ACCOUNTS': 'Can access Gmail, corporate, and saved account credentials',
    'READ_CALL_LOG': 'Can read full call history and phone activity',
    'WRITE_CALL_LOG': 'Can modify or delete call log entries',
    'CAMERA': 'Can take photos or videos without notification',
    'ACCESS_FINE_LOCATION': 'Can track precise GPS location in real time',
    'READ_CALENDAR': 'Can read all calendar events and appointments',
    'WRITE_CONTACTS': 'Can add, modify, or delete contact data',
    'MASTER_CLEAR': 'CRITICAL — Can factory reset the device',
    'BRICK': 'CRITICAL — Can permanently disable the device',
    'BIND_DEVICE_ADMIN': 'Can gain Device Administrator privileges',
    'WRITE_SECURE_SETTINGS': 'Can modify system security settings',
    'ACCESS_SUPERUSER': 'Requests root / superuser access',
}

for perm_key, warning in risky_perms_map.items():
    if perm_key in permissions_input:
        detected_threats.append({
            "type": "Dangerous Permission",
            "value": perm_key,
            "warning": warning,
            "severity": "Critical" if perm_key in ('MASTER_CLEAR', 'BRICK', 'ACCESS_SUPERUSER', 'BIND_DEVICE_ADMIN') else "High"
        })

suspicious_keywords = {
    'free gems': 'Classic scam / fake reward keyword',
    'unlimited coins': 'Classic scam / fake reward keyword',
    'hack': 'Claims illegal/manipulative functionality',
    'spy': 'Stalkerware or surveillance indicator',
    'track boyfriend': 'Stalkerware indicator',
    'track girlfriend': 'Stalkerware indicator',
    'instant loan': 'Predatory/illegal micro-loan app indicator',
    'free vpn': 'Often data harvesting or traffic interception risk',
    'root': 'Claims root access functionality',
    'bypass': 'Bypassing security or system controls',
    'keylogger': 'Records keystrokes without consent',
}
text_content = (name + " " + description).lower()
for keyword, warning in suspicious_keywords.items():
    if keyword in text_content:
        detected_threats.append({
            "type": "Suspicious Keyword",
            "value": keyword,
            "warning": warning,
            "severity": "Medium"
        })

# Elevate risk if critical rule-based threats found
if any(t.get('severity') == 'Critical' for t in detected_threats) and risk_level == "Low":
    risk_level = "High"

# ── Output ────────────────────────────────────────────────────────────────────
print(json.dumps({
    "risk_level": risk_level,
    "confidence": confidence,
    "threats": detected_threats
}))
