"""
App Scanner — HuggingFace URL Maliciousness Predictor
Model: kmack/malicious-url-detection  (DistilBERT fine-tuned on phishing URLs)
Input (argv[1]): raw URL or domain string
Output: JSON { risk_level, confidence, label, score, input }

Usage:
  python ml/hf_predict.py "br-icloud.com.br"
  python ml/hf_predict.py "https://accounts.google.com"
"""

import sys
import json
import re
from urllib.parse import urlparse

# ── Parse input ───────────────────────────────────────────────────────────────
if len(sys.argv) < 2:
    print(json.dumps({"error": "Usage: python hf_predict.py <url_or_domain>"}))
    sys.exit(1)

raw_input = sys.argv[1].strip()

# Extract clean domain string for the model
# kmack/malicious-url-detection expects just the domain name (e.g. "google.com")
def extract_domain(s):
    if s.startswith("http://") or s.startswith("https://"):
        try:
            return urlparse(s).netloc.lower()
        except:
            pass
    # Strip protocol-less URLs
    s = re.sub(r'^www\.', '', s.lower().split('/')[0])
    return s.strip()

domain_input = extract_domain(raw_input)
if not domain_input:
    domain_input = raw_input

# ── Load HuggingFace model ────────────────────────────────────────────────────
try:
    from transformers import pipeline
except ImportError:
    print(json.dumps({"error": "transformers library not installed. Run: pip install transformers torch"}))
    sys.exit(1)

try:
    classifier = pipeline(
        "text-classification",
        model="kmack/malicious-url-detection",
        truncation=True,
        max_length=512
    )
except Exception as e:
    print(json.dumps({"error": f"Failed to load model: {e}"}))
    sys.exit(1)

# ── Run inference ─────────────────────────────────────────────────────────────
try:
    result = classifier(domain_input)[0]
    label = str(result.get("label", "")).lower()
    score = float(result.get("score", 0.5))
except Exception as e:
    print(json.dumps({"error": f"Inference failed: {e}"}))
    sys.exit(1)

# ── Normalize label → risk_level ──────────────────────────────────────────────
# Model outputs: "LABEL_0" (benign) / "LABEL_1" (malicious) or "malware"/"benign"
malicious_keywords = {"malicious", "malware", "phishing", "label_1", "1", "bad", "unsafe", "spam"}
is_malicious = any(kw in label for kw in malicious_keywords)

if is_malicious and score >= 0.7:
    risk_level = "High"
elif is_malicious and score >= 0.5:
    risk_level = "Medium"
else:
    risk_level = "Low"

confidence = {
    "malicious": round(score if is_malicious else 1 - score, 4),
    "benign":    round(1 - score if is_malicious else score, 4)
}

# ── Output ────────────────────────────────────────────────────────────────────
print(json.dumps({
    "input": raw_input,
    "domain": domain_input,
    "risk_level": risk_level,
    "ml_label": result.get("label"),
    "ml_score": round(score, 4),
    "confidence": confidence,
    "threats": []   # model gives a single classification — no discrete threats
}))
