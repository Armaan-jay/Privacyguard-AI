"""
LLM Security Gateway — Prompt Injection Firewall (Hardened)
Model: protectai/deberta-v3-base-prompt-injection
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ValidationError
import uvicorn
import requests
import json
import torch
from typing import List, Optional

# ─────────────────────────────────────────────────────────────
# App & Constants
# ─────────────────────────────────────────────────────────────
app = FastAPI(title="LLM Security Gateway")

MODEL_NAME = "protectai/deberta-v3-base-prompt-injection"
OLLAMA_URL = "http://localhost:11434/api"
MAX_PROMPT_LENGTH = 2000  # hard safety cap

INJECTION_THRESHOLD = 0.65
SUSPICIOUS_THRESHOLD = 0.45

classifier = None
ollama_model = None


# ─────────────────────────────────────────────────────────────
# Request / Response Schemas
# ─────────────────────────────────────────────────────────────
class PromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT_LENGTH)


class OllamaSecurityReport(BaseModel):
    intent: str
    category: str
    threat_type: str
    risk_level: str
    confidence_score: str
    risky_segments: List[str]
    explanation: str
    firewall_action: str
    status: str
    safe_alternative_prompt: Optional[str]


# ─────────────────────────────────────────────────────────────
# Startup: Load Model Safely
# ─────────────────────────────────────────────────────────────
@app.on_event("startup")
def load_models():
    global classifier, ollama_model

    try:
        from transformers import (
            AutoTokenizer,
            AutoModelForSequenceClassification,
            pipeline
        )

        device = 0 if torch.cuda.is_available() else -1

        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)

        classifier = pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer,
            truncation=True,
            max_length=512,
            return_all_scores=True,
            device=device
        )

        print("✅ DeBERTa model loaded")

    except Exception as e:
        print(f"❌ Fatal model load error: {e}")
        classifier = None

    ollama_model = detect_ollama_model()


# ─────────────────────────────────────────────────────────────
# Ollama Detection
# ─────────────────────────────────────────────────────────────
def detect_ollama_model():
    try:
        r = requests.get(f"{OLLAMA_URL}/tags", timeout=5)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        for pref in ("llama3", "mistral", "phi3", "gemma", "llama2"):
            for m in models:
                if pref in m.lower():
                    return m
        return models[0] if models else None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# Health Check
# ─────────────────────────────────────────────────────────────
@app.get("/")
def health():
    return {
        "status": "online" if classifier else "degraded",
        "deberta_loaded": bool(classifier),
        "ollama_model": ollama_model or "not available"
    }


# ─────────────────────────────────────────────────────────────
# Ollama Deep Scan (Advisory ONLY)
# ─────────────────────────────────────────────────────────────
def ollama_deep_scan(prompt: str) -> Optional[OllamaSecurityReport]:
    if not ollama_model:
        return None

    system_prompt = (
        "You are an AI Security Engine. "
        "Analyze the prompt strictly and return ONLY valid JSON."
    )

    try:
        r = requests.post(
            f"{OLLAMA_URL}/generate",
            json={
                "model": ollama_model,
                "system": system_prompt,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            },
            timeout=15
        )
        r.raise_for_status()

        data = json.loads(r.json().get("response", "{}"))
        return OllamaSecurityReport(**data)

    except (requests.RequestException, ValidationError, json.JSONDecodeError):
        return None


# ─────────────────────────────────────────────────────────────
# Main Analysis Endpoint
# ─────────────────────────────────────────────────────────────
@app.post("/analyze")
def analyze_prompt(req: PromptRequest):

    if not classifier:
        raise HTTPException(
            status_code=503,
            detail="Security model unavailable — fail closed"
        )

    # ── DeBERTa Classification ──────────────────────────────
    try:
        scores = classifier(req.prompt)[0]
        score_map = {s["label"]: s["score"] for s in scores}

        injection_prob = score_map.get("INJECTION", 0.0)

    except Exception:
        # FAIL CLOSED
        raise HTTPException(
            status_code=500,
            detail="Inference failure — request blocked"
        )

    # ── Tier Decision ───────────────────────────────────────
    if injection_prob >= INJECTION_THRESHOLD:
        tier = "malicious"
    elif injection_prob >= SUSPICIOUS_THRESHOLD:
        tier = "suspicious"
    else:
        tier = "safe"

    response = {
        "engine": "DeBERTa-v3",
        "injection_probability": round(injection_prob, 4),
        "tier": tier,
        "allowed": tier == "safe"
    }

    # ── Optional Ollama Advisory Scan ───────────────────────
    if tier != "safe":
        advisory = ollama_deep_scan(req.prompt)
        if advisory:
            response["ollama_advisory"] = advisory.dict()

    # Deterministic decision NEVER overridden by LLM
    if tier == "malicious":
        response["allowed"] = False

    return response


# ─────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
