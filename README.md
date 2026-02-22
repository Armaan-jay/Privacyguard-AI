<div align="center">
  <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/shield-check.svg" width="80" height="80" alt="PrivacyGuard AI Logo" />
  <h1>PrivacyGuard AI Security Suite</h1>
  <p>An intelligent, multi-layered security analysis platform powered by state-of-the-art HuggingFace Models and Heuristics.</p>
</div>

---

## 🛡️ Overview

**PrivacyGuard AI Security Suite** is a comprehensive set of next-generation security assessment tools designed to protect systems, applications, and language models from modern threats. By combining local heuristic scanners with powerful HuggingFace DistilBERT and DeBERTa models, PrivacyGuard provides blazing-fast, accurate threat detection across multiple vectors.

### 🌟 Key Features

#### 🧠 1. LLM Firewall
A dedicated security layer defending Large Language Models from abuse.
* **Model:** [`protectai/deberta-v3-base-prompt-injection`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection)
* **Capabilities:** Detects Prompt Injections, Jailbreak attempts, System Prompts leaks, and Data Exfiltration.
* **Architecture:** Fast classification pipeline (DeBERTa-v3) with a 3-tier confidence threshold (Safe, Suspicious, Malicious), backed by a deep-scan Ollama generative engine fallback.

#### 📱 2. App Scanner
Comprehensive Android APK and URL risk assessment engine.
* **APK Filename Heuristics:** Evaluates APKs against 10 rigorous checks, including modded/cracked indicators, Fake System App camouflage, Financial/Government impersonation, and known Malware Family names.
* **Play Store Verification:** Automatically queries the Google Play Store to verify if the APK actually exists and validates its origin.
* **AI URL Scan:** Uses [`kmack/malicious-url-detection`](https://huggingface.co/kmack/malicious-url-detection) (DistilBERT) to analyze incoming domains and URLs for phishing and malware hosting with exact confidence scores.

#### 👻 3. Ghost Hunter & 💻 Code Lint (Upcoming)
* **Ghost Hunter:** Detects forgotten, vulnerable web pages, exposed endpoints, and orphaned domains.
* **Code Security Lint:** Automated static code analysis to catch common security flaws (like hardcoded secrets or XSS vulns) right at the source.

---

## 🚀 Getting Started

### Prerequisites
* [Node.js](https://nodejs.org/) (v16+)
* [Python 3.9+](https://www.python.org/)
* [Ollama](https://ollama.ai/) (optional, for LLM deep scans)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/privacyguard-ai.git
   cd privacyguard-ai
   ```

2. **Install Frontend and Node Backend Dependencies**
   ```bash
   npm install
   ```

3. **Install Python ML Dependencies**
   ```bash
   cd llm_engine
   pip install -r requirements.txt
   # Ensure transformers, torch, fastapi, uvicorn are installed
   ```

### Running the Application

This project requires three distinct services running concurrently:

1. **Frontend (Vite / React)**
   ```bash
   npm run dev
   ```

2. **Main API Server (Node.js)**
   Handles frontend requests, Play Store scraping, and routing for the App Scanner.
   ```bash
   node server/server.js
   ```

3. **LLM Engine (FastAPI / Python)**
   Hosts the HuggingFace models (DeBERTa / DistilBERT) for prompt analysis and URL scanning.
   ```bash
   cd llm_engine
   python main.py
   ```

---

## 🏗️ Architecture

* **Frontend:** React, TailwindCSS, Vite
* **Backend:** Node.js, Express, `google-play-scraper`
* **Machine Learning Interface:** Python, FastAPI, HuggingFace `transformers`, PyTorch
* **Generative Fallback:** Ollama (Local LLM via `http://localhost:11434`)

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

> *Note: The first time a scan is run, the HuggingFace models (~250MB - 500MB) will be downloaded to your local `.cache/huggingface` directory. Subsequent runs will be near-instant.*
