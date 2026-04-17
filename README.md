# LLM Sentinel: AI Security Gateway

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Ollama](https://img.shields.io/badge/AI_Engine-Ollama-F97316?logo=ollama&logoColor=white)](https://ollama.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-07405E?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![JWT](https://img.shields.io/badge/Security-JWT-D63AFF?logo=JSON%20web%20tokens&logoColor=white)](https://jwt.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](https://opensource.org/licenses/MIT)

Hey! I'm Aman. I built **Sentinel** to demonstrate how organizations can safely integrate Large Language Models (LLMs) without compromising user privacy or system security. Instead of connecting end-users directly to an AI, I engineered a locally-hosted middleware that acts as a secure proxy, dynamically filtering out sensitive data and blocking malicious inputs in real-time.

---

## 🧩 The Problem & Solution

**The Problem:** Connecting raw user inputs directly to LLMs introduces two massive attack vectors: 
1. **Data Exfiltration:** Users accidentally sharing Personally Identifiable Information (PII) like credit cards, Aadhaar numbers, or addresses.
2. **Prompt Injection:** Attackers using malicious instructions to bypass system guardrails, hijack the AI's logic, or extract backend secrets.

**The Solution:** A lightweight, high-performance security gateway built with FastAPI. It intercepts every request, runs a multi-pass sanitization engine (Regex + Contextual checks) to redact PII, actively blocks prompt injection signatures, and logs every event into an immutable audit trail — all before the data ever reaches the target LLM, ensuring a secure, zero-dependency defense layer.

---

## 🏗️ System Architecture & Data Flow

I designed this gateway with a "Privacy by Design" architecture. Processing happens 100% locally, ensuring zero data leaves the host machine.

```text
[Web UI / Client] ──(HTTP POST)──> [FastAPI Security Gateway]
                                          │
                                          ▼
                             [Multi-Pass Sanitization Engine]
                              ├─ 1. PII Redaction (Regex/Context)
                              └─ 2. Injection Signature Scanning
                                          │
        ┌─────────────────────────────────┴─────────────────────────────────┐
        ▼                                                                   ▼
 [SQLite Audit DB]                                                   [Ollama AI Engine]
 (Immutable Logging) ◄──────────(AI Response / Block Status)───────── (tinyllama)
```

---

## 📸 System in Action

*Note: These are live captures from my development environment demonstrating the gateway's active defense capabilities under testing.*

### 1. Secure Access Portal
A JWT-secured authentication layer ensuring only authorized administrators can access the gateway's telemetry and audit logs.

![Gateway Login](assets/login.png)

### 2. Real-Time Telemetry Dashboard
The central command center. It visualizes intercepted PII types, system health, and features a dynamic control panel to toggle sanitization filters (Name, Phone, Email, Address, Cards). **Note:** Government IDs are permanently locked ON as a mandatory security protocol. Turning off a filter explicitly flags leaked data as `UNMASKED` in the risk assessment.

![Security Dashboard](assets/dashboard.png)

### 3. Active Threat Mitigation
Demonstrating the gateway intercepting a malicious prompt injection (`forget all instructions...`). The system blocks the attack before it reaches the LLM and instantly updates the real-time heatmap and threat metrics. It also enforces a strict context guardrail, preventing the AI from leaking previously provided user data.

![Prompt Injection Blocked](assets/injection_blocked.png)

### 4. Immutable Audit Trail
The compliance log. It records the original input (blurred for privacy), the dynamically secured output (showing `<TAGS>`), the computed risk level (`SECURE`, `MEDIUM`, `HIGH`), and the timestamp. You can see the `MEDIUM (UNMASKED)` flag actively catching instances where toggles were disabled but sensitive data was still detected. Includes a one-click **Export** feature to generate `CSV`/`PDF` reports for security audits.

![Audit Logs](assets/audit_history_logs.png)

---

## 📂 Project Structure

```text
llm-sentinel/
├── assets/                    # Live system screenshots for documentation
├── static/
│   ├── script.js              # Frontend logic, charts, and API communication
│   └── style.css              # UI styling and dark theme
├── database.py                # Database connection and table setup
├── index.html                 # Main interface and dashboard UI
├── main.py                    # FastAPI application, auth, and API routes
├── sanitizer.py               # Core logic for PII masking & injection detection
├── .env.example               # Template for environment variables
├── requirements.txt           # Backend dependencies
├── LICENSE                    # MIT License file
└── README.md                  # Project documentation
```

---

## ⚖️ Architecture Tradeoffs & Design Choices

* **Local LLM (Ollama) vs. Cloud Providers:** I chose Ollama to guarantee 100% data sovereignty. *Tradeoff:* Bounded by local compute limits compared to accessing massive cloud APIs like OpenAI, but entirely eliminates external API data-sharing risks.

* **Regex/Heuristics vs. NLP Models for PII:** The sanitization engine uses optimized regular expressions and contextual visibility checks instead of heavy ML models. *Tradeoff:* Incredibly fast (sub-millisecond latency) making it viable as a real-time gateway, but may lack the deep semantic understanding of a dedicated NLP classification model.

* **Dynamic Risk Scoring:** Implemented an intelligent detection system that differentiates between harmless conversational fillers ("I live in") and actual data exposure. *Tradeoff:* Requires stricter pattern maintenance, but drastically reduces false positives for the end-user.

* **SQLite vs. PostgreSQL:** Used SQLite for the audit and history databases. *Tradeoff:* Perfect for a lightweight, zero-config local gateway demonstration, but would require migrating to PostgreSQL for distributed, high-concurrency enterprise deployments.

---

## 🚀 Get it Running Locally

### 1. Clone & Setup

```bash
git clone https://github.com/iamanpathak/llm-sentinel.git
cd llm-sentinel

# Create and activate virtual environment
python -m venv .venv

# Windows
.\.venv\Scripts\activate 
# Mac/Linux
# source .venv/bin/activate 

# Install required packages
pip install -r requirements.txt
```

### 2. Start the AI Engine
Ensure [Ollama](https://ollama.com/) is installed and running on your machine, then pull the required model:

```bash
ollama run tinyllama
```

### 3. Launch the Gateway
Start the FastAPI server:

```bash
python main.py
```
* **Dashboard/Gateway:** Navigate to `http://127.0.0.1:8000`
* **Default Admin Credentials:** `admin` / `admin123`

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
<p align="center">
  Made with ❤️ by <a href="https://github.com/iamanpathak">Aman Pathak</a>
</p>
