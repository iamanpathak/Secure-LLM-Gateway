# 🛡️ Secure LLM Gateway: Vulnerability Mitigation Framework

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Ollama](https://img.shields.io/badge/AI_Engine-Ollama-black.svg)](https://ollama.com/)

A lightweight, locally-hosted middleware designed to secure interactions between end-users and Large Language Models (LLMs). It intercepts requests, sanitizes sensitive data (PII), and blocks prompt injection attacks in real-time.

## ⚙️ System Architecture Flow

```text
Client ➔ [ FastAPI Gateway ] ➔ 🔍 Sanitizer Engine (PII & Injection Check)
                                                │
                                                ▼ (Cleaned Payload)
[ SQLite Audit DB ] ◄───────────────── 🧠 Local LLM (Ollama)
```

## ✨ Core Features
* **🔍 Real-Time PII Redaction:** Automatically masks sensitive information (emails, phone numbers, credit cards, etc.) before the payload reaches the AI model.
* **🛑 Prompt Injection Defense:** Scans and neutralizes malicious overrides and adversarial prompts.
* **🧠 100% Local Processing:** Integrates directly with local LLMs via Ollama to ensure complete data privacy and sovereignty.
* **📊 Audit & Monitoring:** Maintains a secure SQLite audit trail of all interactions, visualized on a JWT-secured admin dashboard.

## 💻 Tech Stack
* **Backend:** Python 3.10+, FastAPI, PyJWT
* **Frontend:** HTML5, CSS3, Vanilla JavaScript, Chart.js
* **AI Engine:** Ollama (Model: `tinyllama`)

## 🚀 Quick Start Guide

### 1. Setup Environment
Clone the repository and install dependencies:
```bash
git clone [https://github.com/iamanpathak/Secure-LLM-Gateway.git](https://github.com/iamanpathak/Secure-LLM-Gateway.git)
cd Secure-LLM-Gateway

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # Mac/Linux

# Install required packages
pip install -r requirements.txt
```

### 2. Start the AI Engine
Ensure [Ollama](https://ollama.com/) is installed and running locally, then pull the model:
```bash
ollama run tinyllama
```

### 3. Launch the Gateway
Start the FastAPI application:
```bash
python main.py
```
Navigate to `http://127.0.0.1:8000` in your web browser to access the interface.

## 🔑 Testing Credentials
For local development and evaluation, the system initializes with a default administrator account to access the secure monitoring dashboard:
* **Username:** `admin`
* **Password:** `admin123`