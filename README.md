# Secure LLM Gateway Framework

An Enterprise-grade Middleware & Security Dashboard for Large Language Models (LLMs). 
This framework sits between the user and the LLM, actively intercepting prompts to sanitize Personally Identifiable Information (PII) and block Prompt Injections before they reach the AI.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-TinyLlama-white?style=for-the-badge)

## ✨ Key Features
* **🔐 JWT Authentication:** Secure login system (`admin` dashboard protection) using PyJWT and bcrypt password hashing.
* **🕵️‍♂️ Real-Time PII Sanitization:** Automatically masks sensitive Indian & Global data structures using Regex (Emails, Phone Numbers, Credit Cards, Aadhaar Cards, PAN Cards, etc.).
* **🛡️ Prompt Injection Defense:** Detects and intercepts jailbreak attempts and malicious prompt injections.
* **📊 Glassmorphism Analytics Dashboard:** Beautiful, modern UI with real-time Threat Heatmaps and Pie Charts (powered by Chart.js).
* **🗄️ Local Audit Logging:** Saves complete chat histories (Original vs. Masked) securely in a local SQLite Database.
* **📄 Export Features:** Instantly export security audit logs to **PDF** or **CSV** formats.

## 🛠️ Tech Stack
* **Backend:** FastAPI, Uvicorn, Python
* **Frontend:** Vanilla JavaScript (ES6), HTML5, CSS3 (Glassmorphism design)
* **Database:** SQLite3
* **AI Integration:** Ollama (Local TinyLlama Model)
* **Libraries:** Chart.js, html2pdf.js, PyJWT, Bcrypt, python-multipart

## 🚀 How to Install and Run Locally

**1. Clone the repository**
```bash
git clone [https://github.com/your-username/secure-llm-gateway.git](https://github.com/your-username/secure-llm-gateway.git)
cd secure-llm-gateway
2. Create a Virtual Environment

Bash
python -m venv .venv
# On Windows
.\.venv\Scripts\activate
# On Mac/Linux
source .venv/bin/activate
3. Install Dependencies

Bash
pip install -r requirements.txt
4. Start the Local AI Model (Ollama)
Make sure you have Ollama installed on your system.

Bash
ollama run tinyllama
5. Run the Secure Gateway Server

Bash
python main.py
6. Access the Dashboard

Open your browser and go to: http://127.0.0.1:8000/

Default Credentials:

Username: admin

Password: admin123

📂 Project Structure
main.py - Core FastAPI server, API endpoints, and AI logic.

sanitizer.py - Regex engine for PII and Threat detection.

database.py - SQLite schema, queries, and JWT validation.

index.html - The frontend UI, Login Screen, and charts.

.gitignore - Protects .env and *.db files from leaking.

🤝 Contribution
Feel free to fork this repository, create a feature branch, and submit a Pull Request!