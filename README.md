# CyberScan AI 🛡️
### *Intelligence-Driven Web Vulnerability Assessment*

**CyberScan AI** is an advanced, Python-powered security auditing platform designed to bridge the gap between automated scanning and actionable intelligence. By leveraging asynchronous processing and machine learning classification, it provides real-time insights into web application security postures.

---

## 🔗 Live Demo
Experience the scanner in action without any local setup:

> **[Launch CyberScan AI Live](https://cyberscan-ai-dtql.onrender.com/)**  
> *(Note: The initial load may take ~50 seconds as the Render free-tier instance wakes up.)*

---

## 📸 Screenshots

### 🖥️ Main Dashboard
![Dashboard](https://github.com/Samarth1416/ai-web-vuln-scanner/blob/c83251ef10da67960d8ea6433d8463223643cb38/Screenshot%202026-04-07%20195033.png))
*A high-level overview of security posture and recent scan history.*

### 📡 Real-Time Scanning
![Scanning](https://github.com/Samarth1416/ai-web-vuln-scanner/blob/87bb6f3be73323450d724fdc1b40c45bd2d333c8/Screenshot%202026-04-07%20195011.png)
*Live telemetry feed showing active vulnerability detection via Server-Sent Events (SSE).*

---

## ✨ Key Features
- **Automated Discovery:** Deep-crawling engine that identifies entry points for SQL Injection (SQLi), Cross-Site Scripting (XSS), and security misconfigurations.
- **AI-Enhanced Classification:** Findings are intelligently graded based on severity (Critical, High, Medium, Low, Info) using integrated analysis.
- **Non-Blocking Architecture:** Scans are executed in background threads, keeping the UI responsive while performing heavy lifting.
- **Live Telemetry:** View scanning progress in real-time via Server-Sent Events (SSE)—no manual refreshing required.
- **Professional Reporting:** Export findings into detailed PDF or JSON reports for stakeholders.
- **Secure Persistence:** Integrated user authentication and SQLite database to maintain a history of all security audits.

---

## 🛠️ Technical Stack

| Component | Technology |
| :--- | :--- |
| **Backend** | Python / Flask |
| **Concurrency** | Threading & SSE (Server-Sent Events) |
| **Database** | SQLite (SQLAlchemy ORM) |
| **Frontend** | Jinja2, Bootstrap 5, Modern JavaScript |
| **Deployment** | Gunicorn / Render |

---

## 🚀 Local Installation

### Prerequisites
- Python 3.10+
- Git

### Setup
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YourUsername/cyberscan-ai.git](https://github.com/YourUsername/cyberscan-ai.git)
   cd cyberscan-ai

2. Create and activate a Virtual Environment (Recommended):
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate
   
   # Linux/macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application locally:
   ```bash
   python app.py
   ```
5. Navigate to `http://127.0.0.1:5000` in your browser.

## 🌍 Production Deployment (Render)

This application is pre-configured to be deployed on Render or Heroku. It uses `gunicorn` as the WSGI HTTP server.

1. Connect your GitHub repository to a new **Web Service** on [Render.com](https://render.com).
2. Set the build command:
   ```bash
   pip install -r requirements.txt
   ```
3. Set the start command (or leave blank if it defaults to the `Procfile`):
   ```bash
   gunicorn app:app --workers 1 --threads 4
   ```

> **Note:** The free tier of Render uses an ephemeral filesystem. Your local SQLite database (`cyberscan.db`) and user data will reset if the server goes to sleep. For a persistent production system, upgrade to a persistent disk or connect a managed PostgreSQL database.

## ⚠️ Disclaimer
**For Educational and Authorized Testing Purposes Only.**
CyberScan AI is built to assist developers and security professionals in identifying vulnerabilities within applications they own or have explicit permission to test. The authors are not responsible for any misuse of this tool.

---
*Developed with Python, Flask, and ❤️.*
