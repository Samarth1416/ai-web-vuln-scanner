# CyberScan AI 🛡️

CyberScan AI is an intelligent, Python-based web vulnerability scanner designed to detect security flaws in web applications. It uses advanced scanning techniques combined with machine learning classification to identify vulnerabilities such as SQL Injection (SQLi), Cross-Site Scripting (XSS), missing security headers, and more.

## ✨ Features
- **Automated Scanning:** Crawl and scan entire target applications for vulnerabilities.
- **Background Processes:** Scans are executed dynamically in non-blocking threads.
- **Live Streamed Results:** View your scanning progress in real-time via Server-Sent Events (SSE).
- **Vulnerability Classification:** Scans are graded based on severity (Critical, High, Medium, Low, Info) using integrated analysis.
- **Detailed PDF/JSON Reports:** Export your scan results into professional formats.
- **User Dashboard:** Secure user authentication with an integrated SQLite database to maintain scan history.

## 🚀 Local Installation

### Prerequisites
- Python 3.8+
- Git

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/YourUsername/cyberscan-ai.git
   cd cyberscan-ai
   ```

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
