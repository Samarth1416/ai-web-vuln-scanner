import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyberscan-ai-secret-2026')
    DATABASE = os.path.join(os.path.dirname(__file__), 'cyberscan.db')
    REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')
    SCAN_TIMEOUT = 10
    MAX_REDIRECTS = 3
    DEBUG = True
