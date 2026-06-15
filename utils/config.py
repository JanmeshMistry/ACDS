import os
from dotenv import load_dotenv

load_dotenv()

# API keys - grab these from your .env file
# VirusTotal: https://www.virustotal.com/gui/join-us (free)
# OTX: https://otx.alienvault.com/ (also free)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY_HERE")
OTX_API_KEY = os.getenv("OTX_API_KEY", "YOUR_ALIENVAULT_OTX_API_KEY_HERE")

# MongoDB - default is fine for local dev
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = os.getenv("MONGO_DB", "acds_db")

# Honeypot ports
# SSH on 2222 so we don't need root (real SSH sits on 22)
WEB_HONEYPOT_HOST = os.getenv("WEB_HONEYPOT_HOST", "0.0.0.0")
WEB_HONEYPOT_PORT = int(os.getenv("WEB_HONEYPOT_PORT", 5000))

SSH_HONEYPOT_HOST = os.getenv("SSH_HONEYPOT_HOST", "0.0.0.0")
SSH_HONEYPOT_PORT = int(os.getenv("SSH_HONEYPOT_PORT", 2222))

# Block an IP if its reputation score hits this threshold (0-100)
BLOCK_REPUTATION_THRESHOLD = int(os.getenv("BLOCK_REPUTATION_THRESHOLD", 50))

# Block after this many attempts inside the brute force time window
BLOCK_ATTEMPT_THRESHOLD = int(os.getenv("BLOCK_ATTEMPT_THRESHOLD", 5))

# How far back (seconds) to look when counting brute force attempts
BRUTE_FORCE_WINDOW_SECONDS = int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", 60))

# If the combined risk score reaches this, block regardless of individual checks
RISK_SCORE_BLOCK_THRESHOLD = int(os.getenv("RISK_SCORE_BLOCK_THRESHOLD", 70))

# Path to the MaxMind GeoLite2 .mmdb file
# Free download at https://www.maxmind.com/ - just needs an account
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "data/GeoLite2-City.mmdb")

# Email alerts - flip ALERT_EMAIL_ENABLED=true in .env to switch on
ALERT_EMAIL_ENABLED = os.getenv("ALERT_EMAIL_ENABLED", "false").lower() == "true"
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "acds@yourdomain.com")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "admin@yourdomain.com")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "your_email@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "your_app_password")

# Django settings
DJANGO_SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "acds-super-secret-key-change-in-production")
DJANGO_DEBUG = os.getenv("DJANGO_DEBUG", "true").lower() == "true"
DJANGO_ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "*").split(",")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", 8000))

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/acds.log")
LOG_TO_FILE = os.getenv("LOG_TO_FILE", "true").lower() == "true"

# Max requests per IP before we flag it as rate-abusive
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", 20))
RATE_LIMIT_WINDOW_SEC = int(os.getenv("RATE_LIMIT_WINDOW_SEC", 60))

# VirusTotal
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_RATE_LIMIT_DELAY = 15  # free tier is ~4 req/min, so we sleep between calls

# AlienVault OTX
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
