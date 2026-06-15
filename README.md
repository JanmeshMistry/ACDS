# ⚔️ Autonomous Cyber Defense System (ACDS)

A production-style SOC (Security Operations Center) pipeline that captures, analyzes, scores, and automatically blocks malicious actors in real time.

```
Attacker → Honeypot → MongoDB → Intel (VT+OTX) → Decision Engine → iptables Block → Dashboard
```

---

## 📁 Project Structure

```
ACDS/
├── honeypot/
│   ├── web_honeypot.py      # Flask fake login page
│   └── ssh_honeypot.py      # Paramiko SSH trap
├── intelligence/
│   ├── virustotal.py        # VirusTotal API integration
│   └── otx.py               # AlienVault OTX integration
├── engine/
│   ├── decision.py          # Full evaluation pipeline
│   └── scoring.py           # Composite risk scoring
├── defense/
│   └── firewall.py          # iptables auto-blocking
├── database/
│   └── mongo.py             # MongoDB schemas + helpers
├── dashboard/               # Django SOC dashboard
│   ├── settings.py
│   ├── urls.py
│   ├── core/
│   │   ├── views.py
│   │   ├── models.py
│   │   ├── urls.py
│   │   └── api_urls.py
│   └── templates/core/
│       ├── index.html       # Main dashboard
│       ├── blocked.html     # Blocked IP management
│       └── logs.html        # Event log viewer
├── utils/
│   ├── config.py            # Central configuration
│   ├── logger.py            # Colored rotating logger
│   ├── alerts.py            # Console + email alerts
│   └── geoip.py             # MaxMind GeoIP lookup
├── tests/
│   └── simulate_attack.py   # Attack simulation scripts
├── main.py                  # System orchestrator
├── manage.py                # Django management
├── requirements.txt
└── .env.example
```

---

## 🚀 Setup Instructions

### 1. Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip python3-venv mongodb iptables

# Start MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod
```

### 2. Clone & Install

```bash
git clone <your-repo>
cd ACDS

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp .env.example .env
nano .env   # Fill in your API keys and settings
```

**Minimum required:**
- `VIRUSTOTAL_API_KEY` — free at https://www.virustotal.com/gui/join-us
- `OTX_API_KEY` — free at https://otx.alienvault.com/

> Without API keys, the system runs in **mock mode** (simulated threat scores) so you can still test everything.

### 4. (Optional) GeoIP Database

```bash
mkdir -p data
# Download GeoLite2-City.mmdb from https://www.maxmind.com/ (free account)
# Place it at: data/GeoLite2-City.mmdb
```

### 5. Create log directory

```bash
mkdir -p logs
```

---

## ▶️ Running the System

### Start Everything at Once

```bash
# Requires root for iptables (or use sudo)
sudo python main.py --all
```

### Start Individual Modules

```bash
# Web honeypot only (port 5000)
python main.py --web-honeypot

# SSH honeypot only (port 2222)
sudo python main.py --ssh-honeypot

# Django dashboard only (port 8000)
python main.py --dashboard

# All except SSH (useful for dev)
python main.py --all --no-ssh
```

### Start Dashboard Manually (Django)

```bash
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

---

## 🧪 Running Attack Simulations

```bash
# Simulate web login brute-force (15 attempts)
python tests/simulate_attack.py --web

# Simulate path/vulnerability scanner
python tests/simulate_attack.py --scan

# Simulate rapid rate-limit attack
python tests/simulate_attack.py --rate-limit

# Inject and evaluate known-malicious IPs directly
python tests/simulate_attack.py --malicious-ip

# Simulate SSH brute-force (connects to localhost honeypot)
python tests/simulate_attack.py --ssh

# Run ALL scenarios
python tests/simulate_attack.py --all

# Custom attempt count
python tests/simulate_attack.py --web --count 30
```

---

## 🌐 Dashboard & API

| URL | Description |
|-----|-------------|
| `http://localhost:8000/` | Main SOC dashboard |
| `http://localhost:8000/logs/` | Event log viewer |
| `http://localhost:8000/blocked/` | Blocked IP management |
| `http://localhost:8000/api/stats/` | JSON: attack statistics |
| `http://localhost:8000/api/logs/` | JSON: recent events |
| `http://localhost:8000/api/blocked/` | JSON: blocked IPs |
| `http://localhost:8000/api/top-attackers/` | JSON: top offenders |
| `POST /api/unblock/<ip>/` | Remove firewall block |

---

## 🔍 How Each Module Works

### Honeypot → Intelligence → Decision Flow

```
1. Attacker hits web honeypot (port 5000) or SSH (port 2222)
2. IP, credentials, timestamp, User-Agent captured
3. GeoIP lookup performed
4. Event logged to MongoDB (logs collection)
5. Attacker record upserted (attackers collection)
6. Decision engine fires asynchronously:
   a. VirusTotal API → reputation score (0-100)
   b. AlienVault OTX API → pulse count + threat score
   c. Scoring engine computes composite risk:
      - VT score (35 pts) + OTX score (25 pts)
      - Brute-force detection (20 pts)
      - Rate limiting (10 pts)
      - Historical attempts (10 pts)
   d. Rules applied:
      IF vt_score >= 50 OR otx_score >= 50 → BLOCK
      IF brute_force_detected → BLOCK
      IF composite_score >= 70 → BLOCK
      IF composite_score >= 40 → MONITOR
      ELSE → ALLOW
7. If BLOCK:
   a. iptables -I INPUT -s <ip> -j DROP
   b. IP recorded in blocked_ips collection
   c. Alert fired (console + optional email)
8. Dashboard updates on next poll/refresh
```

### Risk Score Breakdown

| Factor | Max Points | Condition |
|--------|-----------|-----------|
| VirusTotal reputation | 35 | Scaled from VT malicious ratio |
| AlienVault OTX pulses | 25 | Scaled from pulse count |
| Brute-force detection | 20 | ≥5 attempts in 60 seconds |
| Rate limiting | 10 | >20 requests in 60 seconds |
| Historical attempts | 10 | Cumulative past activity |

---

## 📊 Sample Output Logs

```
2024-01-15 14:23:01 [WARNING]  honeypot.web – LOGIN ATTEMPT | IP=185.220.101.45  user=admin           pass=admin123    ua=Hydra v9.4
2024-01-15 14:23:01 [INFO]     intelligence.virustotal – VT result for 185.220.101.45 — malicious:8 suspicious:2 score:72
2024-01-15 14:23:01 [INFO]     intelligence.otx – OTX result for 185.220.101.45 — pulses:5 score:50
2024-01-15 14:23:01 [WARNING]  engine.decision – BLOCKED 185.220.101.45 — VT reputation score 72 >= 50 (score=81)
2024-01-15 14:23:01 [WARNING]  defense.firewall – 🔥 FIREWALL BLOCK applied: iptables -I INPUT -s 185.220.101.45 -j DROP
2024-01-15 14:23:01 [CRITICAL] utils.alerts –
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
AUTONOMOUS CYBER DEFENSE SYSTEM — ALERT
==================================================
Timestamp   : 2024-01-15T14:23:01.442Z
IP Address  : 185.220.101.45
Risk Score  : 81/100
Reason      : VT reputation score 72 >= 50
Action      : IP has been blocked via iptables
==================================================
```

### Sample API Response (`/api/stats/`)

```json
{
  "total_attacks": 127,
  "total_blocked": 14,
  "unique_attackers": 23,
  "attacks_per_hour": [
    {"_id": "2024-01-15T12:00:00Z", "count": 8},
    {"_id": "2024-01-15T13:00:00Z", "count": 34},
    {"_id": "2024-01-15T14:00:00Z", "count": 85}
  ]
}
```

### MongoDB Document Examples

**attackers collection:**
```json
{
  "ip": "185.220.101.45",
  "username": "admin",
  "service": "web",
  "country": "Germany",
  "risk_score": 81,
  "risk_level": "CRITICAL",
  "vt_score": 72,
  "otx_score": 50,
  "decision": "BLOCK",
  "attempt_count": 15,
  "first_seen": "2024-01-15T14:20:00Z",
  "last_seen": "2024-01-15T14:23:01Z"
}
```

**blocked_ips collection:**
```json
{
  "ip": "185.220.101.45",
  "reason": "VT reputation score 72 >= 50",
  "risk_score": 81,
  "blocked_at": "2024-01-15T14:23:01Z"
}
```

---

## ⚙️ Configuration Reference

All settings can be set in `.env` or as environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key |
| `OTX_API_KEY` | — | AlienVault OTX key |
| `MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection |
| `WEB_HONEYPOT_PORT` | `5000` | Flask honeypot port |
| `SSH_HONEYPOT_PORT` | `2222` | SSH honeypot port |
| `DASHBOARD_PORT` | `8000` | Django dashboard port |
| `BLOCK_REPUTATION_THRESHOLD` | `50` | VT/OTX score to trigger block |
| `BLOCK_ATTEMPT_THRESHOLD` | `5` | Attempts before brute-force flag |
| `BRUTE_FORCE_WINDOW_SECONDS` | `60` | Window for brute-force counting |
| `RISK_SCORE_BLOCK_THRESHOLD` | `70` | Composite score to block |
| `ALERT_EMAIL_ENABLED` | `false` | Enable email alerts |

---

## ⚠️ Security & Legal Notes

- **Deploy on isolated VMs or lab environments only.** Never expose honeypots to the internet unless you understand the legal and security implications.
- **iptables blocking requires root** (`sudo`). The system degrades gracefully without it — threats are still logged and scored.
- **Credentials captured by the honeypot are stored as plaintext in MongoDB** (intentionally — this is how honeypots work). Secure your MongoDB instance.
- API keys should **never** be committed to version control. Use `.env` only.
- GeoIP database (GeoLite2) requires a free MaxMind account. See https://www.maxmind.com/

---

## 🛠 Troubleshooting

| Problem | Solution |
|---------|----------|
| `Cannot connect to MongoDB` | Run `sudo systemctl start mongod` |
| `iptables: Permission denied` | Run with `sudo` |
| `Port 2222 in use` | Change `SSH_HONEYPOT_PORT` in `.env` |
| `VT/OTX returns mock data` | Add real API keys to `.env` |
| `GeoIP returns Unknown` | Download `GeoLite2-City.mmdb` to `data/` |
| `Dashboard shows no data` | Run attack simulator first: `python tests/simulate_attack.py --all` |
