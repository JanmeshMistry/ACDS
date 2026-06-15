import sys
import os
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, render_template_string, jsonify
from utils.logger import get_logger
from utils.config import WEB_HONEYPOT_HOST, WEB_HONEYPOT_PORT
from utils.geoip import lookup as geo_lookup
from database.mongo import upsert_attacker, insert_log
from engine.decision import evaluate

logger = get_logger("honeypot.web")

app = Flask(__name__)

# this looks like a legit admin login page - that's the whole point
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Admin Portal — Login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #1a1a2e; font-family: 'Segoe UI', sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; color: #eee;
    }
    .card {
      background: #16213e; border: 1px solid #0f3460;
      border-radius: 12px; padding: 40px; width: 380px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }
    h2 { text-align: center; margin-bottom: 8px; font-size: 1.4rem; color: #e94560; }
    p.sub { text-align: center; color: #888; font-size: 0.85rem; margin-bottom: 28px; }
    label { display: block; margin-bottom: 6px; font-size: 0.85rem; color: #aaa; }
    input {
      width: 100%; padding: 10px 14px; border-radius: 6px;
      border: 1px solid #0f3460; background: #0f3460;
      color: #eee; font-size: 0.95rem; margin-bottom: 18px;
    }
    button {
      width: 100%; padding: 12px; background: #e94560; border: none;
      border-radius: 6px; color: white; font-size: 1rem;
      cursor: pointer; font-weight: 600; letter-spacing: 0.5px;
    }
    button:hover { background: #c73652; }
    .error { color: #e94560; text-align: center; margin-top: 14px; font-size: 0.85rem; }
    .footer { text-align: center; margin-top: 20px; font-size: 0.75rem; color: #444; }
  </style>
</head>
<body>
  <div class="card">
    <h2>🔒 Admin Portal</h2>
    <p class="sub">Secure access — authorised personnel only</p>
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" placeholder="admin" required autocomplete="off">
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" required>
      <button type="submit">Sign In</button>
    </form>
    {% if error %}
    <p class="error">⚠ {{ error }}</p>
    {% endif %}
    <p class="footer">© 2024 SecureCorp Internal Systems</p>
  </div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET"])
def login_page():
    return render_template_string(LOGIN_HTML)


# these are paths that scanners always probe - we catch them all
@app.route("/admin", methods=["GET"])
@app.route("/wp-admin", methods=["GET"])
@app.route("/phpmyadmin", methods=["GET"])
@app.route("/.env", methods=["GET"])
@app.route("/config", methods=["GET"])
def decoy_paths():
    """Logs anyone who hits our decoy URLs - only a scanner would know to try these."""
    ip = _get_real_ip()
    path = request.path
    geo = geo_lookup(ip)

    event_data = {
        "event_type": "path_probe",
        "path": path,
        "user_agent": request.headers.get("User-Agent", ""),
        "geo": geo,
    }

    insert_log(ip, "path_probe", event_data)
    upsert_attacker(ip, {**event_data, **geo})

    # run evaluation in the background so we respond immediately
    threading.Thread(target=evaluate, args=(ip, event_data), daemon=True).start()

    logger.info("Path probe from %s on %s", ip, path)
    return render_template_string(LOGIN_HTML), 200


@app.route("/login", methods=["POST"])
def handle_login():
    """Someone submitted credentials. Log everything and keep them engaged."""
    ip = _get_real_ip()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ua = request.headers.get("User-Agent", "")
    geo = geo_lookup(ip)

    event_data = {
        "event_type": "login_attempt",
        "username": username,
        "password": password,  # we intentionally store this - it's the whole point
        "user_agent": ua,
        "service": "web",
        "geo": geo,
    }

    logger.warning("LOGIN ATTEMPT | IP=%-15s user=%-20s pass=%s ua=%s",
                   ip, username, password[:20], ua[:40])

    insert_log(ip, "login_attempt", event_data)
    upsert_attacker(ip, {**event_data, **geo})

    # don't block the response waiting for the intel APIs
    threading.Thread(target=evaluate, args=(ip, event_data), daemon=True).start()

    # always say wrong password - keeps them trying and gives us more data
    return render_template_string(LOGIN_HTML, error="Invalid username or password. Please try again."), 401


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "honeypot_active", "port": WEB_HONEYPOT_PORT})


def _get_real_ip() -> str:
    """Gets the real client IP, accounting for reverse proxies."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def run():
    logger.info("Web Honeypot starting on %s:%d", WEB_HONEYPOT_HOST, WEB_HONEYPOT_PORT)
    app.run(host=WEB_HONEYPOT_HOST, port=WEB_HONEYPOT_PORT, debug=False, threaded=True)


if __name__ == "__main__":
    run()
