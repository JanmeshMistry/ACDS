#!/usr/bin/env python3
"""
Attack simulator for testing ACDS locally.
Throws fake attacks at the honeypot so you can see the full pipeline in action.

Usage:
    python tests/simulate_attack.py --web          brute-force the login page
    python tests/simulate_attack.py --scan         run a path scanner
    python tests/simulate_attack.py --rate-limit   flood requests quickly
    python tests/simulate_attack.py --malicious-ip inject IPs straight into the engine
    python tests/simulate_attack.py --ssh          SSH brute-force (hits localhost only)
    python tests/simulate_attack.py --all          run everything
"""

import sys
import os
import argparse
import time
import requests
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import WEB_HONEYPOT_PORT, SSH_HONEYPOT_PORT
from utils.logger import get_logger

logger = get_logger("simulator")

WEB_BASE = f"http://localhost:{WEB_HONEYPOT_PORT}"

# a mix of real scanner IPs that show up in threat feeds
FAKE_IPS = [
    "45.33.32.156",     # Shodan
    "198.20.69.74",     # Shodan
    "185.220.101.45",   # Tor exit node
    "192.241.240.5",    # known scanner
    "222.186.42.11",    # frequent attacker in threat feeds
    "10.0.0.{n}",       # private - tests our IP filtering
]

USERNAMES = [
    "admin", "root", "administrator", "user", "test", "guest",
    "oracle", "postgres", "ubuntu", "pi", "deploy", "ansible",
]

PASSWORDS = [
    "admin", "password", "123456", "root", "admin123", "toor",
    "letmein", "qwerty", "12345678", "pass", "changeme", "secret",
]

# paths that real vulnerability scanners probe
SCAN_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config",
    "/backup", "/.git/config", "/api/v1/users", "/shell.php",
    "/xmlrpc.php", "/wp-login.php", "/.htpasswd",
]


def simulate_web_brute_force(ip_override=None, count=15):
    """Hammers the login form with credential guesses."""
    logger.info("=== Web brute-force: %d attempts ===", count)

    session = requests.Session()
    fake_ip = ip_override or random.choice(FAKE_IPS).replace("{n}", str(random.randint(1, 254)))
    headers = {"X-Forwarded-For": fake_ip, "User-Agent": "Hydra v9.4"}

    for i in range(count):
        user = random.choice(USERNAMES)
        pwd = random.choice(PASSWORDS)
        try:
            resp = session.post(
                f"{WEB_BASE}/login",
                data={"username": user, "password": pwd},
                headers=headers,
                timeout=5,
                allow_redirects=False,
            )
            logger.info("[%02d] user=%-15s pass=%-12s status=%d ip=%s", i + 1, user, pwd, resp.status_code, fake_ip)
        except requests.exceptions.ConnectionError:
            logger.error("Can't connect to %s - is the honeypot running?", WEB_BASE)
            return
        time.sleep(random.uniform(0.1, 0.5))

    logger.info("=== Brute-force done ===\n")


def simulate_path_scan(ip_override=None):
    """Probes common vulnerable paths like a scanner would."""
    logger.info("=== Path scanner ===")

    fake_ip = ip_override or random.choice(FAKE_IPS).replace("{n}", str(random.randint(1, 254)))
    headers = {"X-Forwarded-For": fake_ip, "User-Agent": "Nikto/2.1.6"}
    session = requests.Session()

    for path in SCAN_PATHS:
        try:
            resp = session.get(f"{WEB_BASE}{path}", headers=headers, timeout=5, allow_redirects=False)
            logger.info("SCAN %-30s status=%d ip=%s", path, resp.status_code, fake_ip)
        except requests.exceptions.ConnectionError:
            logger.error("Can't connect to %s", WEB_BASE)
            return
        time.sleep(0.2)

    logger.info("=== Path scan done ===\n")


def simulate_malicious_ip_injection():
    """
    Skips the honeypot and pushes known-bad IPs directly into the decision engine.
    Good for testing scoring and blocking without needing a real attacker.
    """
    logger.info("=== Direct IP injection test ===")

    from engine.decision import evaluate
    from database.mongo import init_indexes
    init_indexes()

    test_cases = [
        {
            "ip": "185.220.101.45",
            "event": {"event_type": "login_attempt", "username": "root", "password": "toor", "service": "ssh"},
            "label": "Tor exit node",
        },
        {
            "ip": "222.186.42.11",
            "event": {"event_type": "login_attempt", "username": "admin", "password": "admin123", "service": "web"},
            "label": "Known scanner IP",
        },
        {
            "ip": "127.0.0.1",
            "event": {"event_type": "login_attempt", "username": "test", "password": "test", "service": "web"},
            "label": "Localhost - should NOT be blocked",
        },
    ]

    for case in test_cases:
        logger.info("Testing %s (%s)", case["ip"], case["label"])
        try:
            result = evaluate(case["ip"], case["event"])
            logger.info("  -> %s | score=%d | level=%s",
                        result["decision"], result["risk_score"], result.get("risk_level", "?"))
        except Exception as e:
            logger.error("  -> Error: %s", e)
        time.sleep(1)

    logger.info("=== IP injection done ===\n")


def simulate_rate_limit_attack():
    """Sends a flood of requests really fast to trigger rate limiting."""
    logger.info("=== Rate limit flood ===")

    fake_ip = "203.0.113.99"  # TEST-NET-3, safe to use in tests
    headers = {"X-Forwarded-For": fake_ip, "User-Agent": "curl/7.88"}
    session = requests.Session()

    for i in range(25):
        try:
            session.post(
                f"{WEB_BASE}/login",
                data={"username": "admin", "password": str(i)},
                headers=headers,
                timeout=3,
            )
            if i % 5 == 0:
                logger.info("Sent %d requests from %s...", i + 1, fake_ip)
        except requests.exceptions.ConnectionError:
            logger.error("Can't connect to %s", WEB_BASE)
            return
        time.sleep(0.05)  # fast enough to trigger rate limiting

    logger.info("=== Rate limit flood done ===\n")


def simulate_ssh_brute_force():
    """
    Connects to the SSH honeypot on localhost and tries some passwords.
    Totally safe - it only hits our own honeypot.
    """
    logger.info("=== SSH brute-force ===")

    try:
        import paramiko
    except ImportError:
        logger.error("paramiko not installed, skipping SSH test")
        return

    for i in range(8):
        user = random.choice(USERNAMES)
        pwd = random.choice(PASSWORDS)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname="127.0.0.1",
                port=SSH_HONEYPOT_PORT,
                username=user,
                password=pwd,
                timeout=4,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.AuthenticationException:
            logger.info("[%02d] SSH rejected: user=%-15s pass=%s", i + 1, user, pwd)
        except Exception as e:
            logger.warning("[%02d] SSH connection failed: %s", i + 1, e)
        finally:
            client.close()

        time.sleep(0.5)

    logger.info("=== SSH done ===\n")


def main():
    parser = argparse.ArgumentParser(description="ACDS Attack Simulator")
    parser.add_argument("--web", action="store_true", help="Web login brute-force")
    parser.add_argument("--ssh", action="store_true", help="SSH brute-force")
    parser.add_argument("--scan", action="store_true", help="Path scanner")
    parser.add_argument("--malicious-ip", action="store_true", help="Inject IPs into decision engine")
    parser.add_argument("--rate-limit", action="store_true", help="Request flood")
    parser.add_argument("--all", action="store_true", help="Run all scenarios")
    parser.add_argument("--count", type=int, default=15, help="Login attempts for --web")
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        return

    print(f"\n{'=' * 55}")
    print("  ACDS Attack Simulator")
    print(f"  Web target: {WEB_BASE}")
    print(f"  SSH target: localhost:{SSH_HONEYPOT_PORT}")
    print(f"{'=' * 55}\n")

    if args.all or args.web:
        simulate_web_brute_force(count=args.count)

    if args.all or args.scan:
        simulate_path_scan()

    if args.all or args.rate_limit:
        simulate_rate_limit_attack()

    if args.all or args.malicious_ip:
        simulate_malicious_ip_injection()

    if args.all or args.ssh:
        simulate_ssh_brute_force()

    print(f"\nDone. Check the dashboard at http://localhost:8000\n")


if __name__ == "__main__":
    main()
