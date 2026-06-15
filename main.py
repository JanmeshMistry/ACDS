#!/usr/bin/env python3
"""
ACDS - Autonomous Cyber Defense System
Entry point that starts all the components.

Usage:
    python main.py --all               start everything
    python main.py --web-honeypot      web honeypot only
    python main.py --ssh-honeypot      SSH honeypot only
    python main.py --dashboard         Django dashboard only
    python main.py --all --no-ssh      everything except SSH
"""

import argparse
import threading
import subprocess
import sys
import os
import time
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.logger import get_logger
from utils.config import WEB_HONEYPOT_PORT, SSH_HONEYPOT_PORT, DASHBOARD_PORT

logger = get_logger("main")

_threads = []
_shutdown = threading.Event()


def banner():
    print("""
    ╔══════════════════════════════════════════════╗
    ║   Autonomous Cyber Defense System (ACDS)    ║
    ║   Honeypot -> Intel -> Score -> Block        ║
    ╚══════════════════════════════════════════════╝
    """)


def start_web_honeypot():
    logger.info("Starting web honeypot on port %d", WEB_HONEYPOT_PORT)
    try:
        from honeypot.web_honeypot import run
        run()
    except Exception as e:
        logger.error("Web honeypot crashed: %s", e)


def start_ssh_honeypot():
    logger.info("Starting SSH honeypot on port %d", SSH_HONEYPOT_PORT)
    try:
        from honeypot.ssh_honeypot import run
        run()
    except Exception as e:
        logger.error("SSH honeypot crashed: %s", e)


def start_dashboard():
    logger.info("Starting dashboard on port %d", DASHBOARD_PORT)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dashboard.settings")
    try:
        # run migrations quietly before starting
        subprocess.run(
            [sys.executable, "manage.py", "migrate", "--run-syncdb", "--verbosity=0"],
            check=False
        )
        subprocess.run(
            [sys.executable, "manage.py", "runserver", f"0.0.0.0:{DASHBOARD_PORT}", "--noreload"],
            check=False
        )
    except Exception as e:
        logger.error("Dashboard crashed: %s", e)


def init_database():
    logger.info("Connecting to MongoDB...")
    try:
        from database.mongo import init_indexes
        init_indexes()
        logger.info("MongoDB ready")
    except Exception as e:
        logger.error("MongoDB init failed: %s", e)
        logger.warning("Continuing anyway - logs won't be saved until DB is available")


def signal_handler(sig, frame):
    logger.info("Shutting down ACDS...")
    _shutdown.set()
    sys.exit(0)


def main():
    banner()

    parser = argparse.ArgumentParser(description="ACDS - Autonomous Cyber Defense System")
    parser.add_argument("--all", action="store_true", help="Start all components")
    parser.add_argument("--web-honeypot", action="store_true", help="Start web honeypot")
    parser.add_argument("--ssh-honeypot", action="store_true", help="Start SSH honeypot")
    parser.add_argument("--dashboard", action="store_true", help="Start Django dashboard")
    parser.add_argument("--no-ssh", action="store_true", help="Skip SSH when using --all")
    args = parser.parse_args()

    if not any([args.all, args.web_honeypot, args.ssh_honeypot, args.dashboard]):
        parser.print_help()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    init_database()

    components = []

    if args.all or args.web_honeypot:
        components.append(("Web Honeypot", start_web_honeypot))

    if (args.all or args.ssh_honeypot) and not args.no_ssh:
        components.append(("SSH Honeypot", start_ssh_honeypot))

    if args.all or args.dashboard:
        components.append(("Dashboard", start_dashboard))

    for name, target in components:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        _threads.append(t)
        logger.info("Started: %s", name)
        time.sleep(0.5)

    logger.info("")
    logger.info("  ACDS is running. Ctrl+C to stop.")
    logger.info("  Web Honeypot -> http://localhost:%d", WEB_HONEYPOT_PORT)
    logger.info("  SSH Honeypot -> ssh root@localhost -p %d", SSH_HONEYPOT_PORT)
    logger.info("  Dashboard    -> http://localhost:%d", DASHBOARD_PORT)
    logger.info("")

    while not _shutdown.is_set():
        time.sleep(1)


if __name__ == "__main__":
    main()
