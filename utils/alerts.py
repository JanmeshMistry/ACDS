import smtplib
import sys
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger

logger = get_logger("utils.alerts")


def send_alert(ip: str, risk_score: int, reason: str) -> None:
    """
    Fires an alert whenever a high-risk IP gets blocked.
    Always prints to console. Will also email if you've set
    ALERT_EMAIL_ENABLED=true in your .env.
    """
    from utils.config import (
        ALERT_EMAIL_ENABLED, ALERT_EMAIL_FROM, ALERT_EMAIL_TO,
        SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
    )

    timestamp = datetime.now(timezone.utc).isoformat()
    subject = f"[ACDS] Blocked malicious IP: {ip} (score={risk_score})"
    body = (
        f"ACDS ALERT\n"
        f"{'=' * 45}\n"
        f"Time        : {timestamp}\n"
        f"IP Address  : {ip}\n"
        f"Risk Score  : {risk_score}/100\n"
        f"Reason      : {reason}\n"
        f"Action      : Blocked via iptables\n"
        f"{'=' * 45}\n"
        f"Check the dashboard for full details.\n"
    )

    # always log to console so you see it even without email
    logger.critical("\n%s\n%s\n%s", "!" * 55, body, "!" * 55)

    if ALERT_EMAIL_ENABLED:
        _send_email(subject, body, ALERT_EMAIL_FROM, ALERT_EMAIL_TO,
                    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS)
    else:
        logger.info("Email alerts are off. Set ALERT_EMAIL_ENABLED=true in .env to turn on.")


def _send_email(subject, body, from_addr, to_addr, smtp_host, smtp_port, smtp_user, smtp_pass):
    """Sends a plain text alert over SMTP with TLS."""
    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, to_addr, msg.as_string())
        logger.info("Alert email sent to %s", to_addr)

    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP login failed - double check SMTP_USER and SMTP_PASS in .env")
    except smtplib.SMTPException as e:
        logger.error("SMTP error while sending alert: %s", e)
    except Exception as e:
        logger.error("Could not send alert email: %s", e)
