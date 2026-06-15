import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone, timedelta
from utils.logger import get_logger
from utils.config import (
    BLOCK_REPUTATION_THRESHOLD,
    BLOCK_ATTEMPT_THRESHOLD,
    RISK_SCORE_BLOCK_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
)
from engine.scoring import calculate_risk_score, classify_risk
from intelligence.virustotal import check_ip_reputation
from intelligence.otx import check_ip_otx
from database.mongo import (
    upsert_attacker, insert_log, is_ip_blocked,
    record_blocked_ip, attackers_col, logs_col,
)
from defense.firewall import block_ip as fw_block_ip
from utils.alerts import send_alert

logger = get_logger("engine.decision")


def _count_recent_attempts(ip: str, window_seconds: int) -> int:
    """Counts how many login attempts we've seen from this IP in the last N seconds."""
    since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    return logs_col().count_documents({
        "ip": ip,
        "event_type": "login_attempt",
        "timestamp": {"$gte": since},
    })


def _is_rate_limited(ip: str) -> bool:
    """Returns True if this IP is sending requests faster than our threshold."""
    from utils.config import RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SEC
    recent = _count_recent_attempts(ip, RATE_LIMIT_WINDOW_SEC)
    return recent > RATE_LIMIT_MAX_REQUESTS


def evaluate(ip: str, event_data: dict) -> dict:
    """
    The main pipeline. Takes an IP and event info, runs it through
    threat intel and scoring, then decides what to do.

    Returns a report dict with the decision and all the supporting data.

    Decision can be: BLOCK, MONITOR, ALLOW, or ALREADY_BLOCKED
    """
    logger.info("Evaluating %s (event=%s)", ip, event_data.get("event_type", "?"))

    # if we already blocked them, no need to re-run everything
    if is_ip_blocked(ip):
        logger.info("%s is already blocked, skipping", ip)
        insert_log(ip, "already_blocked", event_data)
        return {"ip": ip, "decision": "ALREADY_BLOCKED", "risk_score": 100}

    # pull threat intelligence from both sources
    vt_result = check_ip_reputation(ip)
    otx_result = check_ip_otx(ip)

    insert_log(ip, "intel_check", {
        "vt_reputation_score": vt_result.get("reputation_score"),
        "otx_threat_score": otx_result.get("threat_score"),
        "vt_malicious_count": vt_result.get("malicious_count"),
        "otx_pulse_count": otx_result.get("pulse_count"),
    })

    # gather attempt history
    attacker_doc = attackers_col().find_one({"ip": ip}) or {}
    attempt_count = attacker_doc.get("attempt_count", 0) + 1
    recent_attempts = _count_recent_attempts(ip, BRUTE_FORCE_WINDOW_SECONDS)
    rate_limited = _is_rate_limited(ip)

    # calculate the composite risk score
    score_breakdown = calculate_risk_score(vt_result, otx_result, attempt_count, recent_attempts, rate_limited)
    risk_score = score_breakdown["total_risk_score"]
    risk_level = classify_risk(risk_score)

    # apply the decision rules - first match wins
    decision = "ALLOW"
    block_reason = ""

    if vt_result.get("reputation_score", 0) >= BLOCK_REPUTATION_THRESHOLD:
        decision = "BLOCK"
        block_reason = f"VirusTotal score {vt_result['reputation_score']} >= {BLOCK_REPUTATION_THRESHOLD}"

    elif otx_result.get("threat_score", 0) >= BLOCK_REPUTATION_THRESHOLD:
        decision = "BLOCK"
        block_reason = f"OTX score {otx_result['threat_score']} >= {BLOCK_REPUTATION_THRESHOLD}"

    elif score_breakdown["brute_force_detected"]:
        decision = "BLOCK"
        block_reason = f"Brute force: {recent_attempts} attempts in {BRUTE_FORCE_WINDOW_SECONDS}s"

    elif risk_score >= RISK_SCORE_BLOCK_THRESHOLD:
        decision = "BLOCK"
        block_reason = f"Composite risk score {risk_score} >= {RISK_SCORE_BLOCK_THRESHOLD}"

    elif risk_score >= 40:
        decision = "MONITOR"

    # if we're blocking, do it now
    if decision == "BLOCK":
        fw_ok = fw_block_ip(ip)
        record_blocked_ip(ip, block_reason, risk_score)
        insert_log(ip, "blocked", {
            "reason": block_reason,
            "risk_score": risk_score,
            "firewall_ok": fw_ok,
        })
        logger.warning("BLOCKED %s - %s (score=%d)", ip, block_reason, risk_score)

        # only alert on high/critical to avoid noise
        if risk_level in ("HIGH", "CRITICAL"):
            send_alert(ip, risk_score, block_reason)

    # update the attacker record with latest info
    geo = {"country": vt_result.get("country") or otx_result.get("country", "Unknown")}
    upsert_attacker(ip, {
        **event_data,
        **geo,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "vt_score": vt_result.get("reputation_score"),
        "otx_score": otx_result.get("threat_score"),
        "decision": decision,
    })

    logger.info("Decision for %s: %s | score=%d (%s)", ip, decision, risk_score, risk_level)

    return {
        "ip": ip,
        "decision": decision,
        "block_reason": block_reason,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "score_breakdown": score_breakdown,
        "vt_result": vt_result,
        "otx_result": otx_result,
        "attempt_count": attempt_count,
        "brute_force": score_breakdown["brute_force_detected"],
        "rate_limited": rate_limited,
    }
