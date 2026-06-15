import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger
from utils.config import (
    BLOCK_ATTEMPT_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SEC,
)

logger = get_logger("engine.scoring")


def calculate_risk_score(vt_result, otx_result, attempt_count, recent_attempts, is_rate_limited) -> dict:
    """
    Combines all available signals into a single risk score from 0 to 100.

    How the points break down:
        VirusTotal reputation   ->  up to 35 pts
        OTX threat intel        ->  up to 25 pts
        Brute force activity    ->  up to 20 pts
        Rate limiting           ->  up to 10 pts
        Historical attempts     ->  up to 10 pts
        ------------------------------------------------
        Total                   ->  100 pts max
    """

    # VirusTotal - scale their 0-100 score into our 35 pt bucket
    vt_raw = vt_result.get("reputation_score", 0)
    vt_factor = int((vt_raw / 100) * 35)

    # OTX - same idea, into our 25 pt bucket
    otx_raw = otx_result.get("threat_score", 0)
    otx_factor = int((otx_raw / 100) * 25)

    # Brute force - did they hammer us in the time window?
    brute_force_detected = recent_attempts >= BLOCK_ATTEMPT_THRESHOLD
    brute_factor = 0
    if brute_force_detected:
        # scale up the more they go over the threshold, max at 20
        ratio = min(recent_attempts / BLOCK_ATTEMPT_THRESHOLD, 2.0)
        brute_factor = int(ratio * 10)
    elif recent_attempts > 1:
        # not quite threshold, but still suspicious
        brute_factor = recent_attempts * 2
    brute_factor = min(brute_factor, 20)

    # Rate limiting - flat 10 pts if they're flooding us
    rate_factor = 10 if is_rate_limited else 0

    # Historical - adds up slowly the more attempts we've seen from this IP overall
    attempt_factor = min(attempt_count // 10, 10)

    total = min(vt_factor + otx_factor + brute_factor + rate_factor + attempt_factor, 100)

    logger.debug(
        "Score breakdown for %d total / %d recent attempts -> %d "
        "(vt=%d otx=%d bf=%d rl=%d hist=%d)",
        attempt_count, recent_attempts, total,
        vt_factor, otx_factor, brute_factor, rate_factor, attempt_factor,
    )

    return {
        "vt_factor": vt_factor,
        "otx_factor": otx_factor,
        "brute_force_factor": brute_factor,
        "rate_limit_factor": rate_factor,
        "attempt_history_factor": attempt_factor,
        "total_risk_score": total,
        "brute_force_detected": brute_force_detected,
        "is_rate_limited": is_rate_limited,
    }


def classify_risk(score: int) -> str:
    """Turns the numeric score into a human-readable label."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "MINIMAL"
