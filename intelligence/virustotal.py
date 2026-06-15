import time
import requests
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger
from utils.config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL, VIRUSTOTAL_RATE_LIMIT_DELAY

logger = get_logger("intelligence.virustotal")

# cache results for an hour so we don't hammer the API
_cache = {}
CACHE_TTL = 3600


def check_ip_reputation(ip: str) -> dict:
    """
    Asks VirusTotal what it knows about an IP address.

    Returns something like:
    {
        "ip": "1.2.3.4",
        "malicious_count": 8,
        "suspicious_count": 2,
        "harmless_count": 1,
        "reputation_score": 72,   # 0 = clean, 100 = definitely bad
        "country": "Germany",
        "as_owner": "Some ISP",
        "tags": ["malware", "scanner"],
        "error": None
    }
    """
    # no point checking private IPs against an external service
    if _is_private_ip(ip):
        logger.debug("Skipping VT check for private IP %s", ip)
        return _empty_result(ip, note="private_ip")

    # return cached result if it's still fresh
    if ip in _cache:
        result, cached_at = _cache[ip]
        if time.time() - cached_at < CACHE_TTL:
            logger.debug("VT cache hit for %s", ip)
            return result

    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        logger.warning("No VirusTotal API key set - using mock data for %s", ip)
        return _mock_result(ip)

    url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + harmless or 1

        # weight malicious hits twice as heavily as suspicious
        score = min(100, int(((malicious * 2 + suspicious) / (total * 2)) * 100))

        result = {
            "ip": ip,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "reputation_score": score,
            "country": attrs.get("country", "Unknown"),
            "as_owner": attrs.get("as_owner", "Unknown"),
            "tags": attrs.get("tags", []),
            "error": None,
        }

        _cache[ip] = (result, time.time())
        logger.info("VT result for %s - malicious=%d suspicious=%d score=%d", ip, malicious, suspicious, score)

        # free tier only allows ~4 requests per minute
        time.sleep(VIRUSTOTAL_RATE_LIMIT_DELAY)
        return result

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            logger.warning("VT rate limit hit for %s - waiting 60s then retrying", ip)
            time.sleep(60)
            return check_ip_reputation(ip)
        logger.error("VT HTTP error for %s: %s", ip, e)
        return _empty_result(ip, error=str(e))

    except requests.exceptions.RequestException as e:
        logger.error("VT request failed for %s: %s", ip, e)
        return _empty_result(ip, error=str(e))


def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _empty_result(ip: str, error=None, note="") -> dict:
    return {
        "ip": ip, "malicious_count": 0, "suspicious_count": 0,
        "harmless_count": 0, "reputation_score": 0,
        "country": "Unknown", "as_owner": "Unknown",
        "tags": [], "error": error, "note": note,
    }


def _mock_result(ip: str) -> dict:
    """Generates a deterministic fake score from the IP string, useful for testing."""
    import hashlib
    score = int(hashlib.md5(ip.encode()).hexdigest(), 16) % 100
    return {
        "ip": ip,
        "malicious_count": score // 10,
        "suspicious_count": score // 20,
        "harmless_count": max(0, 10 - score // 10),
        "reputation_score": score,
        "country": "Mockland",
        "as_owner": "Mock ISP",
        "tags": ["mock"],
        "error": None,
        "note": "mock_data",
    }
