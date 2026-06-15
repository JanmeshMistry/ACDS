import time
import requests
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger
from utils.config import OTX_API_KEY, OTX_BASE_URL

logger = get_logger("intelligence.otx")

_cache = {}
CACHE_TTL = 3600


def check_ip_otx(ip: str) -> dict:
    """
    Checks AlienVault OTX for threat intelligence on an IP.
    OTX is community-driven - security researchers submit "pulses"
    (threat reports) when they spot malicious activity from an IP.

    Returns:
    {
        "ip": "1.2.3.4",
        "pulse_count": 5,         # how many threat reports mention this IP
        "threat_score": 50,       # pulse_count * 10, capped at 100
        "malware_families": [],
        "tags": [],
        "country": "Russia",
        "error": None
    }
    """
    if _is_private_ip(ip):
        return _empty_result(ip, note="private_ip")

    cached = _cache.get(ip)
    if cached and time.time() - cached[1] < CACHE_TTL:
        logger.debug("OTX cache hit for %s", ip)
        return cached[0]

    if OTX_API_KEY == "YOUR_ALIENVAULT_OTX_API_KEY_HERE":
        logger.warning("No OTX API key set - using mock data for %s", ip)
        return _mock_result(ip)

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"{OTX_BASE_URL}/indicators/IPv4/{ip}/general"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        pulse_count = pulse_info.get("count", 0)

        # pull out unique malware families and tags across all pulses
        malware_families = list({tag for p in pulses for tag in p.get("malware_families", [])})
        tags = list({tag for p in pulses for tag in p.get("tags", [])})

        threat_score = min(100, pulse_count * 10)

        result = {
            "ip": ip,
            "pulse_count": pulse_count,
            "threat_score": threat_score,
            "malware_families": malware_families,
            "tags": tags,
            "country": data.get("country_name", "Unknown"),
            "error": None,
        }

        _cache[ip] = (result, time.time())
        logger.info("OTX result for %s - pulses=%d score=%d", ip, pulse_count, threat_score)
        return result

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            logger.warning("OTX rate limit for %s - waiting 30s", ip)
            time.sleep(30)
            return check_ip_otx(ip)
        logger.error("OTX HTTP error for %s: %s", ip, e)
        return _empty_result(ip, error=str(e))

    except requests.exceptions.RequestException as e:
        logger.error("OTX request failed for %s: %s", ip, e)
        return _empty_result(ip, error=str(e))


def get_recent_pulses(limit: int = 10) -> list:
    """Fetches the latest threat pulses from the OTX subscription feed."""
    if OTX_API_KEY == "YOUR_ALIENVAULT_OTX_API_KEY_HERE":
        return []

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"{OTX_BASE_URL}/pulses/subscribed?limit={limit}"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json().get("results", [])
    except Exception as e:
        logger.error("OTX pulse feed error: %s", e)
        return []


def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _empty_result(ip: str, error=None, note="") -> dict:
    return {
        "ip": ip, "pulse_count": 0, "threat_score": 0,
        "malware_families": [], "tags": [], "country": "Unknown",
        "error": error, "note": note,
    }


def _mock_result(ip: str) -> dict:
    import hashlib
    score = int(hashlib.sha1(ip.encode()).hexdigest(), 16) % 80
    return {
        "ip": ip,
        "pulse_count": score // 10,
        "threat_score": score,
        "malware_families": ["mock_malware"] if score > 40 else [],
        "tags": ["mock"],
        "country": "Mockland",
        "error": None,
        "note": "mock_data",
    }
