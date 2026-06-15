import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger
from utils.config import GEOIP_DB_PATH

logger = get_logger("utils.geoip")

# we only open the database file once and reuse the reader
_reader = None


def _get_reader():
    """Opens the MaxMind database. Returns None if the file isn't there yet."""
    global _reader
    if _reader is not None:
        return _reader

    try:
        import geoip2.database
        if os.path.exists(GEOIP_DB_PATH):
            _reader = geoip2.database.Reader(GEOIP_DB_PATH)
            logger.info("GeoIP database loaded from %s", GEOIP_DB_PATH)
        else:
            logger.warning(
                "GeoIP database not found at %s. "
                "Download GeoLite2-City.mmdb from maxmind.com and put it in the data/ folder.",
                GEOIP_DB_PATH
            )
    except ImportError:
        logger.warning("geoip2 not installed - GeoIP lookups will be skipped")

    return _reader


def lookup(ip: str) -> dict:
    """
    Returns location info for an IP address.
    If the database isn't available, just returns a dict of unknowns
    so the rest of the system doesn't break.
    """
    fallback = {
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0,
    }

    reader = _get_reader()
    if reader is None:
        return fallback

    try:
        import ipaddress
        if ipaddress.ip_address(ip).is_private:
            return {**fallback, "country": "Private Network"}

        resp = reader.city(ip)
        return {
            "country": resp.country.name or "Unknown",
            "country_code": resp.country.iso_code or "XX",
            "city": resp.city.name or "Unknown",
            "latitude": float(resp.location.latitude or 0),
            "longitude": float(resp.location.longitude or 0),
        }
    except Exception as e:
        logger.debug("GeoIP lookup failed for %s: %s", ip, e)
        return fallback
