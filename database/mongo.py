from datetime import datetime, timezone
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymongo import MongoClient, ASCENDING, DESCENDING, errors as mongo_errors
from utils.logger import get_logger
from utils.config import MONGO_URI, MONGO_DB

logger = get_logger("database.mongo")

# single client instance shared across the app
_client = None


def get_db():
    """Returns the MongoDB database. Creates the connection on first call."""
    global _client
    if _client is None:
        try:
            _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            _client.admin.command("ping")  # crash early if mongo isn't running
            logger.info("Connected to MongoDB at %s", MONGO_URI)
        except mongo_errors.ServerSelectionTimeoutError as e:
            logger.error("Cannot reach MongoDB - is mongod running? Error: %s", e)
            raise
    return _client[MONGO_DB]


# shorthand accessors so we don't repeat get_db()["collection"] everywhere
def attackers_col():
    return get_db()["attackers"]

def logs_col():
    return get_db()["logs"]

def blocked_ips_col():
    return get_db()["blocked_ips"]


def init_indexes():
    """
    Sets up indexes for the three collections.
    Call this once at startup - safe to call multiple times.
    """
    db = get_db()

    db["attackers"].create_index([("ip", ASCENDING)], unique=True)
    db["attackers"].create_index([("last_seen", DESCENDING)])

    db["logs"].create_index([("ip", ASCENDING)])
    db["logs"].create_index([("timestamp", DESCENDING)])
    db["logs"].create_index([("event_type", ASCENDING)])

    db["blocked_ips"].create_index([("ip", ASCENDING)], unique=True)
    db["blocked_ips"].create_index([("blocked_at", DESCENDING)])

    logger.info("MongoDB indexes ready")


def upsert_attacker(ip: str, data: dict) -> None:
    """
    Creates or updates the attacker document for this IP.
    Automatically increments attempt_count and updates last_seen.
    """
    now = datetime.now(timezone.utc)
    attackers_col().update_one(
        {"ip": ip},
        {
            "$set": {**data, "last_seen": now},
            "$inc": {"attempt_count": 1},
            "$setOnInsert": {"first_seen": now, "ip": ip},
        },
        upsert=True,
    )


def insert_log(ip: str, event_type: str, details: dict) -> str:
    """Writes a log entry and returns its MongoDB ID as a string."""
    doc = {
        "ip": ip,
        "event_type": event_type,
        "details": details,
        "timestamp": datetime.now(timezone.utc),
    }
    result = logs_col().insert_one(doc)
    return str(result.inserted_id)


def is_ip_blocked(ip: str) -> bool:
    """Returns True if this IP is in the blocked list."""
    return blocked_ips_col().find_one({"ip": ip}) is not None


def record_blocked_ip(ip: str, reason: str, risk_score: int) -> None:
    """Saves a blocked IP to the database. Safe to call more than once for the same IP."""
    now = datetime.now(timezone.utc)
    blocked_ips_col().update_one(
        {"ip": ip},
        {
            "$set": {
                "ip": ip,
                "reason": reason,
                "risk_score": risk_score,
                "blocked_at": now,
            }
        },
        upsert=True,
    )
    logger.info("Saved blocked IP to DB: %s (score=%d)", ip, risk_score)


def get_recent_logs(limit: int = 50) -> list:
    cursor = logs_col().find({}, {"_id": 0}).sort("timestamp", DESCENDING).limit(limit)
    return list(cursor)


def get_blocked_ips(limit: int = 100) -> list:
    cursor = blocked_ips_col().find({}, {"_id": 0}).sort("blocked_at", DESCENDING).limit(limit)
    return list(cursor)


def get_attack_stats() -> dict:
    db = get_db()
    total_attacks = db["logs"].count_documents({"event_type": "login_attempt"})
    total_blocked = db["blocked_ips"].count_documents({})
    unique_attackers = db["attackers"].count_documents({})

    # group login attempts by hour for the timeline chart
    pipeline = [
        {"$match": {"event_type": "login_attempt"}},
        {
            "$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%dT%H:00:00Z", "date": "$timestamp"}},
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": ASCENDING}},
        {"$limit": 24},
    ]
    attacks_per_hour = list(db["logs"].aggregate(pipeline))

    return {
        "total_attacks": total_attacks,
        "total_blocked": total_blocked,
        "unique_attackers": unique_attackers,
        "attacks_per_hour": attacks_per_hour,
    }


def get_top_attackers(limit: int = 10) -> list:
    cursor = attackers_col().find(
        {}, {"_id": 0, "ip": 1, "attempt_count": 1, "risk_score": 1, "country": 1}
    ).sort("attempt_count", DESCENDING).limit(limit)
    return list(cursor)
