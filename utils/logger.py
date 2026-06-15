import logging
import os
import sys
from logging.handlers import RotatingFileHandler

try:
    import colorlog
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/acds.log")
LOG_TO_FILE = os.getenv("LOG_TO_FILE", "true").lower() == "true"

# make sure the logs folder exists before we try writing to it
os.makedirs(os.path.dirname(LOG_FILE) if os.path.dirname(LOG_FILE) else "logs", exist_ok=True)


def get_logger(name: str) -> logging.Logger:
    """
    Returns a named logger. Call this once at the top of each module:
        logger = get_logger(__name__)

    Logs go to console (with color if colorlog is installed) and to a
    rotating file that caps at 5MB and keeps 3 backups.
    """
    logger = logging.getLogger(name)

    # don't add handlers twice if this logger was already set up
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

    # console output
    if HAS_COLOR:
        fmt = colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s [%(levelname)s]%(reset)s %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                "DEBUG":    "cyan",
                "INFO":     "green",
                "WARNING":  "yellow",
                "ERROR":    "red",
                "CRITICAL": "bold_red",
            }
        )
    else:
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # file output - rotates at 5MB, keeps last 3 files
    if LOG_TO_FILE:
        fh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)

    logger.propagate = False
    return logger
