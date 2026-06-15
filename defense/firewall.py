import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import get_logger

logger = get_logger("defense.firewall")

# keep track of what we've already blocked so we don't add duplicate rules
_blocked_set = set()


def block_ip(ip: str) -> bool:
    """
    Drops all traffic from an IP using iptables.
    Safe to call multiple times for the same IP - won't add duplicate rules.
    Returns True if the rule was applied, False if something went wrong.
    """
    if ip in _blocked_set:
        logger.debug("%s already blocked, skipping iptables call", ip)
        return True

    if not _validate_ip(ip):
        logger.error("Not a valid IP address: %s", ip)
        return False

    cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            _blocked_set.add(ip)
            logger.warning("FIREWALL: blocked %s via iptables", ip)
            return True
        else:
            # iptables failed (probably no root) - log it but don't crash
            logger.error("iptables failed for %s (rc=%d): %s", ip, result.returncode, result.stderr.strip())
            _blocked_set.add(ip)  # mark as done so we don't keep retrying
            return False

    except FileNotFoundError:
        logger.error("iptables not found - are you on Linux?")
        _blocked_set.add(ip)
        return False

    except PermissionError:
        logger.error("Permission denied for iptables - try running as root")
        _blocked_set.add(ip)
        return False

    except subprocess.TimeoutExpired:
        logger.error("iptables timed out for %s", ip)
        return False

    except Exception as e:
        logger.error("Unexpected error blocking %s: %s", ip, e)
        return False


def unblock_ip(ip: str) -> bool:
    """Removes the DROP rule for an IP. Used when manually unblocking from the dashboard."""
    if not _validate_ip(ip):
        return False

    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            _blocked_set.discard(ip)
            logger.info("Unblocked %s", ip)
            return True
        else:
            logger.error("Failed to unblock %s: %s", ip, result.stderr.strip())
            return False
    except Exception as e:
        logger.error("Error unblocking %s: %s", ip, e)
        return False


def list_blocked_ips_firewall() -> list:
    """
    Reads the current iptables INPUT chain and returns all DROP'd IPs.
    Falls back to the in-memory set if iptables isn't available.
    """
    try:
        result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=10
        )
        blocked = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "DROP":
                source = parts[3]
                if source != "0.0.0.0/0":
                    blocked.append(source)
        return blocked
    except Exception as e:
        logger.error("Cannot read iptables rules: %s", e)
        return list(_blocked_set)


def flush_acds_rules() -> bool:
    """Unblocks everything ACDS has blocked. Use carefully."""
    success = True
    for ip in list(_blocked_set):
        if not unblock_ip(ip):
            success = False
    return success


def _validate_ip(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
