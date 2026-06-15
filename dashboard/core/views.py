# ============================================================
# ACDS - Django Dashboard Views
# dashboard/core/views.py
# ============================================================

import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from database.mongo import (
    get_attack_stats, get_recent_logs, get_blocked_ips, get_top_attackers
)
from defense.firewall import unblock_ip, list_blocked_ips_firewall
from database.mongo import blocked_ips_col
from utils.logger import get_logger

logger = get_logger("dashboard.views")


# ── HTML Dashboard ───────────────────────────────────────

def index(request):
    """Main SOC dashboard view."""
    try:
        stats        = get_attack_stats()
        recent_logs  = get_recent_logs(limit=20)
        blocked_ips  = get_blocked_ips(limit=20)
        top_attackers= get_top_attackers(limit=10)

        # Serialise datetime objects for template
        for log in recent_logs:
            if hasattr(log.get("timestamp"), "isoformat"):
                log["timestamp"] = log["timestamp"].isoformat()

        for bip in blocked_ips:
            if hasattr(bip.get("blocked_at"), "isoformat"):
                bip["blocked_at"] = bip["blocked_at"].isoformat()

        context = {
            "stats":         stats,
            "recent_logs":   recent_logs,
            "blocked_ips":   blocked_ips,
            "top_attackers": top_attackers,
            "chart_data":    json.dumps(stats.get("attacks_per_hour", [])),
        }
    except Exception as e:
        logger.error("Dashboard render error: %s", e)
        context = {"error": str(e), "stats": {}, "recent_logs": [], "blocked_ips": []}

    return render(request, "core/index.html", context)


def blocked_view(request):
    """Blocked IPs management page."""
    blocked = get_blocked_ips(limit=200)
    for b in blocked:
        if hasattr(b.get("blocked_at"), "isoformat"):
            b["blocked_at"] = b["blocked_at"].isoformat()
    return render(request, "core/blocked.html", {"blocked_ips": blocked})


def logs_view(request):
    """Recent logs page."""
    logs = get_recent_logs(limit=100)
    for log in logs:
        if hasattr(log.get("timestamp"), "isoformat"):
            log["timestamp"] = log["timestamp"].isoformat()
    return render(request, "core/logs.html", {"logs": logs})


# ── REST API ─────────────────────────────────────────────

def api_stats(request):
    """GET /api/stats/ — dashboard statistics."""
    try:
        stats = get_attack_stats()
        # Convert datetime objects
        for item in stats.get("attacks_per_hour", []):
            pass  # already strings from aggregation
        return JsonResponse(stats, safe=False)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


def api_logs(request):
    """GET /api/logs/?limit=50 — recent log entries."""
    limit = int(request.GET.get("limit", 50))
    logs  = get_recent_logs(limit=limit)
    for log in logs:
        if hasattr(log.get("timestamp"), "isoformat"):
            log["timestamp"] = log["timestamp"].isoformat()
    return JsonResponse(logs, safe=False)


def api_blocked(request):
    """GET /api/blocked/ — blocked IP list."""
    blocked = get_blocked_ips(limit=200)
    for b in blocked:
        if hasattr(b.get("blocked_at"), "isoformat"):
            b["blocked_at"] = b["blocked_at"].isoformat()
    return JsonResponse(blocked, safe=False)


def api_top_attackers(request):
    """GET /api/top-attackers/ — top attacking IPs."""
    return JsonResponse(get_top_attackers(limit=10), safe=False)


@csrf_exempt
@require_http_methods(["POST"])
def api_unblock(request, ip: str):
    """POST /api/unblock/<ip>/ — remove firewall block for an IP."""
    try:
        fw_ok = unblock_ip(ip)
        blocked_ips_col().delete_one({"ip": ip})
        return JsonResponse({"success": True, "ip": ip, "firewall_removed": fw_ok})
    except Exception as e:
        logger.error("Unblock API error for %s: %s", ip, e)
        return JsonResponse({"success": False, "error": str(e)}, status=500)
