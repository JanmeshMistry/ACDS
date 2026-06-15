# ============================================================
# ACDS - REST API URL Patterns
# dashboard/core/api_urls.py
# ============================================================

from django.urls import path
from . import views

urlpatterns = [
    path("stats/",              views.api_stats,         name="api-stats"),
    path("logs/",               views.api_logs,          name="api-logs"),
    path("blocked/",            views.api_blocked,       name="api-blocked"),
    path("top-attackers/",      views.api_top_attackers, name="api-top-attackers"),
    path("unblock/<str:ip>/",   views.api_unblock,       name="api-unblock"),
]
