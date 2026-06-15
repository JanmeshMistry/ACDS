# ============================================================
# ACDS - Core URL Patterns
# dashboard/core/urls.py
# ============================================================

from django.urls import path
from . import views

urlpatterns = [
    path("",        views.index,        name="dashboard"),
    path("blocked/",views.blocked_view, name="blocked"),
    path("logs/",   views.logs_view,    name="logs"),
]
