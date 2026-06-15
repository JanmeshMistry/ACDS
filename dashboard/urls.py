# ============================================================
# ACDS - Django URL Configuration
# dashboard/urls.py
# ============================================================

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/",  admin.site.urls),
    path("",        include("dashboard.core.urls")),
    path("api/",    include("dashboard.core.api_urls")),
]
