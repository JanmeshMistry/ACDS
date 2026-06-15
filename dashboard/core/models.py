# ============================================================
# ACDS - Django Models
# dashboard/core/models.py
#
# Attack data lives in MongoDB (accessed via database/mongo.py).
# This file defines Django-managed models only for dashboard
# config / user preferences stored in SQLite.
# ============================================================

from django.db import models


class DashboardConfig(models.Model):
    """Key-value store for dashboard runtime configuration."""
    key   = models.CharField(max_length=100, unique=True)
    value = models.TextField()

    def __str__(self):
        return f"{self.key} = {self.value}"

    class Meta:
        verbose_name = "Dashboard Config"
        verbose_name_plural = "Dashboard Configs"


class AuditLog(models.Model):
    """Audit trail for manual actions taken via the dashboard."""
    ACTION_CHOICES = [
        ("unblock",  "Manual Unblock"),
        ("block",    "Manual Block"),
        ("config",   "Config Change"),
    ]
    action     = models.CharField(max_length=20, choices=ACTION_CHOICES)
    target_ip  = models.GenericIPAddressField(null=True, blank=True)
    operator   = models.CharField(max_length=100, default="admin")
    notes      = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} on {self.target_ip} at {self.created_at}"

    class Meta:
        ordering = ["-created_at"]
