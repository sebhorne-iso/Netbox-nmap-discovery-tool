from __future__ import annotations

from django.conf import settings

from . import DEFAULT_SETTINGS

__all__ = ("get_settings",)


def get_settings() -> dict:
    """Return the plugin settings: defaults overlaid with PLUGINS_CONFIG['netbox_nmap_discovery']."""
    configured = (getattr(settings, "PLUGINS_CONFIG", {}) or {}).get("netbox_nmap_discovery") or {}
    return {**DEFAULT_SETTINGS, **configured}
