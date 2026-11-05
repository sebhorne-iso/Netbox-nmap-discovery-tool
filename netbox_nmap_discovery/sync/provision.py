"""Idempotent creation of the custom fields and tags used by discovery."""
from __future__ import annotations

import logging

from django.db import transaction

logger = logging.getLogger("netbox_nmap_discovery.sync")

TAG_DISCOVERED = "discovered"
TAG_STALE = "discovery-stale"
TAG_AUTOCREATED = "discovery-autocreated"

TAGS = (
    (TAG_DISCOVERED, "Discovered", "2196f3", "Created by network discovery"),
    (TAG_STALE, "Discovery: stale", "ff9800", "No longer seen by network discovery"),
    (TAG_AUTOCREATED, "Discovery: auto-created", "9c27b0",
     "Device type / manufacturer / platform created automatically by discovery - please review"),
)

CF_LAST_SEEN = "discovery_last_seen"
CF_MAC = "discovery_mac_address"
CF_MAC_VENDOR = "discovery_mac_vendor"
CF_OS = "discovery_os_guess"
CF_PORTS = "discovery_open_ports"

# name, type, label, models, description
CUSTOM_FIELDS = (
    (CF_LAST_SEEN, "datetime", "Last seen", ("ipam.ipaddress", "dcim.device"),
     "When network discovery last saw this object"),
    (CF_MAC, "text", "MAC address (discovered)", ("ipam.ipaddress",), "MAC address learned via nmap or ARP"),
    (CF_MAC_VENDOR, "text", "MAC vendor", ("ipam.ipaddress",), "Vendor of the discovered MAC address (OUI)"),
    (CF_OS, "text", "OS guess", ("ipam.ipaddress", "dcim.device"), "Operating system detected by discovery"),
    (CF_PORTS, "longtext", "Open ports", ("ipam.ipaddress",), "Open TCP/UDP ports found by nmap"),
)

_provisioned = False


def ensure_custom_fields_and_tags(force: bool = False):
    """Create (or repair) discovery tags and custom fields. Cheap to call repeatedly."""
    global _provisioned
    if _provisioned and not force:
        return
    from core.models import ObjectType
    from django.apps import apps
    from extras.models import CustomField, Tag

    with transaction.atomic():
        for slug, name, color, description in TAGS:
            Tag.objects.get_or_create(slug=slug, defaults={"name": name, "color": color, "description": description})

        for name, type_, label, models, description in CUSTOM_FIELDS:
            field, created = CustomField.objects.get_or_create(
                name=name,
                defaults={
                    "type": type_,
                    "label": label,
                    "group_name": "Discovery",
                    "description": description,
                    "ui_editable": "no",
                    "required": False,
                },
            )
            wanted = [ObjectType.objects.get_for_model(apps.get_model(label_)) for label_ in models]
            existing = set(field.object_types.values_list("pk", flat=True))
            missing = [ot for ot in wanted if ot.pk not in existing]
            if missing:
                field.object_types.add(*missing)
            if created:
                logger.info("Created custom field %s", name)
    _provisioned = True


def get_tag(slug):
    from extras.models import Tag

    ensure_custom_fields_and_tags()
    return Tag.objects.get(slug=slug)
