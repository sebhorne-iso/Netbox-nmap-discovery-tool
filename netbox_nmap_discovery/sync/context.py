from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from django.utils import timezone

from ..choices import SyncModeChoices

__all__ = ("Change", "SyncContext")


@dataclass
class Change:
    """One planned modification, used both to apply changes and to describe them in the review queue."""

    model: str  # device | interface | mac | ip | primary_ip | lag
    action: str  # create | update | assign
    key: str  # interface name / IP address / field
    values: dict = field(default_factory=dict)  # create: {field: value}; update: {field: [old, new]}
    sensitive: bool = False  # requires review in hybrid mode
    note: str = ""
    applied: bool = False
    error: str = ""

    def describe(self) -> str:
        if self.action == "create":
            details = ", ".join(f"{k}={v}" for k, v in self.values.items() if v not in (None, "", [], {}))
            text = f"Create {self.model} {self.key}" + (f" ({details})" if details else "")
        elif self.action == "update":
            details = ", ".join(f"{k}: {old!r} → {new!r}" for k, (old, new) in self.values.items())
            text = f"Update {self.model} {self.key}: {details}"
        else:
            details = ", ".join(f"{k}={v}" for k, v in self.values.items())
            text = f"{self.action.capitalize()} {self.model} {self.key}" + (f" ({details})" if details else "")
        if self.note:
            text += f" — {self.note}"
        if self.error:
            text += f" [failed: {self.error}]"
        return text

    def to_dict(self):
        return {"model": self.model, "action": self.action, "key": self.key, "values": self.values,
                "sensitive": self.sensitive, "note": self.note, "text": self.describe()}


@dataclass
class SyncContext:
    scan_target: object | None
    settings: dict
    mode: str = SyncModeChoices.HYBRID
    job: object | None = None
    user: object | None = None
    log_callback: object | None = None
    full_scan: bool = True  # False for single-host rediscovery (no miss counting)
    now: datetime = field(default_factory=timezone.now)
    stats: Counter = field(default_factory=Counter)
    # model label -> set of object pks seen during this run (for sightings / stale detection)
    seen: dict = field(default_factory=lambda: defaultdict(set))
    polled_devices: set = field(default_factory=set)  # device pks successfully polled via SNMP/SSH
    errors: list = field(default_factory=list)

    @property
    def now_text(self) -> str:
        """Timestamp for custom fields (second precision)."""
        return self.now.replace(microsecond=0).isoformat()

    @property
    def vrf(self):
        return getattr(self.scan_target, "vrf", None)

    @property
    def tenant(self):
        return getattr(self.scan_target, "tenant", None)

    @property
    def auto_apply_new(self) -> bool:
        return self.mode == SyncModeChoices.AUTOMATIC

    @property
    def auto_apply_updates(self) -> bool:
        return self.mode in (SyncModeChoices.AUTOMATIC, SyncModeChoices.HYBRID)

    def log(self, level, message):
        if self.log_callback:
            self.log_callback(level, message)
        else:
            logging.getLogger("netbox_nmap_discovery.sync").log(level, message)
        if level >= logging.ERROR:
            self.errors.append(message)

    def info(self, message):
        self.log(logging.INFO, message)

    def warning(self, message):
        self.log(logging.WARNING, message)

    def debug(self, message):
        self.log(logging.DEBUG, message)

    def mark_seen(self, obj):
        if obj is not None and obj.pk:
            self.seen[obj._meta.label_lower].add(obj.pk)
