"""Device-role rule evaluation (kept free of ORM queries so it can be unit tested)."""
from __future__ import annotations

import re

from ..engine.results import HostResult

__all__ = ("rule_matches", "select_role_rule")


def _search(pattern: str, value: str | None) -> bool:
    if not pattern:
        return True
    if not value:
        return False
    try:
        return re.search(pattern, value, re.I) is not None
    except re.error:
        return False


def rule_matches(rule, host: HostResult) -> bool:
    """True when every condition configured on ``rule`` matches ``host`` (unset conditions are ignored)."""
    facts = host.facts
    hostname = host.hostname or ""
    if not _search(rule.hostname_regex, hostname):
        return False
    if not _search(rule.sys_descr_regex, facts.sys_descr if facts else None):
        return False
    if rule.sys_object_id_prefix:
        oid = (facts.sys_object_id if facts else None) or ""
        if not oid.lstrip(".").startswith(rule.sys_object_id_prefix.lstrip(".")):
            return False
    if rule.platform and (not facts or facts.platform != rule.platform):
        return False
    if not _search(rule.manufacturer_regex, facts.vendor if facts else None):
        return False
    if not _search(rule.model_regex, facts.model if facts else None):
        return False
    mac_vendor = host.mac_vendor or (host.nmap.mac_vendor if host.nmap else None)
    if not _search(rule.mac_vendor_regex, mac_vendor):
        return False
    ports = rule.port_list
    if ports:
        open_ports = {p.port for p in (host.nmap.ports if host.nmap else [])}
        if not open_ports.intersection(ports):
            return False
    return True


def select_role_rule(rules, host: HostResult, scan_target_id=None):
    """Return the first enabled rule (rules must be ordered by weight) matching ``host``."""
    for rule in rules:
        if not rule.enabled:
            continue
        target_ids = getattr(rule, "_target_ids", None)
        if target_ids and scan_target_id not in target_ids:
            continue
        if rule_matches(rule, host):
            return rule
    return None
