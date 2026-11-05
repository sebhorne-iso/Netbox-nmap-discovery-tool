"""
Platform registry and detection.

A *platform key* (e.g. ``cisco_ios``) identifies how to talk to a device over SSH and how it should be
represented in NetBox (Platform and Manufacturer names). Detection uses SNMP sysObjectID/sysDescr first, then
the SSH banner and nmap OS fingerprint as fallbacks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = (
    "PLATFORMS",
    "PlatformSpec",
    "detect_platform",
    "normalize_manufacturer",
)


@dataclass(frozen=True)
class PlatformSpec:
    key: str
    name: str  # NetBox Platform name
    manufacturer: str | None  # NetBox Manufacturer name (None for vendor-neutral platforms)
    collector: str | None  # SSH collector: "napalm", "fortios", "panos", "aoscx", "procurve", "linux" or None
    napalm_driver: str | None = None
    netmiko_device_type: str | None = None


PLATFORMS: dict[str, PlatformSpec] = {spec.key: spec for spec in (
    PlatformSpec("cisco_ios", "Cisco IOS", "Cisco", "napalm", "ios", "cisco_ios"),
    PlatformSpec("cisco_xe", "Cisco IOS-XE", "Cisco", "napalm", "ios", "cisco_xe"),
    PlatformSpec("cisco_nxos", "Cisco NX-OS", "Cisco", "napalm", "nxos_ssh", "cisco_nxos"),
    PlatformSpec("juniper_junos", "Juniper Junos", "Juniper", "napalm", "junos", "juniper_junos"),
    PlatformSpec("arista_eos", "Arista EOS", "Arista", "napalm", "eos", "arista_eos"),
    PlatformSpec("fortinet_fortios", "Fortinet FortiOS", "Fortinet", "fortios", None, "fortinet"),
    PlatformSpec("paloalto_panos", "Palo Alto PAN-OS", "Palo Alto", "panos", None, "paloalto_panos"),
    PlatformSpec("aruba_aoscx", "Aruba AOS-CX", "Aruba", "aoscx", None, "aruba_aoscx"),
    PlatformSpec("hp_procurve", "HPE ArubaOS-Switch", "HPE", "procurve", None, "hp_procurve"),
    PlatformSpec("linux", "Linux", None, "linux", None, "linux"),
    PlatformSpec("windows", "Microsoft Windows", "Microsoft", None, None, None),
)}

# netmiko SSHDetect device types -> platform key
NETMIKO_TO_PLATFORM = {spec.netmiko_device_type: spec.key for spec in PLATFORMS.values() if spec.netmiko_device_type}
NETMIKO_TO_PLATFORM.update({"cisco_ios_telnet": "cisco_ios", "hp_comware": None, "aruba_os": None})

# (sysObjectID prefix, sysDescr regex or None, platform key) - evaluated in order, first match wins
_SNMP_RULES = (
    ("1.3.6.1.4.1.9.", re.compile(r"NX-OS|Nexus", re.I), "cisco_nxos"),
    ("1.3.6.1.4.1.9.", re.compile(r"IOS[ -]XE|IOSXE|Catalyst L3 Switch Software|cat9k|Virtual XE", re.I), "cisco_xe"),
    ("1.3.6.1.4.1.9.", re.compile(r"IOS", re.I), "cisco_ios"),
    ("1.3.6.1.4.1.2636.", None, "juniper_junos"),
    ("1.3.6.1.4.1.30065.", None, "arista_eos"),
    ("1.3.6.1.4.1.12356.", None, "fortinet_fortios"),
    ("1.3.6.1.4.1.25461.", None, "paloalto_panos"),
    ("1.3.6.1.4.1.47196.4.", None, "aruba_aoscx"),
    ("1.3.6.1.4.1.11.2.3.7.11.", None, "hp_procurve"),
    ("1.3.6.1.4.1.311.", None, "windows"),
    ("1.3.6.1.4.1.8072.", re.compile(r"Linux", re.I), "linux"),
)
_SYSDESCR_RULES = (
    (re.compile(r"NX-OS|Cisco Nexus", re.I), "cisco_nxos"),
    (re.compile(r"IOS[ -]XE", re.I), "cisco_xe"),
    (re.compile(r"Cisco IOS Software|Cisco Internetwork Operating System", re.I), "cisco_ios"),
    (re.compile(r"JUNOS|Juniper Networks", re.I), "juniper_junos"),
    (re.compile(r"Arista Networks EOS", re.I), "arista_eos"),
    (re.compile(r"FortiGate|FortiOS", re.I), "fortinet_fortios"),
    (re.compile(r"Palo Alto Networks|PAN-OS", re.I), "paloalto_panos"),
    (re.compile(r"ArubaOS-CX|AOS-CX|Aruba .*CX", re.I), "aruba_aoscx"),
    (re.compile(r"ProCurve|HP J\d{4}|Aruba J[L\d]\d{3}|HPE? .*Switch.*revision", re.I), "hp_procurve"),
    (re.compile(r"Windows", re.I), "windows"),
    (re.compile(r"^Linux", re.I), "linux"),
)
_SSH_BANNER_RULES = (
    (re.compile(r"Cisco", re.I), "cisco_ios"),
    (re.compile(r"FortiSSH|Fortinet", re.I), "fortinet_fortios"),
    (re.compile(r"OpenSSH.*(Ubuntu|Debian|Raspbian|el\d|Fedora)", re.I), "linux"),
)
_NMAP_OS_RULES = (
    (re.compile(r"NX-OS", re.I), "cisco_nxos"),
    (re.compile(r"IOS XE", re.I), "cisco_xe"),
    (re.compile(r"Cisco IOS", re.I), "cisco_ios"),
    (re.compile(r"Junos|Juniper", re.I), "juniper_junos"),
    (re.compile(r"Arista", re.I), "arista_eos"),
    (re.compile(r"FortiOS|FortiGate", re.I), "fortinet_fortios"),
    (re.compile(r"PAN-OS|Palo Alto", re.I), "paloalto_panos"),
    (re.compile(r"Windows", re.I), "windows"),
    (re.compile(r"Linux", re.I), "linux"),
)


def detect_platform(sys_object_id=None, sys_descr=None, ssh_banner=None, nmap_os=None) -> str | None:
    """Return the best-guess platform key, or None."""
    sys_descr = sys_descr or ""
    if sys_object_id:
        oid = sys_object_id.lstrip(".") + "."
        for prefix, descr_re, key in _SNMP_RULES:
            if oid.startswith(prefix) and (descr_re is None or descr_re.search(sys_descr)):
                return key
    if sys_descr:
        for regex, key in _SYSDESCR_RULES:
            if regex.search(sys_descr):
                return key
    if ssh_banner:
        for regex, key in _SSH_BANNER_RULES:
            if regex.search(ssh_banner):
                return key
    if nmap_os:
        for regex, key in _NMAP_OS_RULES:
            if regex.search(nmap_os):
                return key
    return None


# Raw vendor strings (SNMP entPhysicalMfgName, NAPALM vendor, nmap OUI vendor) -> canonical manufacturer name
_MANUFACTURER_PATTERNS = (
    (re.compile(r"^cisco", re.I), "Cisco"),
    (re.compile(r"^juniper", re.I), "Juniper"),
    (re.compile(r"^arista", re.I), "Arista"),
    (re.compile(r"^fortinet", re.I), "Fortinet"),
    (re.compile(r"^palo ?alto", re.I), "Palo Alto"),
    (re.compile(r"^(hpe )?aruba", re.I), "Aruba"),
    (re.compile(r"^(hewlett[ -]packard|hp\b|hpe\b)", re.I), "HPE"),
    (re.compile(r"^dell", re.I), "Dell"),
    (re.compile(r"^lenovo", re.I), "Lenovo"),
    (re.compile(r"^supermicro|^super micro", re.I), "Supermicro"),
    (re.compile(r"^vmware", re.I), "VMware"),
    (re.compile(r"^microsoft", re.I), "Microsoft"),
)


def normalize_manufacturer(raw: str | None, aliases: dict | None = None) -> str | None:
    """Map a vendor string to a canonical manufacturer name (user ``aliases`` take precedence)."""
    if not raw:
        return None
    raw = raw.strip()
    if aliases:
        for key, value in aliases.items():
            if key.lower() == raw.lower():
                return value
    for regex, name in _MANUFACTURER_PATTERNS:
        if regex.search(raw):
            return name
    # Strip common corporate suffixes ("Acme Networks, Inc." -> "Acme")
    cleaned, previous = raw, None
    while cleaned != previous:
        previous = cleaned
        cleaned = re.sub(r"[,.]?\s+(inc|incorporated|corp|corporation|co|ltd|limited|llc|gmbh|ag|sa|systems|"
                         r"networks|technologies)\.?$", "", cleaned, flags=re.I).strip()
    return cleaned or raw
