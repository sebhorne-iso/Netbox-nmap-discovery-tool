"""Small helpers shared by the collectors and the synchronisation layer."""
from __future__ import annotations

import ipaddress
import re

__all__ = (
    "bytes_to_text",
    "canonical_interface_name",
    "is_usable_mac",
    "normalize_mac",
    "parse_target_networks",
    "short_hostname",
)

_MAC_HEX = re.compile(r"[0-9a-fA-F]")

# MAC prefixes which are shared by many devices and must never be used to identify a device:
# VRRP/HSRP/GLBP virtual router MACs, IPv4/IPv6 multicast, and common placeholder values.
_SHARED_MAC_PREFIXES = (
    "00:00:0C:07:AC",  # HSRPv1
    "00:00:0C:9F:F",  # HSRPv2
    "00:07:B4:00",  # GLBP
    "00:00:5E:00:01",  # VRRP IPv4
    "00:00:5E:00:02",  # VRRP IPv6
    "01:00:5E",  # IPv4 multicast
    "33:33",  # IPv6 multicast
    "02:00:00:00:00",  # placeholder
)
_INVALID_MACS = {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}


def normalize_mac(value) -> str | None:
    """
    Normalise a MAC address given as raw bytes, ``aa:bb:..``, ``aabb.ccdd.eeff``, ``aa-bb-..`` or a bare hex
    string into upper-case colon notation. Returns ``None`` for anything that is not a 48-bit MAC.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        if len(value) != 6:
            # Some agents return the MAC as an ASCII string inside an OCTET STRING
            try:
                return normalize_mac(value.decode("ascii"))
            except UnicodeDecodeError:
                return None
        return ":".join(f"{b:02X}" for b in value)
    text = str(value).strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    digits = "".join(_MAC_HEX.findall(text))
    if len(digits) != 12:
        # Handle "0:1b:2c:3:4:5" style notation with stripped leading zeros
        parts = re.split(r"[:\-]", text)
        if len(parts) == 6 and all(1 <= len(p) <= 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts):
            digits = "".join(p.zfill(2) for p in parts)
        else:
            return None
    digits = digits.upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def is_usable_mac(mac: str | None) -> bool:
    """True when ``mac`` uniquely identifies a physical interface (i.e. is not virtual/multicast/placeholder)."""
    if not mac:
        return False
    mac = mac.upper()
    if mac in _INVALID_MACS:
        return False
    if any(mac.startswith(prefix) for prefix in _SHARED_MAC_PREFIXES):
        return False
    first_octet = int(mac[:2], 16)
    return not first_octet & 0x01  # multicast bit


def bytes_to_text(value) -> str:
    """Decode an SNMP OCTET STRING to text, tolerating binary garbage and trailing NULs."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).rstrip(b"\x00")
        try:
            return value.decode("utf-8").strip()
        except UnicodeDecodeError:
            return value.decode("latin-1").strip()
    return str(value).strip()


def short_hostname(name: str | None) -> str | None:
    """Return the first label of a hostname (``sw1.example.com`` -> ``sw1``), lower-cased."""
    if not name:
        return None
    name = name.strip().rstrip(".")
    # Don't split IP addresses
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        pass
    # Strip a CDP-style serial suffix: "switch1(FOC1234X0YZ)"
    name = re.sub(r"\(.*\)$", "", name)
    return name.split(".")[0].lower() or None


# Interface abbreviation -> canonical long form. Matching is case-insensitive and anchored to the start of the
# name; the longest abbreviation wins. This lets "Gi1/0/1" (SNMP ifName, CDP) match "GigabitEthernet1/0/1"
# (NAPALM, NetBox device-type library templates).
_INTERFACE_ABBREVIATIONS = {
    "fa": "FastEthernet",
    "fastethernet": "FastEthernet",
    "gi": "GigabitEthernet",
    "gig": "GigabitEthernet",
    "gigabitethernet": "GigabitEthernet",
    "te": "TenGigabitEthernet",
    "ten": "TenGigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "tengige": "TenGigabitEthernet",
    "tw": "TwoGigabitEthernet",
    "twogigabitethernet": "TwoGigabitEthernet",
    "fi": "FiveGigabitEthernet",
    "fivegigabitethernet": "FiveGigabitEthernet",
    "twe": "TwentyFiveGigE",
    "twentyfivegige": "TwentyFiveGigE",
    "twentyfivegigabitethernet": "TwentyFiveGigE",
    "fo": "FortyGigabitEthernet",
    "fortygigabitethernet": "FortyGigabitEthernet",
    "fortygige": "FortyGigabitEthernet",
    "hu": "HundredGigE",
    "hundredgige": "HundredGigE",
    "hundredgigabitethernet": "HundredGigE",
    "po": "Port-channel",
    "port-channel": "Port-channel",
    "portchannel": "Port-channel",
    "eth": "Ethernet",
    "et": "Ethernet",
    "ethernet": "Ethernet",
    "lo": "Loopback",
    "loopback": "Loopback",
    "vl": "Vlan",
    "vlan": "Vlan",
    "tu": "Tunnel",
    "tunnel": "Tunnel",
    "mgmt": "mgmt",
    "ma": "Management",
    "management": "Management",
    "bdi": "BDI",
    "nve": "nve",
}
_INTERFACE_SPLIT = re.compile(r"^([A-Za-z][A-Za-z\-]*?)\s*(\d.*)$")


def canonical_interface_name(name: str | None) -> str:
    """
    Return a canonical key for an interface name, used only for *matching* names reported by different sources.
    Names with a recognised abbreviation are expanded ("Gi1/0/1" -> "gigabitethernet1/0/1"); everything else is
    lower-cased with whitespace removed.
    """
    if not name:
        return ""
    name = name.strip()
    match = _INTERFACE_SPLIT.match(name)
    if match:
        prefix, rest = match.groups()
        long = _INTERFACE_ABBREVIATIONS.get(prefix.lower())
        if long:
            # Junos "et-0/0/0" must not be confused with Cisco "Et0/0" (Ethernet): only expand when the prefix
            # is not immediately followed by a dash in the original name
            if not name[len(prefix):].startswith("-"):
                return (long + rest).lower().replace(" ", "")
    return name.lower().replace(" ", "")


_TARGET_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")


def parse_target_networks(lines) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Convert scan-target lines (CIDR, single IP or ``a.b.c.x-y`` last-octet range) into a list of networks.
    Hostnames are ignored (they cannot be used for containment checks).
    """
    networks = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        range_match = _TARGET_RANGE.match(line)
        if range_match:
            base, start, end = range_match.groups()
            first = ipaddress.ip_address(f"{base}{start}")
            last = ipaddress.ip_address(f"{base}{end}")
            networks.extend(ipaddress.summarize_address_range(first, last))
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return networks


def address_in_networks(address: str, networks) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("/")[0])
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in networks)
