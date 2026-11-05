"""
Parsers for CLI output collected over SSH.

These are deliberately tolerant: a parser returns whatever it can understand and ignores the rest. Vendor CLI
output varies between software releases, so every parser is covered by fixtures in ``tests/unit`` and new formats
can be added there.
"""
from __future__ import annotations

import ipaddress
import json
import re

from ..interfaces import guess_interface_type
from ..results import ArpEntry, DeviceFacts, DiscoveredInterface, Neighbor
from ..utils import normalize_mac

__all__ = (
    "parse_aoscx_interface_brief",
    "parse_aoscx_lldp_detail",
    "parse_aoscx_system",
    "parse_cdp_neighbors_detail",
    "parse_fortios_arp",
    "parse_fortios_interfaces",
    "parse_fortios_system_status",
    "parse_key_values",
    "parse_linux_dmi",
    "parse_linux_ip_addr",
    "parse_linux_ip_neigh",
    "parse_linux_lldpctl",
    "parse_linux_os_release",
    "parse_panos_arp",
    "parse_panos_interfaces",
    "parse_panos_system_info",
    "parse_procurve_lldp_detail",
    "parse_procurve_system",
)


def parse_key_values(text: str, separator: str = ":") -> dict[str, str]:
    """Parse ``Key : Value`` lines (first occurrence of each key wins). Handles two pairs on one line."""
    result = {}
    key = r"[A-Za-z][\w ./()\-]*?"
    sep = re.escape(separator)
    pair = re.compile(rf"({key})\s*{sep}\s*(.*?)(?=\s{{2,}}{key}\s*{sep}\s|$)")
    for line in (text or "").splitlines():
        line = line.strip()
        if separator not in line:
            continue
        for match in pair.finditer(line):
            key, value = match.group(1).strip(), match.group(2).strip()
            if key and key not in result:
                result[key] = value
    return result


def _split_blocks(text: str, start_regex: str) -> list[str]:
    """Split ``text`` into blocks, each starting at a line that matches ``start_regex``."""
    blocks, current = [], []
    start = re.compile(start_regex, re.M)
    for line in (text or "").splitlines():
        if start.search(line) and current:
            blocks.append("\n".join(current))
            current = []
        current.append(line)
    if current:
        blocks.append("\n".join(current))
    return [b for b in blocks if start.search(b)]


def _cidr(address: str, mask_or_len: str | int | None) -> str | None:
    try:
        if mask_or_len is None:
            return str(ipaddress.ip_interface(address))
        return str(ipaddress.ip_interface(f"{address}/{mask_or_len}"))
    except ValueError:
        return None


# --- Cisco ------------------------------------------------------------------------------------------------------
def parse_cdp_neighbors_detail(text: str) -> list[Neighbor]:
    """Parse ``show cdp neighbors detail`` (IOS, IOS-XE, NX-OS)."""
    neighbors = []
    for block in _split_blocks(text, r"^\s*Device ID\s*:?"):
        device_id = re.search(r"Device ID\s*:?\s*(\S+)", block)
        interface = re.search(r"Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(\S.*)", block)
        if not device_id or not interface:
            continue
        ip_line = r"IP(?:v4)? [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)"
        mgmt = (re.search(r"(?:Management|Mgmt) address\(es\):\s*\n\s*" + ip_line, block)
                or re.search(ip_line, block))
        system_name = re.search(r"System Name:\s*(\S+)", block)
        platform = re.search(r"Platform:\s*([^,\n]+)", block)
        neighbors.append(Neighbor(
            local_interface=interface.group(1).strip(),
            protocol="cdp",
            remote_name=(system_name or device_id).group(1).strip(),
            remote_interface=interface.group(2).strip(),
            remote_mgmt_address=mgmt.group(1) if mgmt else None,
            remote_platform=platform.group(1).strip() if platform else None,
        ))
    return neighbors


# --- Linux ------------------------------------------------------------------------------------------------------
def parse_linux_ip_addr(text: str, speeds: dict[str, int] | None = None) -> list[DiscoveredInterface]:
    """Parse ``ip -j -d addr show`` JSON."""
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    speeds = speeds or {}
    masters = {}
    interfaces = []
    for entry in data:
        name = entry.get("ifname")
        if not name:
            continue
        flags = entry.get("flags") or []
        link_type = entry.get("link_type")
        kind = ((entry.get("linkinfo") or {}).get("info_kind")) or ""
        if_type = 24 if link_type == "loopback" else None
        if kind == "bond":
            type_ = "lag"
        elif kind == "bridge":
            type_ = "bridge"
        elif kind in ("vlan", "veth", "dummy", "vxlan", "tun", "wireguard", "gre", "macvlan", "ipvlan") or if_type:
            type_ = "virtual"
        else:
            type_ = None
        speed_mbps = speeds.get(name)
        speed_kbps = speed_mbps * 1000 if speed_mbps and speed_mbps > 0 else None
        addresses = []
        for info in entry.get("addr_info") or []:
            if info.get("scope") not in ("global", "site", None):
                continue
            cidr = _cidr(info.get("local", ""), info.get("prefixlen"))
            if cidr:
                addresses.append(cidr)
        interface = DiscoveredInterface(
            name=name,
            description=entry.get("ifalias") or "",
            if_type=if_type,
            type=type_ or guess_interface_type(name, if_type, speed_kbps),
            speed_kbps=speed_kbps,
            mtu=entry.get("mtu"),
            mac_address=normalize_mac(entry.get("address")) if link_type == "ether" else None,
            enabled="UP" in flags,
            oper_up=entry.get("operstate") == "UP" or (entry.get("operstate") == "UNKNOWN" and "LOWER_UP" in flags),
            ip_addresses=addresses,
            if_index=entry.get("ifindex"),
        )
        if entry.get("master"):
            masters[name] = entry["master"]
        interfaces.append(interface)
    by_name = {i.name: i for i in interfaces}
    for interface in interfaces:
        master = masters.get(interface.name)
        if master in by_name and by_name[master].type == "lag":
            interface.lag = master
    return interfaces


def parse_linux_lldpctl(text: str) -> list[Neighbor]:
    """Parse ``lldpctl -f json`` output (lldpd)."""
    try:
        data = json.loads(text or "{}")
    except json.JSONDecodeError:
        return []
    interfaces = (data.get("lldp") or {}).get("interface") or []
    if isinstance(interfaces, dict):
        interfaces = [{k: v} for k, v in interfaces.items()]
    neighbors = []
    for item in interfaces:
        for local, details in item.items():
            details_list = details if isinstance(details, list) else [details]
            for detail in details_list:
                chassis = detail.get("chassis") or {}
                if chassis and len(chassis) == 1 and isinstance(next(iter(chassis.values())), dict) \
                        and "id" in next(iter(chassis.values())):
                    remote_name, chassis_info = next(iter(chassis.items()))
                else:
                    remote_name, chassis_info = chassis.get("name", {}).get("value") if isinstance(
                        chassis.get("name"), dict) else chassis.get("name"), chassis
                chassis_id = (chassis_info.get("id") or {})
                mgmt = chassis_info.get("mgmt-ip")
                if isinstance(mgmt, list):
                    mgmt = next((m for m in mgmt if ":" not in m), mgmt[0] if mgmt else None)
                port = detail.get("port") or {}
                port_id = port.get("id") or {}
                neighbors.append(Neighbor(
                    local_interface=local,
                    protocol="lldp",
                    remote_name=remote_name,
                    remote_interface=(normalize_mac(port_id.get("value")) if port_id.get("type") == "mac"
                                      else port_id.get("value")),
                    remote_interface_description=port.get("descr"),
                    remote_chassis_id=(normalize_mac(chassis_id.get("value")) if chassis_id.get("type") == "mac"
                                       else chassis_id.get("value")),
                    remote_mgmt_address=mgmt,
                    remote_platform=chassis_info.get("descr"),
                ))
    return neighbors


def parse_linux_ip_neigh(text: str) -> list[ArpEntry]:
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        return []
    entries = []
    for entry in data:
        mac = normalize_mac(entry.get("lladdr"))
        state = entry.get("state") or []
        if not mac or "FAILED" in state or "INCOMPLETE" in state:
            continue
        try:
            if ipaddress.ip_address(entry.get("dst", "")).is_link_local:
                continue
        except ValueError:
            continue
        entries.append(ArpEntry(ip_address=entry["dst"], mac_address=mac, interface=entry.get("dev")))
    return entries


def parse_linux_dmi(text: str) -> dict[str, str]:
    """Parse ``key=value`` lines produced by the DMI collection command."""
    result = {}
    for line in (text or "").splitlines():
        key, _, value = line.partition("=")
        value = value.strip()
        if key.strip() and value and value.lower() not in ("to be filled by o.e.m.", "default string", "none",
                                                           "not specified", "system serial number", "0"):
            result[key.strip()] = value
    return result


def parse_linux_os_release(text: str) -> str | None:
    match = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', text or "", re.M)
    return match.group(1) if match else None


# --- Fortinet FortiOS -------------------------------------------------------------------------------------------
def parse_fortios_system_status(text: str) -> DeviceFacts:
    kv = parse_key_values(text)
    version = kv.get("Version", "")
    model = None
    os_version = None
    match = re.match(r"(\S+)\s+v([\w.]+)", version)
    if match:
        model, os_version = match.group(1), match.group(2)
    return DeviceFacts(
        hostname=kv.get("Hostname"),
        vendor="Fortinet",
        model=model,
        serial=kv.get("Serial-Number"),
        os_version=os_version,
        platform="fortinet_fortios",
    )


def parse_fortios_interfaces(text: str) -> list[DiscoveredInterface]:
    """Parse ``get system interface physical``."""
    interfaces = []
    for block in _split_blocks(text, r"^\s*==\s*\[[^\]]+\]\s*$"):
        name_match = re.search(r"==\s*\[([^\]]+)\]", block)
        if not name_match or name_match.group(1) in ("onboard",):
            continue
        kv = parse_key_values(block)
        if not kv:
            continue
        name = name_match.group(1)
        addresses = []
        ip = kv.get("ip", "").split()
        if len(ip) == 2 and ip[0] != "0.0.0.0":
            cidr = _cidr(ip[0], ip[1])
            if cidr:
                addresses.append(cidr)
        speed_match = re.match(r"(\d+)Mbps", kv.get("speed", ""))
        speed_kbps = int(speed_match.group(1)) * 1000 if speed_match else None
        interfaces.append(DiscoveredInterface(
            name=name,
            type=guess_interface_type(name, None, speed_kbps),
            speed_kbps=speed_kbps,
            oper_up=kv.get("status") == "up",
            ip_addresses=addresses,
        ))
    return interfaces


def parse_fortios_arp(text: str) -> list[ArpEntry]:
    entries = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 4 and re.match(r"\d+\.\d+\.\d+\.\d+$", parts[0]):
            mac = normalize_mac(parts[2])
            if mac and mac != "00:00:00:00:00:00":
                entries.append(ArpEntry(ip_address=parts[0], mac_address=mac, interface=parts[3]))
    return entries


# --- Palo Alto PAN-OS -------------------------------------------------------------------------------------------
def parse_panos_system_info(text: str) -> DeviceFacts:
    kv = parse_key_values(text)
    return DeviceFacts(
        hostname=kv.get("hostname"),
        vendor="Palo Alto",
        model=kv.get("model"),
        serial=kv.get("serial"),
        os_version=kv.get("sw-version"),
        platform="paloalto_panos",
    )


def parse_panos_interfaces(text: str) -> list[DiscoveredInterface]:
    """Parse ``show interface all`` (hardware and logical sections)."""
    interfaces: dict[str, DiscoveredInterface] = {}
    section = None
    for line in (text or "").splitlines():
        if line.startswith("total configured hardware interfaces"):
            section = "hardware"
            continue
        if line.startswith("total configured logical interfaces"):
            section = "logical"
            continue
        if line.startswith("aggregation groups"):
            section = None
            continue
        parts = line.split()
        if not parts or parts[0] in ("name",) or set(line.strip()) <= {"-", " "}:
            continue
        name = parts[0]
        if not re.match(r"^(ethernet|ae|loopback|tunnel|vlan|mgt)", name):
            continue
        if section == "hardware" and len(parts) >= 3:
            state = parts[2].split("/")
            speed = int(state[0]) * 1000 if state and state[0].isdigit() else None
            mac = normalize_mac(parts[3]) if len(parts) >= 4 else None
            interfaces[name] = DiscoveredInterface(
                name=name,
                type=guess_interface_type(name, None, speed),
                speed_kbps=speed,
                mac_address=mac,
                oper_up=len(state) >= 3 and state[2].startswith("up"),
            )
        elif section == "logical":
            address = parts[-1]
            interface = interfaces.setdefault(name, DiscoveredInterface(name=name, type=guess_interface_type(name)))
            if "/" in address:
                cidr = _cidr(address, None)
                if cidr and cidr not in interface.ip_addresses:
                    interface.ip_addresses.append(cidr)
    return list(interfaces.values())


def parse_panos_arp(text: str) -> list[ArpEntry]:
    entries = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+$", parts[1]):
            mac = normalize_mac(parts[2])
            if mac and mac != "00:00:00:00:00:00":
                entries.append(ArpEntry(ip_address=parts[1], mac_address=mac, interface=parts[0]))
    return entries


# --- Aruba AOS-CX -----------------------------------------------------------------------------------------------
def parse_aoscx_system(text: str) -> DeviceFacts:
    kv = parse_key_values(text)
    product = kv.get("Product Name", "")
    model = product.split()[0] if product else None
    return DeviceFacts(
        hostname=kv.get("Hostname"),
        vendor="Aruba",
        model=model,
        serial=kv.get("Chassis Serial Nbr") or kv.get("Chassis Serial Number"),
        os_version=kv.get("AOS-CX Version") or kv.get("System Description"),
        platform="aruba_aoscx",
    )


def parse_aoscx_interface_brief(text: str) -> list[DiscoveredInterface]:
    interfaces = []
    for line in (text or "").splitlines():
        parts = line.split()
        if not parts or not re.match(r"^(\d+/\d+/\d+|lag\d+|vlan\d+|loopback\d+|mgmt)$", parts[0]):
            continue
        name = parts[0]
        enabled = "yes" in parts[:6]
        oper_up = "up" in parts[:7]
        speed = next((int(p) * 1000 for p in parts[4:] if p.isdigit()), None)
        description = " ".join(parts[8:]) if len(parts) > 8 and parts[-1] != "--" else ""
        interfaces.append(DiscoveredInterface(
            name=name,
            description=description if description != "--" else "",
            type=guess_interface_type(name, None, speed),
            speed_kbps=speed,
            enabled=enabled,
            oper_up=oper_up,
        ))
    return interfaces


def parse_aoscx_lldp_detail(text: str) -> list[Neighbor]:
    neighbors = []
    for block in _split_blocks(text, r"^\s*Port\s*:\s*\S+"):
        kv = parse_key_values(block)
        local = kv.get("Port")
        if not local or not (kv.get("Neighbor Chassis-Name") or kv.get("Neighbor Port-ID")):
            continue
        neighbors.append(Neighbor(
            local_interface=local,
            protocol="lldp",
            remote_name=kv.get("Neighbor Chassis-Name") or None,
            remote_interface=kv.get("Neighbor Port-ID") or None,
            remote_interface_description=kv.get("Neighbor Port-Desc") or None,
            remote_chassis_id=normalize_mac(kv.get("Neighbor Chassis-ID")) or kv.get("Neighbor Chassis-ID"),
            remote_mgmt_address=kv.get("Neighbor Management-Address") or None,
            remote_platform=kv.get("Neighbor Chassis-Description") or None,
        ))
    return neighbors


# --- HPE ArubaOS-Switch (ProCurve) ------------------------------------------------------------------------------
def parse_procurve_system(text: str) -> DeviceFacts:
    kv = parse_key_values(text)
    return DeviceFacts(
        hostname=kv.get("System Name"),
        vendor="HPE",
        serial=kv.get("Serial Number"),
        os_version=kv.get("Software revision"),
        platform="hp_procurve",
    )


def parse_procurve_lldp_detail(text: str) -> list[Neighbor]:
    neighbors = []
    for block in _split_blocks(text, r"^\s*Local Port\s*:\s*\S+"):
        kv = parse_key_values(block)
        local = kv.get("Local Port")
        if not local:
            continue
        chassis = kv.get("ChassisId", "")
        mgmt = re.search(r"Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", block)
        port_id = kv.get("PortId") or None
        if kv.get("PortType") == "mac-address":
            port_id = normalize_mac(port_id) or port_id
        neighbors.append(Neighbor(
            local_interface=local,
            protocol="lldp",
            remote_name=kv.get("SysName") or None,
            remote_interface=port_id,
            remote_interface_description=kv.get("PortDescr") or None,
            remote_chassis_id=(normalize_mac(chassis.replace(" ", "")) if kv.get("ChassisType") == "mac-address"
                               else chassis) or None,
            remote_mgmt_address=mgmt.group(1) if mgmt else None,
            remote_platform=kv.get("System Descr") or None,
        ))
    return neighbors
