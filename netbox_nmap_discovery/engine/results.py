"""
Normalised data structures produced by the discovery engine.

Every collector (nmap, SNMP, NAPALM, Netmiko) emits these structures so that the synchronisation layer only
has to understand one shape of data. All structures round-trip through ``to_dict()`` / ``from_dict()`` so they
can be stored in job results and review-queue proposals as JSON.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

__all__ = (
    "ArpEntry",
    "DeviceFacts",
    "HostResult",
    "DiscoveredInterface",
    "Neighbor",
    "NmapHost",
    "OpenPort",
)


class _Serializable:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None):
        if data is None:
            return None
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class OpenPort(_Serializable):
    port: int
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""

    def label(self) -> str:
        text = f"{self.port}/{self.protocol}"
        if self.service:
            text += f" {self.service}"
        return text


@dataclass
class NmapHost(_Serializable):
    address: str
    hostnames: list[str] = field(default_factory=list)
    mac_address: str | None = None
    mac_vendor: str | None = None
    os_guess: str | None = None
    os_accuracy: int | None = None
    os_vendor: str | None = None
    os_family: str | None = None
    ports: list[OpenPort] = field(default_factory=list)
    ports_scanned: bool = False

    @classmethod
    def from_dict(cls, data):
        if data is None:
            return None
        obj = super().from_dict(data)
        obj.ports = [OpenPort.from_dict(p) if isinstance(p, dict) else p for p in obj.ports]
        return obj

    @property
    def hostname(self) -> str | None:
        return self.hostnames[0] if self.hostnames else None

    def has_port(self, port: int, protocol: str = "tcp") -> bool:
        return any(p.port == port and p.protocol == protocol for p in self.ports)


@dataclass
class DeviceFacts(_Serializable):
    hostname: str | None = None
    fqdn: str | None = None
    vendor: str | None = None
    model: str | None = None
    serial: str | None = None
    os_version: str | None = None
    platform: str | None = None  # key into engine.platforms.PLATFORMS
    sys_object_id: str | None = None
    sys_descr: str | None = None
    sys_location: str | None = None
    sys_contact: str | None = None

    def merge(self, other: DeviceFacts | None) -> DeviceFacts:
        """Return a copy where non-empty values from ``other`` take precedence."""
        if other is None:
            return DeviceFacts(**asdict(self))
        merged = asdict(self)
        for key, value in asdict(other).items():
            if value not in (None, ""):
                merged[key] = value
        return DeviceFacts(**merged)


@dataclass
class DiscoveredInterface(_Serializable):
    name: str
    description: str = ""
    if_type: int | None = None  # IANA ifType, when known
    type: str | None = None  # NetBox interface type slug, when determined by the collector
    speed_kbps: int | None = None
    mtu: int | None = None
    mac_address: str | None = None
    enabled: bool | None = None
    oper_up: bool | None = None
    ip_addresses: list[str] = field(default_factory=list)  # CIDR notation, e.g. "10.0.0.1/24"
    lag: str | None = None  # name of the parent LAG interface
    if_index: int | None = None


@dataclass
class Neighbor(_Serializable):
    local_interface: str
    protocol: str = "lldp"  # lldp | cdp
    remote_name: str | None = None
    remote_interface: str | None = None
    remote_interface_description: str | None = None
    remote_chassis_id: str | None = None
    remote_mgmt_address: str | None = None
    remote_platform: str | None = None


@dataclass
class ArpEntry(_Serializable):
    ip_address: str
    mac_address: str
    interface: str | None = None


@dataclass
class HostResult(_Serializable):
    """Everything learned about a single IP address during a scan."""

    address: str
    source: str = "nmap"  # nmap | arp | lldp | manual
    nmap: NmapHost | None = None
    facts: DeviceFacts | None = None
    interfaces: list[DiscoveredInterface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)  # collectors that succeeded: snmp, ssh
    snmp_credential_id: int | None = None
    ssh_credential_id: int | None = None
    mac_address: str | None = None  # MAC seen for this address (nmap on local L2, or ARP)
    mac_vendor: str | None = None
    errors: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        if data is None:
            return None
        obj = super().from_dict(data)
        obj.nmap = NmapHost.from_dict(obj.nmap) if isinstance(obj.nmap, dict) else obj.nmap
        obj.facts = DeviceFacts.from_dict(obj.facts) if isinstance(obj.facts, dict) else obj.facts
        obj.interfaces = [DiscoveredInterface.from_dict(i) if isinstance(i, dict) else i for i in obj.interfaces]
        obj.neighbors = [Neighbor.from_dict(n) if isinstance(n, dict) else n for n in obj.neighbors]
        obj.arp = [ArpEntry.from_dict(a) if isinstance(a, dict) else a for a in obj.arp]
        return obj

    @property
    def managed(self) -> bool:
        """True when the host answered SNMP or SSH, i.e. we know what device it is."""
        return self.facts is not None and bool(self.methods)

    @property
    def hostname(self) -> str | None:
        if self.facts and self.facts.hostname:
            return self.facts.hostname
        if self.nmap and self.nmap.hostname:
            return self.nmap.hostname
        return None

    @property
    def dns_name(self) -> str | None:
        if self.nmap and self.nmap.hostname:
            return self.nmap.hostname
        return None

    def all_macs(self) -> set[str]:
        macs = {i.mac_address for i in self.interfaces if i.mac_address}
        if self.mac_address:
            macs.add(self.mac_address)
        return macs

    def interface_for_address(self, address: str) -> DiscoveredInterface | None:
        for interface in self.interfaces:
            for cidr in interface.ip_addresses:
                if cidr.split("/")[0] == address:
                    return interface
        return None
