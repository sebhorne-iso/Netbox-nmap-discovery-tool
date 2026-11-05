"""
SNMP collection.

``SnmpClient`` is a tiny synchronous facade (``get`` / ``walk``) over pysnmp's asyncio API. All MIB parsing is
done by ``collect_snmp()`` on plain ``{oid: value}`` dictionaries, which keeps the parsing logic testable without
an SNMP agent. Values are normalised to ``bytes`` (OCTET STRING), ``int`` (all integer types) or ``str``
(OBJECT IDENTIFIER, IpAddress).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from dataclasses import dataclass, field

from .interfaces import guess_interface_type
from .platforms import PLATFORMS, detect_platform, normalize_manufacturer
from .results import ArpEntry, DeviceFacts, DiscoveredInterface, Neighbor
from .utils import bytes_to_text, canonical_interface_name, normalize_mac

__all__ = (
    "SnmpClient",
    "SnmpCredential",
    "SnmpError",
    "SnmpResult",
    "collect_snmp",
    "parse_os_version",
)

logger = logging.getLogger("netbox_nmap_discovery.engine.snmp")


class SnmpError(Exception):
    pass


# --- OIDs ------------------------------------------------------------------------------------------------------
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_MTU = "1.3.6.1.2.1.2.2.1.4"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

IP_AD_ENT_IF_INDEX = "1.3.6.1.2.1.4.20.1.2"
IP_AD_ENT_NETMASK = "1.3.6.1.2.1.4.20.1.3"
IP_ADDRESS_IF_INDEX = "1.3.6.1.2.1.4.34.1.3"
IP_ADDRESS_TYPE = "1.3.6.1.2.1.4.34.1.4"
IP_ADDRESS_PREFIX = "1.3.6.1.2.1.4.34.1.5"

ENT_PHYSICAL_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"
ENT_PHYSICAL_CONTAINED_IN = "1.3.6.1.2.1.47.1.1.1.1.4"
ENT_PHYSICAL_CLASS = "1.3.6.1.2.1.47.1.1.1.1.5"
ENT_PHYSICAL_SOFTWARE_REV = "1.3.6.1.2.1.47.1.1.1.1.10"
ENT_PHYSICAL_SERIAL = "1.3.6.1.2.1.47.1.1.1.1.11"
ENT_PHYSICAL_MFG_NAME = "1.3.6.1.2.1.47.1.1.1.1.12"
ENT_PHYSICAL_MODEL_NAME = "1.3.6.1.2.1.47.1.1.1.1.13"
ENT_CLASS_CHASSIS = 3

LLDP_LOC_PORT_ID_SUBTYPE = "1.0.8802.1.1.2.1.3.7.1.2"
LLDP_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_LOC_PORT_DESC = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_CHASSIS_ID_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT_ID_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.6"
LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYS_DESC = "1.0.8802.1.1.2.1.4.1.1.10"
LLDP_REM_MAN_ADDR_IF_SUBTYPE = "1.0.8802.1.1.2.1.4.2.1.3"

CDP_CACHE_ADDRESS_TYPE = "1.3.6.1.4.1.9.9.23.1.2.1.1.3"
CDP_CACHE_ADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_CACHE_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_CACHE_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

DOT3AD_AGG_PORT_ATTACHED_AGG_ID = "1.2.840.10006.300.43.1.2.1.1.13"

IP_NET_TO_MEDIA_PHYS_ADDRESS = "1.3.6.1.2.1.4.22.1.2"
IP_NET_TO_MEDIA_TYPE = "1.3.6.1.2.1.4.22.1.4"
IP_NET_TO_PHYSICAL_PHYS_ADDRESS = "1.3.6.1.2.1.4.35.1.4"

# Vendor-specific scalars used when ENTITY-MIB is unavailable or incomplete
JNX_BOX_DESCR = "1.3.6.1.4.1.2636.3.1.2.0"
JNX_BOX_SERIAL = "1.3.6.1.4.1.2636.3.1.3.0"
FN_SYS_SERIAL = "1.3.6.1.4.1.12356.100.1.1.1.0"
FG_SYS_VERSION = "1.3.6.1.4.1.12356.101.4.1.1.0"
PAN_SYS_SW_VERSION = "1.3.6.1.4.1.25461.2.1.2.1.1.0"
PAN_SYS_SERIAL = "1.3.6.1.4.1.25461.2.1.2.1.3.0"
HP_SERIAL = "1.3.6.1.4.1.11.2.36.1.1.2.9.0"
CISCO_CHASSIS_ID = "1.3.6.1.4.1.9.3.6.3.0"


# --- Client ----------------------------------------------------------------------------------------------------
@dataclass
class SnmpCredential:
    version: str = "2c"  # "2c" or "3"
    community: str = ""
    username: str = ""
    auth_protocol: str = "none"  # none, md5, sha, sha224, sha256, sha384, sha512
    auth_key: str = ""
    priv_protocol: str = "none"  # none, des, 3des, aes128, aes192, aes256
    priv_key: str = ""
    port: int = 161
    id: int | None = None  # CredentialProfile pk (for reporting)


class SnmpClient:
    """Synchronous SNMP client for a single host (not thread-safe; create one per host)."""

    def __init__(self, host: str, credential: SnmpCredential, timeout: float = 2, retries: int = 1,
                 max_repetitions: int = 25):
        self.host = host
        self.credential = credential
        self.timeout = timeout
        self.retries = retries
        self.max_repetitions = max_repetitions
        self._loop = asyncio.new_event_loop()
        self._engine = None
        self._transport = None
        self._auth = None

    # pysnmp is imported lazily so the parsing code can be used/tested without it
    def _setup(self):
        if self._engine is not None:
            return
        from pysnmp.hlapi.v3arch import asyncio as hlapi

        self._hlapi = hlapi
        self._engine = hlapi.SnmpEngine()
        cred = self.credential
        if cred.version == "3":
            auth_map = {
                "none": hlapi.USM_AUTH_NONE, "md5": hlapi.USM_AUTH_HMAC96_MD5, "sha": hlapi.USM_AUTH_HMAC96_SHA,
                "sha224": hlapi.USM_AUTH_HMAC128_SHA224, "sha256": hlapi.USM_AUTH_HMAC192_SHA256,
                "sha384": hlapi.USM_AUTH_HMAC256_SHA384, "sha512": hlapi.USM_AUTH_HMAC384_SHA512,
            }
            priv_map = {
                "none": hlapi.USM_PRIV_NONE, "des": hlapi.USM_PRIV_CBC56_DES, "3des": hlapi.USM_PRIV_CBC168_3DES,
                "aes128": hlapi.USM_PRIV_CFB128_AES, "aes192": hlapi.USM_PRIV_CFB192_AES,
                "aes256": hlapi.USM_PRIV_CFB256_AES,
            }
            auth_proto = auth_map.get(cred.auth_protocol or "none", hlapi.USM_AUTH_NONE)
            priv_proto = priv_map.get(cred.priv_protocol or "none", hlapi.USM_PRIV_NONE)
            self._auth = hlapi.UsmUserData(
                cred.username,
                authKey=cred.auth_key or None if auth_proto != hlapi.USM_AUTH_NONE else None,
                privKey=cred.priv_key or None if priv_proto != hlapi.USM_PRIV_NONE else None,
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        else:
            self._auth = hlapi.CommunityData(cred.community, mpModel=1)

        async def make_transport():
            try:
                address = ipaddress.ip_address(self.host)
            except ValueError:
                address = None
            ipv6 = address is not None and address.version == 6
            cls = hlapi.Udp6TransportTarget if ipv6 else hlapi.UdpTransportTarget
            return await cls.create((self.host, cred.port or 161), timeout=self.timeout, retries=self.retries)

        self._transport = self._loop.run_until_complete(make_transport())

    @staticmethod
    def _convert(value):
        """Convert a pysnmp value into bytes / int / str (or None for exceptions such as noSuchObject)."""
        type_name = type(value).__name__
        if type_name in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
            return None
        if type_name in ("OctetString", "Opaque", "Bits"):
            return bytes(value.asOctets())
        if type_name == "IpAddress":
            return ".".join(str(b) for b in value.asNumbers())
        if type_name == "ObjectIdentifier" or type_name == "ObjectName":
            return str(value)
        try:
            return int(value)
        except (TypeError, ValueError):
            return value.prettyPrint()

    def get(self, oids: list[str]) -> dict[str, object]:
        self._setup()
        hl = self._hlapi

        async def run():
            return await hl.get_cmd(self._engine, self._auth, self._transport, hl.ContextData(),
                                    *[hl.ObjectType(hl.ObjectIdentity(oid)) for oid in oids], lookupMib=False)

        error_indication, error_status, _error_index, var_binds = self._loop.run_until_complete(run())
        if error_indication:
            raise SnmpError(str(error_indication))
        if error_status:
            # noSuchName (v1-style) for a missing scalar: retry one by one so one missing OID doesn't hide the rest
            if len(oids) > 1:
                result = {}
                for oid in oids:
                    try:
                        result.update(self.get([oid]))
                    except SnmpError:
                        continue
                return result
            raise SnmpError(error_status.prettyPrint())
        result = {}
        for name, value in var_binds:
            converted = self._convert(value)
            if converted is not None:
                result[str(name)] = converted
        return result

    def walk(self, oid: str) -> dict[str, object]:
        self._setup()
        hl = self._hlapi

        async def run():
            result = {}
            async for error_indication, error_status, _error_index, var_binds in hl.bulk_walk_cmd(
                self._engine, self._auth, self._transport, hl.ContextData(), 0, self.max_repetitions,
                hl.ObjectType(hl.ObjectIdentity(oid)), lexicographicMode=False, lookupMib=False,
            ):
                if error_indication:
                    raise SnmpError(str(error_indication))
                if error_status:
                    break
                for name, value in var_binds:
                    converted = self._convert(value)
                    if converted is not None:
                        result[str(name)] = converted
            return result

        return self._loop.run_until_complete(run())

    def close(self):
        try:
            if self._engine is not None:
                self._engine.close_dispatcher()
        except Exception:  # pragma: no cover - best effort cleanup
            pass
        finally:
            self._loop.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --- Parsing ---------------------------------------------------------------------------------------------------
@dataclass
class SnmpResult:
    facts: DeviceFacts
    interfaces: list[DiscoveredInterface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _column(data: dict, base: str) -> dict[str, object]:
    """Strip ``base`` from walked OIDs, returning {index_suffix: value}."""
    prefix = base + "."
    return {oid[len(prefix):]: value for oid, value in data.items() if oid.startswith(prefix)}


def _int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _text(value) -> str:
    return bytes_to_text(value) if isinstance(value, (bytes, bytearray)) else ("" if value is None else str(value))


_VERSION_PATTERNS = (
    re.compile(r"JUNOS ([\w.\-]+)", re.I),
    re.compile(r"EOS version ([\w.\-]+)", re.I),
    re.compile(r"\bVersion:?\s+([\w.()\-:]+?)(?:,|\s|$)", re.I),
    re.compile(r"\brevision ([\w.]+)", re.I),
    re.compile(r"\b([A-Z]{2}\.\d+\.\d+\.\d+)\b"),  # AOS-CX / ArubaOS-Switch firmware, e.g. FL.10.10.1020
    re.compile(r"^Linux \S+ (\S+)"),
)


def parse_os_version(sys_descr: str | None) -> str | None:
    if not sys_descr:
        return None
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(sys_descr)
        if match:
            return match.group(1).rstrip(",")
    return None


_MODEL_FROM_DESCR = (
    re.compile(r"running on an? Arista Networks (\S+)", re.I),
    re.compile(r"^(?:HPE?|Aruba) (J[A-Z]?\d{3,4}[A-Z]?)\b"),
    re.compile(r"^Juniper Networks?,? Inc\. (\S+)", re.I),
    re.compile(r"^Juniper (\S+)", re.I),
    re.compile(r"^(Forti\w+-\w+)", re.I),
)


def _model_from_descr(sys_descr: str) -> str | None:
    for pattern in _MODEL_FROM_DESCR:
        match = pattern.search(sys_descr or "")
        if match:
            return match.group(1)
    return None


def _ip_from_index(parts: list[int]) -> tuple[str | None, int]:
    """
    Decode an InetAddress encoded in an OID index as ``type.len.octets...``; return (address, components used).
    """
    if len(parts) < 2:
        return None, len(parts)
    addr_type, length = parts[0], parts[1]
    octets = parts[2:2 + length]
    used = 2 + length
    if len(octets) != length:
        return None, used
    try:
        if addr_type == 1 and length == 4:
            return str(ipaddress.IPv4Address(bytes(octets))), used
        if addr_type == 2 and length == 16:
            return str(ipaddress.IPv6Address(bytes(octets))), used
    except ValueError:
        return None, used
    return None, used  # ipv4z / ipv6z (zoned, link-local) and dns are ignored


def _probe(client) -> dict:
    return client.get([SYS_OBJECT_ID, SYS_DESCR, SYS_NAME, SYS_LOCATION, SYS_CONTACT])


def collect_snmp(client, collect_neighbors: bool = True, collect_arp: bool = True,
                 manufacturer_aliases: dict | None = None, system: dict | None = None) -> SnmpResult:
    """
    Collect device facts, interfaces, neighbors and the ARP table from an SNMP agent. ``client`` is anything with
    ``get(oids) -> dict`` and ``walk(oid) -> dict``. ``system`` may contain a previous probe result.
    """
    errors = []
    system = system or _probe(client)
    if not system:
        raise SnmpError("No response to system group")

    sys_descr = _text(system.get(SYS_DESCR))
    sys_object_id = str(system.get(SYS_OBJECT_ID) or "") or None
    sys_name = _text(system.get(SYS_NAME)) or None
    platform = detect_platform(sys_object_id=sys_object_id, sys_descr=sys_descr)

    def walk(oid):
        try:
            return client.walk(oid)
        except SnmpError as exc:
            errors.append(f"walk {oid}: {exc}")
            return {}

    # --- Interfaces -----------------------------------------------------------------------------------------
    if_descr = {k: _text(v) for k, v in _column(walk(IF_DESCR), IF_DESCR).items()}
    if_name = {k: _text(v) for k, v in _column(walk(IF_NAME), IF_NAME).items()}
    if_type = _column(walk(IF_TYPE), IF_TYPE)
    if_mtu = _column(walk(IF_MTU), IF_MTU)
    if_speed = _column(walk(IF_SPEED), IF_SPEED)
    if_high_speed = _column(walk(IF_HIGH_SPEED), IF_HIGH_SPEED)
    if_mac = _column(walk(IF_PHYS_ADDRESS), IF_PHYS_ADDRESS)
    if_admin = _column(walk(IF_ADMIN_STATUS), IF_ADMIN_STATUS)
    if_oper = _column(walk(IF_OPER_STATUS), IF_OPER_STATUS)
    if_alias = {k: _text(v) for k, v in _column(walk(IF_ALIAS), IF_ALIAS).items()}

    prefer_descr = platform in ("cisco_ios", "cisco_xe", "cisco_nxos")
    interfaces: dict[str, DiscoveredInterface] = {}  # keyed by ifIndex
    for index in sorted(set(if_descr) | set(if_name), key=lambda i: _int(i, 0)):
        preferred = if_descr.get(index) if prefer_descr else if_name.get(index)
        name = preferred or if_name.get(index) or if_descr.get(index)
        if not name:
            continue
        high = _int(if_high_speed.get(index), 0)
        speed = high * 1000 if high else (_int(if_speed.get(index), 0) // 1000 or None)
        mac = normalize_mac(if_mac.get(index)) if if_mac.get(index) else None
        iftype = _int(if_type.get(index))
        mtu = _int(if_mtu.get(index))
        interfaces[index] = DiscoveredInterface(
            name=name,
            description=if_alias.get(index, ""),
            if_type=iftype,
            type=guess_interface_type(name, iftype, speed),
            speed_kbps=speed or None,
            mtu=mtu if mtu and 0 < mtu <= 65536 else None,
            mac_address=mac if mac and mac != "00:00:00:00:00:00" else None,
            enabled=_int(if_admin.get(index)) == 1 if index in if_admin else None,
            oper_up=_int(if_oper.get(index)) == 1 if index in if_oper else None,
            if_index=_int(index),
        )

    # LAG membership (IEEE8023-LAG-MIB)
    for member, agg in _column(walk(DOT3AD_AGG_PORT_ATTACHED_AGG_ID), DOT3AD_AGG_PORT_ATTACHED_AGG_ID).items():
        agg_if = interfaces.get(str(_int(agg)))
        member_if = interfaces.get(member)
        if agg_if and member_if and agg_if is not member_if:
            member_if.lag = agg_if.name
            agg_if.type = "lag"

    # --- IP addresses ---------------------------------------------------------------------------------------
    def add_ip(if_index, cidr):
        interface = interfaces.get(str(if_index))
        if interface and cidr not in interface.ip_addresses:
            interface.ip_addresses.append(cidr)

    masks = _column(walk(IP_AD_ENT_NETMASK), IP_AD_ENT_NETMASK)
    for ip, if_index in _column(walk(IP_AD_ENT_IF_INDEX), IP_AD_ENT_IF_INDEX).items():
        try:
            mask = masks.get(ip)
            prefixlen = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen if mask else 32
            address = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if address.is_loopback or address.is_link_local:
            continue
        add_ip(if_index, f"{address}/{prefixlen}")

    ip_address_types = _column(walk(IP_ADDRESS_TYPE), IP_ADDRESS_TYPE)
    ip_address_prefixes = _column(walk(IP_ADDRESS_PREFIX), IP_ADDRESS_PREFIX)
    for index, if_index in _column(walk(IP_ADDRESS_IF_INDEX), IP_ADDRESS_IF_INDEX).items():
        if _int(ip_address_types.get(index), 1) != 1:  # unicast only
            continue
        parts = [_int(p, -1) for p in index.split(".")]
        address, _used = _ip_from_index(parts)
        if address is None:
            continue
        ip = ipaddress.ip_address(address)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
            continue
        prefix_pointer = str(ip_address_prefixes.get(index) or "")
        prefixlen = None
        if prefix_pointer and prefix_pointer not in ("0.0", ".0.0"):
            prefixlen = _int(prefix_pointer.rsplit(".", 1)[-1])
        if prefixlen is None or prefixlen > ip.max_prefixlen or prefixlen == 0:
            prefixlen = 32 if ip.version == 4 else 64
        add_ip(if_index, f"{ip}/{prefixlen}")

    # --- Inventory (ENTITY-MIB + vendor fallbacks) ---------------------------------------------------------
    serial = model = vendor = None
    os_version = parse_os_version(sys_descr)
    classes = _column(walk(ENT_PHYSICAL_CLASS), ENT_PHYSICAL_CLASS)
    chassis = sorted((idx for idx, cls in classes.items() if _int(cls) == ENT_CLASS_CHASSIS), key=lambda i: _int(i, 0))
    if chassis:
        contained = _column(walk(ENT_PHYSICAL_CONTAINED_IN), ENT_PHYSICAL_CONTAINED_IN)
        top_level = [idx for idx in chassis if _int(contained.get(idx), 0) == 0] or chassis
        entity = top_level[0]
        columns = (ENT_PHYSICAL_SERIAL, ENT_PHYSICAL_MODEL_NAME, ENT_PHYSICAL_MFG_NAME, ENT_PHYSICAL_DESCR,
                   ENT_PHYSICAL_SOFTWARE_REV)
        try:
            values = client.get([f"{column}.{entity}" for column in columns])
        except SnmpError as exc:
            errors.append(f"ENTITY-MIB: {exc}")
            values = {}
        fields = {column: _text(values.get(f"{column}.{entity}")) for column in columns}
        serial = fields[ENT_PHYSICAL_SERIAL] or None
        model = fields[ENT_PHYSICAL_MODEL_NAME] or None
        vendor = fields[ENT_PHYSICAL_MFG_NAME] or None
        if not model and fields[ENT_PHYSICAL_DESCR]:
            model = _model_from_descr(fields[ENT_PHYSICAL_DESCR])
        if fields[ENT_PHYSICAL_SOFTWARE_REV] and not os_version:
            os_version = fields[ENT_PHYSICAL_SOFTWARE_REV]

    vendor_scalars = []
    if platform == "juniper_junos":
        vendor_scalars = [JNX_BOX_SERIAL, JNX_BOX_DESCR]
    elif platform == "fortinet_fortios":
        vendor_scalars = [FN_SYS_SERIAL, FG_SYS_VERSION]
    elif platform == "paloalto_panos":
        vendor_scalars = [PAN_SYS_SERIAL, PAN_SYS_SW_VERSION]
    elif platform == "hp_procurve":
        vendor_scalars = [HP_SERIAL]
    elif platform in ("cisco_ios", "cisco_xe") and not serial:
        vendor_scalars = [CISCO_CHASSIS_ID]
    if vendor_scalars:
        try:
            scalars = client.get(vendor_scalars)
        except SnmpError:
            scalars = {}
        serial = serial or _text(scalars.get(JNX_BOX_SERIAL) or scalars.get(FN_SYS_SERIAL)
                                 or scalars.get(PAN_SYS_SERIAL) or scalars.get(HP_SERIAL)
                                 or scalars.get(CISCO_CHASSIS_ID)) or None
        if scalars.get(JNX_BOX_DESCR) and not model:
            model = _model_from_descr(_text(scalars[JNX_BOX_DESCR]))
        if scalars.get(FG_SYS_VERSION):
            os_version = _text(scalars[FG_SYS_VERSION]).split(",")[0]
        if scalars.get(PAN_SYS_SW_VERSION):
            os_version = _text(scalars[PAN_SYS_SW_VERSION])

    model = model or _model_from_descr(sys_descr)
    if platform and not vendor:
        vendor = PLATFORMS[platform].manufacturer

    facts = DeviceFacts(
        hostname=sys_name.split(".")[0] if sys_name else None,
        fqdn=sys_name if sys_name and "." in sys_name else None,
        vendor=normalize_manufacturer(vendor, manufacturer_aliases),
        model=model,
        serial=serial,
        os_version=os_version,
        platform=platform,
        sys_object_id=sys_object_id,
        sys_descr=sys_descr or None,
        sys_location=_text(system.get(SYS_LOCATION)) or None,
        sys_contact=_text(system.get(SYS_CONTACT)) or None,
    )

    name_by_index = {idx: iface.name for idx, iface in interfaces.items()}
    neighbors = []
    if collect_neighbors:
        neighbors = _collect_lldp(walk, interfaces) + _collect_cdp(walk, name_by_index)

    arp = []
    if collect_arp:
        arp = _collect_arp(walk, name_by_index)

    return SnmpResult(facts=facts, interfaces=list(interfaces.values()), neighbors=neighbors, arp=arp, errors=errors)


def _decode_chassis_id(subtype, value) -> str | None:
    if value is None:
        return None
    subtype = _int(subtype)
    if subtype == 4:  # macAddress
        return normalize_mac(value)
    if subtype == 5 and isinstance(value, (bytes, bytearray)) and len(value) == 5 and value[0] == 1:
        return str(ipaddress.IPv4Address(bytes(value[1:])))
    if isinstance(value, (bytes, bytearray)) and len(value) == 6 and subtype != 7:
        return normalize_mac(value)
    return _text(value) or None


def _collect_lldp(walk, interfaces: dict[str, DiscoveredInterface]) -> list[Neighbor]:
    rem_sys_name = _column(walk(LLDP_REM_SYS_NAME), LLDP_REM_SYS_NAME)
    rem_port_id = _column(walk(LLDP_REM_PORT_ID), LLDP_REM_PORT_ID)
    if not rem_sys_name and not rem_port_id:
        return []
    rem_port_id_subtype = _column(walk(LLDP_REM_PORT_ID_SUBTYPE), LLDP_REM_PORT_ID_SUBTYPE)
    rem_port_desc = _column(walk(LLDP_REM_PORT_DESC), LLDP_REM_PORT_DESC)
    rem_chassis = _column(walk(LLDP_REM_CHASSIS_ID), LLDP_REM_CHASSIS_ID)
    rem_chassis_subtype = _column(walk(LLDP_REM_CHASSIS_ID_SUBTYPE), LLDP_REM_CHASSIS_ID_SUBTYPE)
    rem_sys_desc = _column(walk(LLDP_REM_SYS_DESC), LLDP_REM_SYS_DESC)
    loc_port_id = {k: _text(v) for k, v in _column(walk(LLDP_LOC_PORT_ID), LLDP_LOC_PORT_ID).items()}
    loc_port_desc = {k: _text(v) for k, v in _column(walk(LLDP_LOC_PORT_DESC), LLDP_LOC_PORT_DESC).items()}

    # Management addresses: index = timeMark.localPort.remIndex.addrSubtype.addrLen.octets...
    mgmt = {}
    for index in _column(walk(LLDP_REM_MAN_ADDR_IF_SUBTYPE), LLDP_REM_MAN_ADDR_IF_SUBTYPE):
        parts = [_int(p, -1) for p in index.split(".")]
        if len(parts) < 5:
            continue
        key = ".".join(str(p) for p in parts[:3])
        subtype, length, octets = parts[3], parts[4], parts[5:5 + parts[4]]
        try:
            if subtype == 1 and length == 4:
                mgmt.setdefault(key, str(ipaddress.IPv4Address(bytes(octets))))
            elif subtype == 2 and length == 16:
                mgmt.setdefault(key, str(ipaddress.IPv6Address(bytes(octets))))
        except ValueError:
            continue

    by_canonical = {canonical_interface_name(i.name): i.name for i in interfaces.values()}

    def local_name(port_num: str) -> str | None:
        candidates = [loc_port_desc.get(port_num), loc_port_id.get(port_num)]
        for candidate in candidates:
            if candidate and canonical_interface_name(candidate) in by_canonical:
                return by_canonical[canonical_interface_name(candidate)]
        port_id = loc_port_id.get(port_num)
        if port_id and port_id.isdigit() and port_id in interfaces:
            return interfaces[port_id].name
        if port_num in interfaces:
            return interfaces[port_num].name
        return next((c for c in candidates if c), None)

    neighbors = []
    for index in sorted(set(rem_port_id) | set(rem_sys_name)):
        parts = index.split(".")
        if len(parts) < 3:
            continue
        local = local_name(parts[1])
        if not local:
            continue
        port_subtype = _int(rem_port_id_subtype.get(index))
        port_value = rem_port_id.get(index)
        if port_subtype == 3:  # macAddress
            remote_port = normalize_mac(port_value)
        else:
            remote_port = _text(port_value) or None
        neighbors.append(Neighbor(
            local_interface=local,
            protocol="lldp",
            remote_name=_text(rem_sys_name.get(index)) or None,
            remote_interface=remote_port,
            remote_interface_description=_text(rem_port_desc.get(index)) or None,
            remote_chassis_id=_decode_chassis_id(rem_chassis_subtype.get(index), rem_chassis.get(index)),
            remote_mgmt_address=mgmt.get(".".join(parts[:3])),
            remote_platform=(_text(rem_sys_desc.get(index)) or None),
        ))
    return neighbors


def _collect_cdp(walk, name_by_index: dict[str, str]) -> list[Neighbor]:
    device_ids = _column(walk(CDP_CACHE_DEVICE_ID), CDP_CACHE_DEVICE_ID)
    if not device_ids:
        return []
    ports = _column(walk(CDP_CACHE_DEVICE_PORT), CDP_CACHE_DEVICE_PORT)
    addresses = _column(walk(CDP_CACHE_ADDRESS), CDP_CACHE_ADDRESS)
    address_types = _column(walk(CDP_CACHE_ADDRESS_TYPE), CDP_CACHE_ADDRESS_TYPE)
    platforms = _column(walk(CDP_CACHE_PLATFORM), CDP_CACHE_PLATFORM)
    neighbors = []
    for index, device_id in sorted(device_ids.items()):
        if_index = index.split(".")[0]
        local = name_by_index.get(if_index)
        if not local:
            continue
        mgmt = None
        raw = addresses.get(index)
        if _int(address_types.get(index), 1) == 1 and isinstance(raw, (bytes, bytearray)) and len(raw) == 4:
            mgmt = str(ipaddress.IPv4Address(bytes(raw)))
        neighbors.append(Neighbor(
            local_interface=local,
            protocol="cdp",
            remote_name=_text(device_id) or None,
            remote_interface=_text(ports.get(index)) or None,
            remote_mgmt_address=mgmt,
            remote_platform=_text(platforms.get(index)) or None,
        ))
    return neighbors


def _collect_arp(walk, name_by_index: dict[str, str]) -> list[ArpEntry]:
    entries = {}
    types = _column(walk(IP_NET_TO_MEDIA_TYPE), IP_NET_TO_MEDIA_TYPE)
    for index, mac in _column(walk(IP_NET_TO_MEDIA_PHYS_ADDRESS), IP_NET_TO_MEDIA_PHYS_ADDRESS).items():
        if _int(types.get(index), 3) == 2:  # invalid
            continue
        parts = index.split(".")
        if len(parts) != 5:
            continue
        if_index, ip = parts[0], ".".join(parts[1:])
        mac = normalize_mac(mac)
        if mac and mac != "00:00:00:00:00:00":
            entries[ip] = ArpEntry(ip_address=ip, mac_address=mac, interface=name_by_index.get(if_index))
    if not entries:
        for index, mac in _column(walk(IP_NET_TO_PHYSICAL_PHYS_ADDRESS), IP_NET_TO_PHYSICAL_PHYS_ADDRESS).items():
            parts = [_int(p, -1) for p in index.split(".")]
            address, _ = _ip_from_index(parts[1:])
            mac = normalize_mac(mac)
            if address and mac and mac != "00:00:00:00:00:00":
                if ipaddress.ip_address(address).is_link_local:
                    continue
                entries[address] = ArpEntry(ip_address=address, mac_address=mac,
                                            interface=name_by_index.get(str(parts[0])))
    return list(entries.values())


def probe_snmp(client) -> dict:
    """Return the system group, or raise SnmpError if the agent does not answer with this credential."""
    system = _probe(client)
    if not system or (SYS_OBJECT_ID not in system and SYS_DESCR not in system):
        raise SnmpError("No response")
    return system
