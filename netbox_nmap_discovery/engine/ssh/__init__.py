"""
SSH collection using NAPALM (Cisco IOS/IOS-XE/NX-OS, Junos, EOS) and Netmiko (FortiOS, PAN-OS, AOS-CX,
ArubaOS-Switch, Linux).

Every collector returns an ``SshResult``; failures of individual commands are recorded in ``errors`` and do not
abort collection. Authentication / connection failures raise ``SshAuthError`` / ``SshError`` so the caller can
try the next credential.
"""
from __future__ import annotations

import logging
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field

from ..interfaces import guess_interface_type
from ..platforms import NETMIKO_TO_PLATFORM, PLATFORMS
from ..results import ArpEntry, DeviceFacts, DiscoveredInterface, Neighbor
from ..utils import normalize_mac
from . import parsers

__all__ = (
    "SshAuthError",
    "SshCredential",
    "SshError",
    "SshResult",
    "autodetect_platform",
    "collect_ssh",
)

logger = logging.getLogger("netbox_nmap_discovery.engine.ssh")


class SshError(Exception):
    pass


class SshAuthError(SshError):
    pass


@dataclass
class SshCredential:
    username: str
    password: str = ""
    enable_secret: str = ""
    private_key: str = ""  # PEM-encoded private key (optional)
    port: int = 22
    options: dict = field(default_factory=dict)  # extra NAPALM optional_args / Netmiko connection arguments
    id: int | None = None


@dataclass
class SshResult:
    facts: DeviceFacts
    interfaces: list[DiscoveredInterface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@contextmanager
def _key_file(private_key: str):
    """Write a private key to a 0600 temp file for the duration of a connection."""
    if not private_key:
        yield None
        return
    fd, path = tempfile.mkstemp(prefix="nbdisc-", suffix=".key")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(private_key.strip() + "\n")
        os.chmod(path, 0o600)
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _classify_exception(exc: Exception) -> SshError:
    name = type(exc).__name__
    text = str(exc)
    if "Authentication" in name or "authentication" in text.lower() or "auth" in name.lower():
        return SshAuthError(f"{name}: {text}"[:500])
    return SshError(f"{name}: {text}"[:500])


def _netmiko_params(host: str, credential: SshCredential, device_type: str, timeout: int, key_file: str | None):
    params = {
        "device_type": device_type,
        "host": host,
        "username": credential.username,
        "password": credential.password or None,
        "secret": credential.enable_secret or "",
        "port": credential.port or 22,
        "conn_timeout": timeout,
        "auth_timeout": timeout,
        "banner_timeout": timeout,
        "timeout": timeout,
        "fast_cli": False,
    }
    if key_file:
        params.update({"use_keys": True, "key_file": key_file})
    else:
        params.update({"use_keys": False, "allow_agent": False})
    params.update({k: v for k, v in (credential.options or {}).items() if k not in ("host", "device_type")})
    return params


def autodetect_platform(host: str, credential: SshCredential, timeout: int = 30) -> str | None:
    """Use Netmiko's SSHDetect to guess the platform of an unknown device."""
    from netmiko import SSHDetect

    with _key_file(credential.private_key) as key_file:
        params = _netmiko_params(host, credential, "autodetect", timeout, key_file)
        try:
            detector = SSHDetect(**params)
            best = detector.autodetect()
            detector.connection.disconnect()
        except Exception as exc:  # netmiko raises many exception types
            raise _classify_exception(exc) from exc
    return NETMIKO_TO_PLATFORM.get(best) if best else None


def collect_ssh(host: str, credential: SshCredential, platform: str, timeout: int = 30,
                collect_neighbors: bool = True, collect_arp: bool = True) -> SshResult:
    spec = PLATFORMS.get(platform)
    if spec is None or spec.collector is None:
        raise SshError(f"No SSH collector for platform {platform!r}")
    if spec.collector == "napalm":
        return _collect_napalm(host, credential, spec, timeout, collect_neighbors, collect_arp)
    collector = _NETMIKO_COLLECTORS[spec.collector]
    return _collect_netmiko(host, credential, spec, timeout, collector, collect_neighbors, collect_arp)


# --- NAPALM -----------------------------------------------------------------------------------------------------
def _collect_napalm(host, credential, spec, timeout, collect_neighbors, collect_arp) -> SshResult:
    from napalm import get_network_driver

    errors = []
    with _key_file(credential.private_key) as key_file:
        optional_args = {"port": credential.port or 22}
        if credential.enable_secret:
            optional_args["secret"] = credential.enable_secret
        if key_file:
            optional_args.update({"key_file": key_file, "use_keys": True})
        optional_args.update(credential.options or {})
        driver = get_network_driver(spec.napalm_driver)
        device = driver(hostname=host, username=credential.username, password=credential.password or "",
                        timeout=timeout, optional_args=optional_args)
        try:
            device.open()
        except Exception as exc:
            raise _classify_exception(exc) from exc
        try:
            facts_raw = device.get_facts()
            facts = DeviceFacts(
                hostname=(facts_raw.get("hostname") or None),
                fqdn=(facts_raw.get("fqdn") or None) if facts_raw.get("fqdn") not in ("", "Unknown") else None,
                vendor=facts_raw.get("vendor") or spec.manufacturer,
                model=facts_raw.get("model") or None,
                serial=(facts_raw.get("serial_number") or None),
                os_version=facts_raw.get("os_version") or None,
                platform=spec.key,
            )

            interfaces: dict[str, DiscoveredInterface] = {}
            try:
                for name, data in device.get_interfaces().items():
                    speed = data.get("speed")
                    speed_kbps = int(float(speed) * 1000) if speed and float(speed) > 0 else None
                    mtu = data.get("mtu")
                    interfaces[name] = DiscoveredInterface(
                        name=name,
                        description=data.get("description") or "",
                        type=guess_interface_type(name, None, speed_kbps),
                        speed_kbps=speed_kbps,
                        mtu=mtu if isinstance(mtu, int) and 0 < mtu <= 65536 else None,
                        mac_address=normalize_mac(data.get("mac_address")),
                        enabled=data.get("is_enabled"),
                        oper_up=data.get("is_up"),
                    )
            except Exception as exc:
                errors.append(f"get_interfaces: {exc}")

            try:
                for name, families in device.get_interfaces_ip().items():
                    interface = interfaces.setdefault(name, DiscoveredInterface(name=name,
                                                                                type=guess_interface_type(name)))
                    for family in ("ipv4", "ipv6"):
                        for address, info in (families.get(family) or {}).items():
                            cidr = parsers._cidr(address, info.get("prefix_length"))
                            if cidr and not cidr.startswith(("fe80", "127.")) and cidr not in interface.ip_addresses:
                                interface.ip_addresses.append(cidr)
            except Exception as exc:
                errors.append(f"get_interfaces_ip: {exc}")

            neighbors = []
            if collect_neighbors:
                try:
                    for local, entries in device.get_lldp_neighbors_detail().items():
                        for entry in entries:
                            neighbors.append(Neighbor(
                                local_interface=local,
                                protocol="lldp",
                                remote_name=entry.get("remote_system_name") or None,
                                remote_interface=entry.get("remote_port") or None,
                                remote_interface_description=entry.get("remote_port_description") or None,
                                remote_chassis_id=(normalize_mac(entry.get("remote_chassis_id"))
                                                   or entry.get("remote_chassis_id") or None),
                                remote_mgmt_address=entry.get("remote_management_address") or None,
                                remote_platform=entry.get("remote_system_description") or None,
                            ))
                except Exception as exc:
                    errors.append(f"get_lldp_neighbors_detail: {exc}")
                if spec.key in ("cisco_ios", "cisco_xe", "cisco_nxos"):
                    try:
                        output = device.cli(["show cdp neighbors detail"]).get("show cdp neighbors detail", "")
                        neighbors.extend(parsers.parse_cdp_neighbors_detail(output))
                    except Exception as exc:
                        errors.append(f"show cdp neighbors detail: {exc}")

            arp = []
            if collect_arp:
                try:
                    for entry in device.get_arp_table():
                        mac = normalize_mac(entry.get("mac"))
                        if mac and mac != "00:00:00:00:00:00" and entry.get("ip"):
                            arp.append(ArpEntry(ip_address=entry["ip"], mac_address=mac,
                                                interface=entry.get("interface") or None))
                except Exception as exc:
                    errors.append(f"get_arp_table: {exc}")
        except Exception as exc:
            raise _classify_exception(exc) from exc
        finally:
            try:
                device.close()
            except Exception:
                pass
    return SshResult(facts=facts, interfaces=list(interfaces.values()), neighbors=neighbors, arp=arp, errors=errors)


# --- Netmiko ----------------------------------------------------------------------------------------------------
def _collect_netmiko(host, credential, spec, timeout, collector, collect_neighbors, collect_arp) -> SshResult:
    from netmiko import ConnectHandler

    with _key_file(credential.private_key) as key_file:
        params = _netmiko_params(host, credential, spec.netmiko_device_type, timeout, key_file)
        try:
            connection = ConnectHandler(**params)
        except Exception as exc:
            raise _classify_exception(exc) from exc
        errors = []

        def run(command, read_timeout=60):
            try:
                return connection.send_command(command, read_timeout=read_timeout)
            except Exception as exc:
                errors.append(f"{command}: {exc}")
                return ""

        try:
            if credential.enable_secret and spec.key in ("hp_procurve",):
                try:
                    connection.enable()
                except Exception as exc:
                    errors.append(f"enable: {exc}")
            result = collector(run, collect_neighbors, collect_arp)
        finally:
            try:
                connection.disconnect()
            except Exception:
                pass
    result.errors.extend(errors)
    result.facts.platform = spec.key
    return result


def _linux(run, collect_neighbors, collect_arp) -> SshResult:
    hostname = run("hostname").strip()
    fqdn = run("hostname -f 2>/dev/null").strip()
    dmi = parsers.parse_linux_dmi(run(
        "for f in sys_vendor product_name product_serial; do printf '%s=' $f; "
        "cat /sys/class/dmi/id/$f 2>/dev/null || sudo -n cat /sys/class/dmi/id/$f 2>/dev/null || echo; done"
    ))
    os_version = parsers.parse_linux_os_release(run("cat /etc/os-release 2>/dev/null"))
    speeds = {}
    for line in run("for i in /sys/class/net/*; do echo \"$(basename $i) $(cat $i/speed 2>/dev/null)\"; done"
                    ).splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("-").isdigit():
            speeds[parts[0]] = int(parts[1])
    interfaces = parsers.parse_linux_ip_addr(run("ip -j -d addr show"), speeds)
    neighbors = parsers.parse_linux_lldpctl(run("lldpctl -f json 2>/dev/null")) if collect_neighbors else []
    arp = parsers.parse_linux_ip_neigh(run("ip -j neigh show")) if collect_arp else []
    facts = DeviceFacts(
        hostname=hostname.split(".")[0] or None,
        fqdn=fqdn if "." in fqdn else None,
        vendor=dmi.get("sys_vendor"),
        model=dmi.get("product_name"),
        serial=dmi.get("product_serial"),
        os_version=os_version,
    )
    return SshResult(facts=facts, interfaces=interfaces, neighbors=neighbors, arp=arp)


def _fortios(run, collect_neighbors, collect_arp) -> SshResult:
    facts = parsers.parse_fortios_system_status(run("get system status"))
    interfaces = parsers.parse_fortios_interfaces(run("get system interface physical"))
    arp = parsers.parse_fortios_arp(run("get system arp")) if collect_arp else []
    return SshResult(facts=facts, interfaces=interfaces, arp=arp)


def _panos(run, collect_neighbors, collect_arp) -> SshResult:
    facts = parsers.parse_panos_system_info(run("show system info"))
    interfaces = parsers.parse_panos_interfaces(run("show interface all"))
    arp = parsers.parse_panos_arp(run("show arp all")) if collect_arp else []
    return SshResult(facts=facts, interfaces=interfaces, arp=arp)


def _aoscx(run, collect_neighbors, collect_arp) -> SshResult:
    facts = parsers.parse_aoscx_system(run("show system"))
    interfaces = parsers.parse_aoscx_interface_brief(run("show interface brief"))
    neighbors = parsers.parse_aoscx_lldp_detail(run("show lldp neighbor-info detail")) if collect_neighbors else []
    return SshResult(facts=facts, interfaces=interfaces, neighbors=neighbors)


def _procurve(run, collect_neighbors, collect_arp) -> SshResult:
    facts = parsers.parse_procurve_system(run("show system"))
    neighbors = (parsers.parse_procurve_lldp_detail(run("show lldp info remote-device detail"))
                 if collect_neighbors else [])
    return SshResult(facts=facts, neighbors=neighbors)


_NETMIKO_COLLECTORS = {
    "linux": _linux,
    "fortios": _fortios,
    "panos": _panos,
    "aoscx": _aoscx,
    "procurve": _procurve,
}
