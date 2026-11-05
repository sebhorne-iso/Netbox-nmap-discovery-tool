"""
Discovery orchestration: nmap sweep -> SNMP -> SSH -> merge, followed by LLDP/CDP neighbour follow-up and ARP
harvesting. Produces a list of ``HostResult`` objects; it never touches NetBox.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import nmap as nmap_mod
from .platforms import PLATFORMS, detect_platform
from .results import DeviceFacts, DiscoveredInterface, HostResult, NmapHost
from .snmp import SnmpClient, SnmpCredential, SnmpError, collect_snmp, probe_snmp
from .ssh import SshAuthError, SshCredential, SshError, autodetect_platform, collect_ssh
from .utils import address_in_networks, canonical_interface_name, parse_target_networks, short_hostname

__all__ = ("DiscoveryEngine", "ScanRequest", "ScanResult", "merge_interfaces")

logger = logging.getLogger("netbox_nmap_discovery.engine")

MAX_NEIGHBOR_FOLLOWUPS = 256


@dataclass
class ScanRequest:
    targets: list[str]
    exclusions: list[str] = field(default_factory=list)
    profile: str = "conservative"
    custom_args: str = ""
    snmp_enabled: bool = True
    ssh_enabled: bool = True
    collect_neighbors: bool = True
    collect_arp: bool = True
    snmp_credentials: list[SnmpCredential] = field(default_factory=list)
    ssh_credentials: list[SshCredential] = field(default_factory=list)
    # address -> {"snmp": credential id, "ssh": credential id, "platform": key} from previous scans
    hints: dict[str, dict] = field(default_factory=dict)
    skip_nmap: bool = False  # poll the target addresses directly (single-host rediscovery)


@dataclass
class ScanResult:
    hosts: list[HostResult]
    nmap_command: list[str] = field(default_factory=list)
    duration: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def stats(self) -> dict:
        return {
            "hosts_up": len(self.hosts),
            "snmp": sum(1 for h in self.hosts if "snmp" in h.methods),
            "ssh": sum(1 for h in self.hosts if "ssh" in h.methods),
            "managed": sum(1 for h in self.hosts if h.managed),
            "duration_seconds": round(self.duration, 1),
        }


def merge_interfaces(primary: list[DiscoveredInterface], secondary: list[DiscoveredInterface]):
    """
    Merge two interface lists by canonical name. Values from ``secondary`` (SSH) override ``primary`` (SNMP) when
    they are set; IP addresses are unioned. Names from ``primary`` are kept when the interface exists in both,
    unless primary uses an abbreviated name.
    """
    merged: dict[str, DiscoveredInterface] = {canonical_interface_name(i.name): i for i in primary}
    for other in secondary:
        key = canonical_interface_name(other.name)
        existing = merged.get(key)
        if existing is None:
            merged[key] = other
            continue
        if len(other.name) > len(existing.name):
            existing.name = other.name
        for attr in ("description", "type", "speed_kbps", "mtu", "mac_address", "enabled", "oper_up", "lag"):
            value = getattr(other, attr)
            if value not in (None, ""):
                if attr == "type" and value == "other":
                    continue
                setattr(existing, attr, value)
        for cidr in other.ip_addresses:
            if cidr not in existing.ip_addresses:
                existing.ip_addresses.append(cidr)
    return list(merged.values())


class DiscoveryEngine:
    def __init__(self, settings: dict | None = None, log=None):
        settings = settings or {}
        self.settings = settings
        self.nmap_path = settings.get("nmap_path", "nmap")
        self.nmap_timeout = int(settings.get("nmap_timeout", 3600))
        self.privileged = nmap_mod.nmap_is_privileged(settings.get("nmap_privileged"))
        self.snmp_timeout = float(settings.get("snmp_timeout", 2))
        self.snmp_retries = int(settings.get("snmp_retries", 1))
        self.ssh_timeout = int(settings.get("ssh_timeout", 30))
        self.ssh_autodetect = bool(settings.get("ssh_autodetect", True))
        self.max_workers = max(1, int(settings.get("max_workers", 16)))
        self.follow_neighbors = bool(settings.get("poll_lldp_neighbors", True))
        self.manufacturer_aliases = settings.get("manufacturer_aliases") or {}
        exclude = settings.get("interface_exclude_regex")
        self.interface_exclude = re.compile(exclude) if exclude else None
        self._log = log or (lambda level, message: logger.log(level, message))

    def log(self, level, message):
        self._log(level, message)

    # ------------------------------------------------------------------------------------------------------------
    def run(self, request: ScanRequest) -> ScanResult:
        started = time.monotonic()
        errors = []
        networks = parse_target_networks(request.targets)
        excluded = parse_target_networks(request.exclusions)

        command = []
        if request.skip_nmap:
            nmap_hosts = {t: None for t in request.targets if self._is_ip(t)}
        else:
            command = nmap_mod.build_nmap_command(
                request.targets, request.exclusions, request.profile, request.custom_args,
                privileged=self.privileged, nmap_path=self.nmap_path,
            )
            self.log(logging.INFO, f"Running nmap ({'privileged' if self.privileged else 'unprivileged'}): "
                                   f"{' '.join(command[1:])}")
            xml = nmap_mod.run_nmap(command, timeout=self.nmap_timeout)
            scanned_ports = request.profile != "discovery"
            nmap_hosts = {h.address: h for h in nmap_mod.parse_nmap_xml(xml, ports_scanned=scanned_ports)}
            self.log(logging.INFO, f"nmap found {len(nmap_hosts)} live host(s)")

        hosts: dict[str, HostResult] = {}
        self._poll_many(nmap_hosts, request, hosts, source="manual" if request.skip_nmap else "nmap")

        # Follow LLDP/CDP neighbours whose management address is in scope but which nmap did not report
        if request.collect_neighbors and self.follow_neighbors and networks:
            followups = 0
            while followups < MAX_NEIGHBOR_FOLLOWUPS:
                pending = {}
                for host in list(hosts.values()):
                    for neighbor in host.neighbors:
                        address = neighbor.remote_mgmt_address
                        if (address and address not in hosts and address not in pending
                                and address_in_networks(address, networks)
                                and not address_in_networks(address, excluded)):
                            pending[address] = None
                if not pending:
                    break
                pending = dict(list(pending.items())[:MAX_NEIGHBOR_FOLLOWUPS - followups])
                followups += len(pending)
                self.log(logging.INFO, f"Polling {len(pending)} neighbour(s) learned via LLDP/CDP")
                self._poll_many(pending, request, hosts, source="lldp")

        # ARP harvesting: learn MACs for routed hosts and find in-scope hosts nmap could not see
        if request.collect_arp:
            arp_macs = {}
            for host in hosts.values():
                for entry in host.arp:
                    arp_macs.setdefault(entry.ip_address, entry.mac_address)
            for address, mac in arp_macs.items():
                if address in hosts:
                    if not hosts[address].mac_address:
                        hosts[address].mac_address = mac
                elif networks and address_in_networks(address, networks) and not address_in_networks(address,
                                                                                                     excluded):
                    hosts[address] = HostResult(address=address, source="arp", mac_address=mac)
            arp_only = sum(1 for h in hosts.values() if h.source == "arp")
            if arp_only:
                self.log(logging.INFO, f"Learned {arp_only} additional host(s) from ARP tables")

        return ScanResult(
            hosts=sorted(hosts.values(), key=lambda h: self._sort_key(h.address)),
            nmap_command=command,
            duration=time.monotonic() - started,
            errors=errors,
        )

    @staticmethod
    def _is_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _sort_key(address):
        try:
            ip = ipaddress.ip_address(address)
            return (ip.version, int(ip))
        except ValueError:
            return (9, 0)

    def _poll_many(self, targets: dict[str, NmapHost | None], request: ScanRequest, hosts: dict, source="nmap"):
        if not targets:
            return
        if not (request.snmp_enabled and request.snmp_credentials) and not (
                request.ssh_enabled and request.ssh_credentials):
            for address, nmap_host in targets.items():
                hosts[address] = self._new_host(address, nmap_host, source)
            return
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(targets))) as pool:
            futures = {pool.submit(self.poll_host, address, nmap_host, request, source): address
                       for address, nmap_host in targets.items()}
            done = 0
            for future in as_completed(futures):
                address = futures[future]
                try:
                    hosts[address] = future.result()
                except Exception as exc:  # never let one host abort the scan
                    host = self._new_host(address, targets[address], source)
                    host.errors.append(f"Unexpected error: {exc!r}")
                    hosts[address] = host
                    self.log(logging.WARNING, f"{address}: unexpected error during polling: {exc!r}")
                done += 1
                if done % 50 == 0:
                    self.log(logging.INFO, f"Polled {done}/{len(targets)} host(s)")

    @staticmethod
    def _new_host(address, nmap_host, source):
        return HostResult(
            address=address,
            source=source,
            nmap=nmap_host,
            mac_address=nmap_host.mac_address if nmap_host else None,
            mac_vendor=nmap_host.mac_vendor if nmap_host else None,
        )

    # ------------------------------------------------------------------------------------------------------------
    def poll_host(self, address: str, nmap_host: NmapHost | None, request: ScanRequest, source="nmap"):
        host = self._new_host(address, nmap_host, source)
        hint = request.hints.get(address) or {}
        snmp_facts = ssh_facts = None
        snmp_interfaces, ssh_interfaces = [], []

        # --- SNMP ---
        if request.snmp_enabled and request.snmp_credentials:
            for credential in self._ordered(request.snmp_credentials, hint.get("snmp")):
                client = SnmpClient(address, credential, timeout=self.snmp_timeout, retries=self.snmp_retries)
                try:
                    system = probe_snmp(client)
                    result = collect_snmp(client, request.collect_neighbors, request.collect_arp,
                                          self.manufacturer_aliases, system=system)
                except SnmpError:
                    continue
                except Exception as exc:
                    host.errors.append(f"SNMP ({credential.id}): {exc!r}")
                    continue
                finally:
                    client.close()
                snmp_facts = result.facts
                snmp_interfaces = result.interfaces
                host.neighbors.extend(result.neighbors)
                host.arp.extend(result.arp)
                host.errors.extend(result.errors)
                host.methods.append("snmp")
                host.snmp_credential_id = credential.id
                break

        # --- SSH ---
        platform = (snmp_facts.platform if snmp_facts else None) or hint.get("platform")
        ssh_port_known = nmap_host is not None and nmap_host.ports_scanned
        if request.ssh_enabled and request.ssh_credentials:
            credentials = self._ordered(request.ssh_credentials, hint.get("ssh"))
            ssh_open = (not ssh_port_known) or any(nmap_host.has_port(c.port or 22) for c in credentials)
            if not platform and nmap_host is not None:
                banner = " ".join(f"{p.product} {p.version}" for p in nmap_host.ports if p.port == 22)
                platform = detect_platform(ssh_banner=banner, nmap_os=nmap_host.os_guess)
            worth_trying = ssh_open and (snmp_facts is not None or ssh_port_known or source == "manual")
            if worth_trying:
                if (not platform or not PLATFORMS[platform].collector) and self.ssh_autodetect and ssh_port_known:
                    for credential in credentials:
                        try:
                            platform = autodetect_platform(address, credential, self.ssh_timeout) or platform
                            break
                        except SshAuthError:
                            continue
                        except SshError as exc:
                            host.errors.append(f"SSH autodetect: {exc}")
                            break
                if platform and PLATFORMS.get(platform) and PLATFORMS[platform].collector:
                    for credential in credentials:
                        try:
                            result = collect_ssh(address, credential, platform, self.ssh_timeout,
                                                 request.collect_neighbors, request.collect_arp)
                        except SshAuthError as exc:
                            host.errors.append(f"SSH ({credential.id}): {exc}")
                            continue
                        except SshError as exc:
                            host.errors.append(f"SSH: {exc}")
                            break
                        ssh_facts = result.facts
                        ssh_interfaces = result.interfaces
                        host.neighbors.extend(result.neighbors)
                        host.arp.extend(result.arp)
                        host.errors.extend(result.errors)
                        host.methods.append("ssh")
                        host.ssh_credential_id = credential.id
                        break

        # --- Merge ---
        if snmp_facts or ssh_facts:
            facts = (snmp_facts or DeviceFacts()).merge(ssh_facts)
            facts.platform = facts.platform or platform
            host.facts = facts
            interfaces = merge_interfaces(snmp_interfaces, ssh_interfaces)
            if self.interface_exclude:
                interfaces = [i for i in interfaces if not self.interface_exclude.match(i.name)]
            host.interfaces = interfaces
            host.neighbors = self._dedupe_neighbors(host.neighbors, {canonical_interface_name(i.name)
                                                                     for i in interfaces})
            arp = {}
            for entry in host.arp:
                arp.setdefault(entry.ip_address, entry)
            host.arp = list(arp.values())
            if not host.mac_address:
                interface = host.interface_for_address(address)
                if interface and interface.mac_address:
                    host.mac_address = interface.mac_address
        return host

    @staticmethod
    def _ordered(credentials, preferred_id):
        if preferred_id is None:
            return list(credentials)
        return sorted(credentials, key=lambda c: 0 if c.id == preferred_id else 1)

    @staticmethod
    def _dedupe_neighbors(neighbors, valid_local):
        seen = {}
        for neighbor in neighbors:
            local = canonical_interface_name(neighbor.local_interface)
            if valid_local and local not in valid_local:
                continue
            key = (local, short_hostname(neighbor.remote_name) or (neighbor.remote_chassis_id or "").lower(),
                   canonical_interface_name(neighbor.remote_interface))
            existing = seen.get(key)
            if existing is None:
                seen[key] = neighbor
            else:  # merge details from LLDP + CDP or SNMP + SSH
                for attr in ("remote_interface_description", "remote_chassis_id", "remote_mgmt_address",
                             "remote_platform"):
                    if not getattr(existing, attr) and getattr(neighbor, attr):
                        setattr(existing, attr, getattr(neighbor, attr))
        return list(seen.values())
