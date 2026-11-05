"""
nmap integration: safe command construction, execution and XML parsing.

nmap is always executed without a shell, with arguments passed as a list. User-supplied "custom" arguments are
validated against an allow-list so that a NetBox user with permission to edit scan targets cannot use nmap to
read or write files or run NSE scripts on the NetBox host.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import shlex
import subprocess

from defusedxml import ElementTree

from .results import NmapHost, OpenPort
from .utils import normalize_mac

__all__ = (
    "NmapError",
    "SCAN_PROFILES",
    "build_nmap_command",
    "parse_nmap_xml",
    "run_nmap",
    "validate_custom_arguments",
    "validate_targets",
)

logger = logging.getLogger("netbox_nmap_discovery.engine.nmap")


class NmapError(Exception):
    pass


# Built-in scan profiles. "{scan}" is replaced with -sS (privileged SYN scan) or -sT (unprivileged connect scan).
SCAN_PROFILES = {
    "discovery": {
        "label": "Discovery only (ping/ARP sweep)",
        "args": ["-sn", "-T3"],
        "ports": False,
        "os_detection": False,
    },
    "conservative": {
        "label": "Conservative (top 100 TCP ports, OS detection, -T3)",
        "args": ["{scan}", "--top-ports", "100", "-T3", "--max-retries", "2", "--host-timeout", "5m"],
        "ports": True,
        "os_detection": True,
    },
    "thorough": {
        "label": "Thorough (top 1000 TCP ports, service versions, OS detection, -T4)",
        "args": ["{scan}", "--top-ports", "1000", "-sV", "--version-light", "-T4", "--host-timeout", "15m"],
        "ports": True,
        "os_detection": True,
    },
}

# Options a user may pass in a "custom" profile. Value is True when the option takes a separate argument.
_ALLOWED_OPTIONS = {
    "-sS": False, "-sT": False, "-sU": False, "-sn": False, "-sV": False, "-O": False, "-Pn": False,
    "-PE": False, "-PP": False, "-PM": False, "-PR": False, "-n": False, "-R": False, "-F": False,
    "-6": False, "-r": False,
    "--osscan-limit": False, "--osscan-guess": False, "--version-light": False, "--version-all": False,
    "--open": False, "--disable-arp-ping": False, "--traceroute": False, "--reason": False,
    "-p": True, "--top-ports": True, "--max-retries": True, "--host-timeout": True, "--min-rate": True,
    "--max-rate": True, "--min-parallelism": True, "--max-parallelism": True, "--min-hostgroup": True,
    "--max-hostgroup": True, "--scan-delay": True, "--max-scan-delay": True, "--version-intensity": True,
    "--dns-servers": True, "--initial-rtt-timeout": True, "--max-rtt-timeout": True, "--min-rtt-timeout": True,
    "-e": True, "--ttl": True, "--source-port": True, "-g": True,
}
# Options with an attached value, e.g. -T4, -PS22,80, -p22
_ATTACHED_VALUE_OPTIONS = re.compile(r"^(-T[0-5]|-P[SAUY][\d,\-]*|-p[\w,:\-]+)$")
_SAFE_VALUE = re.compile(r"^[\w.,:/\-]+$")

_TARGET = re.compile(
    r"^(?:"
    r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?"  # IPv4 / CIDR
    r"|\d{1,3}(?:\.\d{1,3}){2}\.\d{1,3}-\d{1,3}"  # last-octet range
    r"|[0-9a-fA-F:]+:[0-9a-fA-F:]*(?:/\d{1,3})?"  # IPv6 / CIDR
    r"|(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*"
    r")$"
)


def validate_targets(lines) -> list[str]:
    """Validate scan target / exclusion lines; return the cleaned list or raise ValueError."""
    cleaned = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-") or not _TARGET.match(line):
            raise ValueError(f"Invalid target {line!r}: use an IP address, CIDR prefix, a.b.c.x-y range or hostname")
        if "/" in line:
            try:
                network = ipaddress.ip_network(line, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid prefix {line!r}: {exc}") from exc
            if network.version == 4 and network.prefixlen < 16:
                raise ValueError(f"Prefix {line!r} is too large to scan (minimum /16)")
            if network.version == 6 and network.prefixlen < 112:
                raise ValueError(f"IPv6 prefix {line!r} is too large to scan (minimum /112)")
        cleaned.append(line)
    return cleaned


def validate_custom_arguments(text: str) -> list[str]:
    """Parse and validate custom nmap arguments against the allow-list; return the argument list."""
    try:
        tokens = shlex.split(text or "")
    except ValueError as exc:
        raise ValueError(f"Unable to parse arguments: {exc}") from exc
    result = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if _ATTACHED_VALUE_OPTIONS.match(token):
            result.append(token)
            i += 1
            continue
        option, _, inline_value = token.partition("=")
        if option not in _ALLOWED_OPTIONS:
            raise ValueError(f"nmap option {token!r} is not permitted")
        takes_value = _ALLOWED_OPTIONS[option]
        if takes_value:
            if inline_value:
                value = inline_value
            else:
                i += 1
                if i >= len(tokens):
                    raise ValueError(f"nmap option {option} requires a value")
                value = tokens[i]
            if not _SAFE_VALUE.match(value):
                raise ValueError(f"Invalid value {value!r} for nmap option {option}")
            result.extend([option, value])
        else:
            if inline_value:
                raise ValueError(f"nmap option {option} does not take a value")
            result.append(option)
        i += 1
    return result


def nmap_is_privileged(setting=None) -> bool:
    """Decide whether nmap can use raw sockets (SYN scan, OS detection)."""
    if setting is not None:
        return bool(setting)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    return os.environ.get("NMAP_PRIVILEGED", "").lower() in ("1", "true", "yes")


def build_nmap_command(targets, exclusions=(), profile="conservative", custom_args="", privileged=False,
                       nmap_path="nmap", resolve_dns=True) -> list[str]:
    """Build the nmap argument list for a scan."""
    targets = validate_targets(targets)
    exclusions = validate_targets(exclusions)
    if not targets:
        raise ValueError("No scan targets defined")

    if profile == "custom":
        args = validate_custom_arguments(custom_args)
    else:
        spec = SCAN_PROFILES.get(profile)
        if spec is None:
            raise ValueError(f"Unknown scan profile {profile!r}")
        args = [("-sS" if privileged else "-sT") if a == "{scan}" else a for a in spec["args"]]
        if spec["os_detection"] and privileged:
            args += ["-O", "--osscan-limit"]

    if not privileged:
        # Raw-socket features would make nmap abort; degrade gracefully instead.
        args = ["-sT" if a == "-sS" else a for a in args if a not in ("-O", "--osscan-limit", "--osscan-guess")]
        if "-sU" in args:
            raise ValueError("UDP scans (-sU) require nmap raw-socket privileges")

    command = [nmap_path, *args]
    if privileged and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        command.append("--privileged")
    if not resolve_dns:
        command.append("-n")
    if exclusions:
        command += ["--exclude", ",".join(exclusions)]
    command += ["-oX", "-", "--noninteractive"]
    command += targets
    return command


def run_nmap(command: list[str], timeout: int = 3600) -> str:
    """Execute nmap and return its XML output."""
    logger.debug("Running %s", " ".join(shlex.quote(c) for c in command))
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise NmapError(f"nmap executable not found ({command[0]}). Install nmap on the NetBox worker host.") from exc
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"nmap did not finish within {timeout} seconds") from exc
    if proc.returncode != 0 or "<nmaprun" not in proc.stdout:
        stderr = (proc.stderr or "").strip()
        if "requires root privileges" in stderr or "Operation not permitted" in stderr:
            stderr += (" -- grant nmap raw-socket capabilities (setcap cap_net_raw,cap_net_admin+eip) or set "
                       "nmap_privileged=False in the plugin configuration")
        raise NmapError(f"nmap exited with code {proc.returncode}: {stderr[:2000]}")
    return proc.stdout


def parse_nmap_xml(xml_text: str, ports_scanned: bool = True) -> list[NmapHost]:
    """Parse nmap ``-oX`` output into ``NmapHost`` objects for every host that is up."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise NmapError(f"Unable to parse nmap XML output: {exc}") from exc

    scan_ports = ports_scanned and root.find("scaninfo") is not None
    hosts = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = None
        mac = vendor = None
        for addr_el in host_el.findall("address"):
            addrtype = addr_el.get("addrtype")
            if addrtype in ("ipv4", "ipv6") and address is None:
                address = addr_el.get("addr")
            elif addrtype == "mac":
                mac = normalize_mac(addr_el.get("addr"))
                vendor = addr_el.get("vendor") or None
        if not address:
            continue

        hostnames = []
        for hn in host_el.findall("hostnames/hostname"):
            name = hn.get("name")
            if name and name not in hostnames:
                # Prefer PTR records over user-supplied names
                if hn.get("type") == "PTR":
                    hostnames.insert(0, name)
                else:
                    hostnames.append(name)

        ports = []
        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port_el.find("service")
            ports.append(OpenPort(
                port=int(port_el.get("portid")),
                protocol=port_el.get("protocol", "tcp"),
                service=(service.get("name") if service is not None else "") or "",
                product=(service.get("product") if service is not None else "") or "",
                version=(service.get("version") if service is not None else "") or "",
            ))

        os_guess = os_vendor = os_family = None
        os_accuracy = None
        best = None
        for match in host_el.findall("os/osmatch"):
            accuracy = int(match.get("accuracy", "0"))
            if best is None or accuracy > int(best.get("accuracy", "0")):
                best = match
        if best is not None:
            os_guess = best.get("name")
            os_accuracy = int(best.get("accuracy", "0"))
            osclass = best.find("osclass")
            if osclass is not None:
                os_vendor = osclass.get("vendor")
                os_family = osclass.get("osfamily")

        hosts.append(NmapHost(
            address=address,
            hostnames=hostnames,
            mac_address=mac,
            mac_vendor=vendor,
            os_guess=os_guess,
            os_accuracy=os_accuracy,
            os_vendor=os_vendor,
            os_family=os_family,
            ports=sorted(ports, key=lambda p: (p.protocol, p.port)),
            ports_scanned=scan_ports,
        ))
    return hosts
