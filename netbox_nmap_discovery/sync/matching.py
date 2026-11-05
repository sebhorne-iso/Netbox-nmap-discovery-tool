"""Match discovered hosts and LLDP/CDP neighbours to existing NetBox devices and interfaces."""
from __future__ import annotations

from dcim.models import Device, Interface, MACAddress
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from ipam.models import IPAddress

from ..engine.results import HostResult, Neighbor
from ..engine.utils import canonical_interface_name, is_usable_mac, normalize_mac, short_hostname

__all__ = ("find_interface", "match_device", "match_neighbor_device")


def _prefer_site(devices, site):
    if len(devices) == 1:
        return devices[0]
    if site is not None:
        in_site = [d for d in devices if d.site_id == site.pk]
        if len(in_site) == 1:
            return in_site[0]
    return None


def devices_by_name(name: str | None):
    short = short_hostname(name)
    if not short:
        return []
    query = Q(name__iexact=short) | Q(name__istartswith=f"{short}.")
    if name and "." in name and name.lower() != short:
        query |= Q(name__iexact=name.rstrip("."))
    return list(Device.objects.filter(query)[:10])


def devices_by_macs(macs) -> list:
    macs = sorted({m for m in (normalize_mac(m) for m in macs) if is_usable_mac(m)})
    if not macs:
        return []
    interface_type = ContentType.objects.get_for_model(Interface)
    interface_ids = MACAddress.objects.filter(
        mac_address__in=macs, assigned_object_type=interface_type,
    ).values_list("assigned_object_id", flat=True)
    device_ids = set(Interface.objects.filter(pk__in=list(interface_ids)).values_list("device_id", flat=True))
    return list(Device.objects.filter(pk__in=device_ids)[:10])


def devices_by_ip(address: str, vrf=None) -> list:
    if not address:
        return []
    ips = IPAddress.objects.filter(address__net_host=address, vrf=vrf)
    device_ids = set()
    interface_type = ContentType.objects.get_for_model(Interface)
    for ip in ips:
        if ip.assigned_object_type_id == interface_type.pk:
            device_id = Interface.objects.filter(pk=ip.assigned_object_id).values_list("device_id", flat=True).first()
            if device_id:
                device_ids.add(device_id)
    device_ids |= set(Device.objects.filter(
        Q(primary_ip4__in=ips) | Q(primary_ip6__in=ips) | Q(oob_ip__in=ips)
    ).values_list("pk", flat=True))
    return list(Device.objects.filter(pk__in=device_ids)[:10])


def match_device(host: HostResult, vrf=None, site=None):
    """
    Return ``(device, reason)`` for an existing device matching ``host``, trying serial number, interface MACs,
    hostname and finally IP address. ``(None, reason)`` is returned when nothing (or more than one device) matches.
    """
    facts = host.facts
    ambiguous = []

    if facts and facts.serial:
        devices = list(Device.objects.filter(serial__iexact=facts.serial.strip())[:10])
        device = _prefer_site(devices, site)
        if device:
            return device, f"serial {facts.serial}"
        if devices:
            ambiguous.append(f"serial {facts.serial} matches {len(devices)} devices")

    macs = {i.mac_address for i in host.interfaces if i.mac_address}
    if host.managed and host.mac_address:
        macs.add(host.mac_address)
    devices = devices_by_macs(macs)
    device = _prefer_site(devices, site)
    if device:
        return device, "interface MAC address"
    if devices:
        ambiguous.append(f"MAC addresses match {len(devices)} devices")

    for name in (facts.fqdn if facts else None, facts.hostname if facts else None, host.dns_name):
        devices = devices_by_name(name)
        device = _prefer_site(devices, site)
        if device:
            return device, f"name {device.name}"
        if devices:
            ambiguous.append(f"name {name} matches {len(devices)} devices")

    devices = devices_by_ip(host.address, vrf)
    device = _prefer_site(devices, site)
    if device:
        return device, f"IP address {host.address}"
    if devices:
        ambiguous.append(f"IP {host.address} matches {len(devices)} devices")

    return None, "; ".join(ambiguous) if ambiguous else "no match"


def match_neighbor_device(neighbor: Neighbor, vrf=None, cache=None):
    """Find the NetBox device an LLDP/CDP neighbour refers to (by name, chassis MAC, then management IP)."""
    cache = cache if cache is not None else {}
    key = (neighbor.remote_name, neighbor.remote_chassis_id, neighbor.remote_mgmt_address)
    if key in cache:
        return cache[key]
    device = None
    if neighbor.remote_name:
        devices = devices_by_name(neighbor.remote_name)
        if len(devices) == 1:
            device = devices[0]
    if device is None and neighbor.remote_chassis_id and normalize_mac(neighbor.remote_chassis_id):
        devices = devices_by_macs([neighbor.remote_chassis_id])
        if len(devices) == 1:
            device = devices[0]
    if device is None and neighbor.remote_mgmt_address:
        devices = devices_by_ip(neighbor.remote_mgmt_address, vrf)
        if len(devices) == 1:
            device = devices[0]
    cache[key] = device
    return device


def find_interface(device, *names, mac=None):
    """Find an interface on ``device`` by any of ``names`` (abbreviation-insensitive) or by MAC address."""
    interfaces = list(device.interfaces.all()) if hasattr(device, "interfaces") else []
    by_canonical = {canonical_interface_name(i.name): i for i in interfaces}
    for name in names:
        if not name:
            continue
        interface = by_canonical.get(canonical_interface_name(name))
        if interface:
            return interface
    mac = normalize_mac(mac) if mac else None
    for name in names:
        candidate = normalize_mac(name) if name else None
        if candidate:
            mac = mac or candidate
    if mac:
        interface_type = ContentType.objects.get_for_model(Interface)
        ids = set(MACAddress.objects.filter(
            mac_address=mac, assigned_object_type=interface_type,
            assigned_object_id__in=[i.pk for i in interfaces],
        ).values_list("assigned_object_id", flat=True))
        if len(ids) == 1:
            return next(i for i in interfaces if i.pk in ids)
    return None
