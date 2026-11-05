"""IPAM synchronisation for every address that answered a scan (including hosts that are not NetBox devices)."""
from __future__ import annotations

from dcim.models import Interface
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import transaction
from ipam.choices import IPAddressStatusChoices
from ipam.models import IPAddress

from ..choices import ProposalKindChoices
from ..engine.results import HostResult
from .context import Change, SyncContext
from .provision import CF_LAST_SEEN, CF_MAC, CF_MAC_VENDOR, CF_OS, CF_PORTS, TAG_DISCOVERED, get_tag
from .resolvers import ip_prefix_length

__all__ = ("address_metadata", "create_ip_address", "find_ip", "sync_address")


def find_ip(address: str, vrf=None, device=None):
    candidates = list(IPAddress.objects.filter(vrf=vrf, address__net_host=address))
    if not candidates:
        return None
    if device is not None and device.pk:
        interface_ct = ContentType.objects.get_for_model(Interface)
        interface_ids = set(device.interfaces.values_list("pk", flat=True))
        for candidate in candidates:
            if candidate.assigned_object_type_id == interface_ct.pk and candidate.assigned_object_id in interface_ids:
                return candidate
    return candidates[0]


def address_metadata(host: HostResult) -> dict:
    nmap = host.nmap
    os_guess = None
    if host.facts and (host.facts.platform or host.facts.os_version):
        from ..engine.platforms import PLATFORMS

        spec = PLATFORMS.get(host.facts.platform or "")
        os_guess = " ".join(p for p in (spec.name if spec else None, host.facts.os_version) if p)
    elif nmap and nmap.os_guess:
        os_guess = nmap.os_guess + (f" ({nmap.os_accuracy}%)" if nmap.os_accuracy else "")
    ports = ", ".join(p.label() for p in nmap.ports) if nmap and nmap.ports_scanned else None
    return {
        CF_MAC: host.mac_address or None,
        CF_MAC_VENDOR: host.mac_vendor or (nmap.mac_vendor if nmap else None) or None,
        CF_OS: os_guess,
        CF_PORTS: ports,
    }


def _metadata_changes(ip, host: HostResult, ctx: SyncContext) -> dict:
    """Return the custom field values that differ (discovery_last_seen is rate-limited)."""
    from .devices import _parse_dt

    current = ip.custom_field_data or {}
    updates = {}
    for key, value in address_metadata(host).items():
        if value is None:
            # Keep previously learned values (e.g. MAC learned via ARP) when this scan didn't see them
            continue
        if current.get(key) != value:
            updates[key] = value
    hours = int(ctx.settings.get("last_seen_update_hours", 24))
    last_seen = current.get(CF_LAST_SEEN)
    if updates or not last_seen or (ctx.now - _parse_dt(last_seen)).total_seconds() >= hours * 3600:
        updates[CF_LAST_SEEN] = ctx.now_text
    return updates


def create_ip_address(address: str, prefix_length: int, host_data: dict | None, ctx: SyncContext, dns_name=""):
    metadata = {k: v for k, v in (host_data or {}).items() if v is not None}
    metadata[CF_LAST_SEEN] = ctx.now_text
    ip = IPAddress(
        address=f"{address}/{prefix_length}",
        vrf=ctx.vrf,
        tenant=ctx.tenant,
        status=IPAddressStatusChoices.STATUS_ACTIVE,
        dns_name=(dns_name or "")[:255],
        custom_field_data=metadata,
    )
    ip.full_clean()
    ip.save()
    ip.tags.add(get_tag(TAG_DISCOVERED))
    return ip


def sync_address(host: HostResult, ctx: SyncContext, device=None, proposals=None):
    """
    Make sure the scanned address is recorded in IPAM with the latest discovery metadata. Returns the IPAddress
    (or None when its creation is waiting for review).
    """
    ip = find_ip(host.address, ctx.vrf, device)
    if ip is None:
        interface = host.interface_for_address(host.address)
        known = next((c for c in (interface.ip_addresses if interface else []) if c.split("/")[0] == host.address),
                     None)
        prefix_length = int(known.split("/")[1]) if known and "/" in known else ip_prefix_length(host.address,
                                                                                                 ctx.vrf)
        cidr = f"{host.address}/{prefix_length}"
        metadata = address_metadata(host)
        if ctx.mode == "review":
            if proposals is not None:
                proposals.upsert(
                    kind=ProposalKindChoices.CREATE_IP,
                    fingerprint=f"create-ip:{ctx.vrf.pk if ctx.vrf else 0}:{host.address}",
                    summary=f"New IP address {cidr}" + (f" ({host.dns_name})" if host.dns_name else ""),
                    data={"address": host.address, "prefix_length": prefix_length, "dns_name": host.dns_name or "",
                          "metadata": metadata},
                    diff=[Change("ip", "create", cidr, {"dns_name": host.dns_name, **metadata}).to_dict()],
                )
            return None
        try:
            with transaction.atomic():
                ip = create_ip_address(host.address, prefix_length, metadata, ctx, dns_name=host.dns_name or "")
            ctx.stats["ips_created"] += 1
        except ValidationError as exc:
            ctx.warning(f"{host.address}: unable to create IP address: {'; '.join(exc.messages)}")
            return None
    else:
        updates = _metadata_changes(ip, host, ctx)
        dns_update = None
        if host.dns_name and not ip.dns_name:
            dns_update = host.dns_name[:255]
        if dns_update and ctx.mode == "review":
            if proposals is not None:
                proposals.upsert(
                    kind=ProposalKindChoices.UPDATE_IP,
                    fingerprint=f"update-ip:{ip.pk}",
                    summary=f"Set DNS name of {ip.address} to {dns_update}",
                    data={"ip_id": ip.pk, "dns_name": dns_update},
                    diff=[Change("ip", "update", str(ip.address), {"dns_name": [ip.dns_name, dns_update]}).to_dict()],
                    obj=ip,
                )
            dns_update = None
        if updates or dns_update:
            ip.snapshot()
            ip.custom_field_data = {**(ip.custom_field_data or {}), **updates}
            if dns_update:
                ip.dns_name = dns_update
            try:
                with transaction.atomic():
                    ip.full_clean()
                    ip.save()
                ctx.stats["ips_updated"] += 1
            except ValidationError as exc:
                ctx.warning(f"{host.address}: unable to update IP address {ip}: {'; '.join(exc.messages)}")
    if ip is not None:
        ctx.mark_seen(ip)
    return ip
