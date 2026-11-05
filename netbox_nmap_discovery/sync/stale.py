"""
Stale-object detection.

Every object discovery maintains (IP addresses, interfaces, cables, devices) gets an ``ObjectSighting`` per scan
target. Sightings are updated in bulk, so routine scans add no change-log entries; a NetBox object is only modified
when it crosses the stale threshold (tagged ``discovery-stale``, optionally deprecated) or recovers.

An object only counts as *missed* when the scan could have seen it: IPs inside the target's networks, interfaces
and cables of devices that were successfully polled during this run, and devices matched by previous scans.
"""
from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import F
from ipam.choices import IPAddressStatusChoices

from ..engine.utils import address_in_networks, parse_target_networks
from ..models import DiscoveredHost, ObjectSighting
from .context import SyncContext
from .provision import TAG_STALE, get_tag

__all__ = ("process_sightings", "update_discovered_hosts")

TRACKED_MODELS = ("ipam.ipaddress", "dcim.interface", "dcim.cable", "dcim.device")


def _content_type(label):
    app_label, model = label.split(".")
    return ContentType.objects.get_by_natural_key(app_label, model)


def _mark_stale(obj, sighting, ctx: SyncContext):
    target = ctx.scan_target
    obj.snapshot()
    if obj._meta.label_lower == "ipam.ipaddress" and target.deprecate_stale_ips \
            and obj.status != IPAddressStatusChoices.STATUS_DEPRECATED:
        sighting.previous_status = obj.status
        obj.status = IPAddressStatusChoices.STATUS_DEPRECATED
        obj.save()
    obj.tags.add(get_tag(TAG_STALE))
    sighting.is_stale = True
    ctx.stats[f"stale_{obj._meta.model_name}"] += 1
    ctx.info(f"Marked {obj._meta.verbose_name} {obj} as stale (missed {sighting.miss_count} scans)")


def _unmark_stale(obj, sighting, ctx: SyncContext):
    obj.snapshot()
    if sighting.previous_status and getattr(obj, "status", None) == IPAddressStatusChoices.STATUS_DEPRECATED:
        obj.status = sighting.previous_status
        obj.save()
    obj.tags.remove(get_tag(TAG_STALE))
    sighting.previous_status = ""
    sighting.is_stale = False
    ctx.stats[f"recovered_{obj._meta.model_name}"] += 1
    ctx.info(f"{obj._meta.verbose_name.capitalize()} {obj} has been seen again; removed stale tag")


def _in_scope(label, obj, ctx: SyncContext, networks) -> bool:
    if label == "ipam.ipaddress":
        return address_in_networks(str(obj.address.ip), networks)
    if label == "dcim.interface":
        return obj.device_id in ctx.polled_devices
    if label == "dcim.cable":
        if not ctx.scan_target.collect_neighbors:
            return False
        devices = {getattr(t, "device_id", None) for t in list(obj.a_terminations) + list(obj.b_terminations)}
        return bool(devices) and devices <= ctx.polled_devices
    if label == "dcim.device":
        return True
    return False


def process_sightings(ctx: SyncContext):
    target = ctx.scan_target
    if target is None:
        return
    now = ctx.now

    # Record what was seen
    for label in TRACKED_MODELS:
        pks = ctx.seen.get(label) or set()
        if not pks:
            continue
        content_type = _content_type(label)
        existing = {s.object_id: s for s in ObjectSighting.objects.filter(
            scan_target=target, object_type=content_type, object_id__in=pks)}
        ObjectSighting.objects.bulk_create([
            ObjectSighting(object_type=content_type, object_id=pk, scan_target=target, first_seen=now, last_seen=now)
            for pk in pks if pk not in existing
        ], ignore_conflicts=True)
        ObjectSighting.objects.filter(pk__in=[s.pk for s in existing.values()]).update(last_seen=now, miss_count=0)
        recovered = [s for s in existing.values() if s.is_stale]
        if recovered:
            model = content_type.model_class()
            objects = model.objects.in_bulk([s.object_id for s in recovered])
            for sighting in recovered:
                obj = objects.get(sighting.object_id)
                if obj is not None:
                    with transaction.atomic():
                        _unmark_stale(obj, sighting, ctx)
                        sighting.save(update_fields=("is_stale", "previous_status"))

    if not ctx.full_scan:
        return

    # Count misses
    networks = parse_target_networks(target.target_list)
    for label in TRACKED_MODELS:
        content_type = _content_type(label)
        model = content_type.model_class()
        sightings = list(ObjectSighting.objects.filter(scan_target=target, object_type=content_type,
                                                       last_seen__lt=now))
        if not sightings:
            continue
        objects = model.objects.in_bulk([s.object_id for s in sightings])
        orphaned = [s.pk for s in sightings if s.object_id not in objects]
        if orphaned:
            ObjectSighting.objects.filter(pk__in=orphaned).delete()
        for sighting in sightings:
            obj = objects.get(sighting.object_id)
            if obj is None or not _in_scope(label, obj, ctx, networks):
                continue
            sighting.miss_count += 1
            if sighting.miss_count >= target.stale_threshold and not sighting.is_stale:
                with transaction.atomic():
                    _mark_stale(obj, sighting, ctx)
            sighting.save(update_fields=("miss_count", "is_stale", "previous_status"))


def update_discovered_hosts(records, ctx: SyncContext):
    """Upsert DiscoveredHost rows in bulk. ``records`` is an iterable of ``(HostResult, device, ip)``."""
    from ..models import CredentialProfile

    vrf = ctx.vrf
    now = ctx.now
    records = list(records)
    valid_credentials = set(CredentialProfile.objects.values_list("pk", flat=True))
    existing = {h.address: h for h in DiscoveredHost.objects.filter(
        vrf=vrf, address__in=[r[0].address for r in records])}
    to_create, to_update = [], []
    update_fields = ("scan_target", "source", "hostname", "dns_name", "mac_address", "mac_vendor", "os_guess",
                     "open_ports", "platform", "methods", "snmp_credential", "ssh_credential", "device", "ip_address",
                     "last_seen", "miss_count", "is_stale", "data", "last_updated")
    for host, device, ip in records:
        nmap = host.nmap
        os_guess = nmap.os_guess if nmap and nmap.os_guess else ""
        values = {
            "scan_target": ctx.scan_target,
            "source": host.source,
            "hostname": (host.hostname or "")[:255],
            "dns_name": (host.dns_name or "")[:255],
            "mac_address": host.mac_address or "",
            "mac_vendor": (host.mac_vendor or (nmap.mac_vendor if nmap else "") or "")[:100],
            "os_guess": os_guess[:200],
            "open_ports": [p.to_dict() for p in nmap.ports] if nmap else [],
            "platform": (host.facts.platform if host.facts else None) or "",
            "methods": host.methods,
            "snmp_credential_id": host.snmp_credential_id if host.snmp_credential_id in valid_credentials else None,
            "ssh_credential_id": host.ssh_credential_id if host.ssh_credential_id in valid_credentials else None,
            "device": device if device is not None and device.pk else None,
            "ip_address": ip if ip is not None and ip.pk else None,
            "last_seen": now,
            "miss_count": 0,
            "is_stale": False,
            "data": host.to_dict(),
            "last_updated": now,
        }
        record = existing.get(host.address)
        if record is None:
            record = DiscoveredHost(address=host.address, vrf=vrf, first_seen=now, **values)
            to_create.append(record)
        else:
            # Keep the previously learned device/IP/credential links when this run didn't establish them
            for keep in ("device", "ip_address", "snmp_credential_id", "ssh_credential_id"):
                if values[keep] is None:
                    values.pop(keep)
            if not values["mac_address"]:
                values.pop("mac_address")
            for key, value in values.items():
                setattr(record, key, value)
            to_update.append(record)
    DiscoveredHost.objects.bulk_create(to_create, batch_size=500)
    if to_update:
        DiscoveredHost.objects.bulk_update(to_update, update_fields, batch_size=500)

    if ctx.full_scan and ctx.scan_target is not None:
        networks = parse_target_networks(ctx.scan_target.target_list)
        missed = [h.pk for h in DiscoveredHost.objects.filter(scan_target=ctx.scan_target, last_seen__lt=now)
                  .only("pk", "address") if address_in_networks(h.address, networks)]
        if missed:
            DiscoveredHost.objects.filter(pk__in=missed).update(miss_count=F("miss_count") + 1)
            DiscoveredHost.objects.filter(pk__in=missed, miss_count__gte=ctx.scan_target.stale_threshold).update(
                is_stale=True)
