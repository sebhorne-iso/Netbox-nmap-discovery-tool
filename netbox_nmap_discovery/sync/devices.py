"""
Reconcile a polled device (SNMP/SSH data) with NetBox.

``reconcile_device()`` walks the discovered data once and produces a list of ``Change`` objects. With
``apply=False`` nothing is written (used for review-queue diffs); with ``apply=True`` each change is executed in its
own savepoint as it is planned, so a single invalid object never aborts the rest of the synchronisation.
"""
from __future__ import annotations

import ipaddress

from dcim.models import Device, Interface, MACAddress
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from ipam.choices import IPAddressStatusChoices
from ipam.models import IPAddress

from ..engine.interfaces import is_management_interface
from ..engine.results import HostResult
from ..engine.utils import canonical_interface_name, is_usable_mac, short_hostname
from .context import Change, SyncContext
from .provision import CF_LAST_SEEN, CF_OS, TAG_DISCOVERED, ensure_custom_fields_and_tags, get_tag
from .resolvers import (
    describe_device_type,
    find_platform,
    get_or_create_device_type,
    get_or_create_platform,
    resolve_role,
    resolve_site_and_location,
)

__all__ = ("ApplyError", "create_device", "describe_new_device", "reconcile_device", "touch_device")

NO_CABLE_TYPES = {"virtual", "lag", "bridge"}
NO_MAC_TYPES = {"virtual", "bridge"}


class ApplyError(Exception):
    pass


def _error_text(exc) -> str:
    if isinstance(exc, ValidationError):
        if hasattr(exc, "message_dict"):
            return "; ".join(f"{k}: {' '.join(v)}" for k, v in exc.message_dict.items())
        return "; ".join(exc.messages)
    return str(exc)


def _save(obj):
    obj.full_clean()
    obj.save()
    return obj


def _host_part(cidr: str) -> str:
    return cidr.split("/")[0]


def _cidr_version(cidr: str) -> int:
    return ipaddress.ip_interface(cidr).version


def touch_device(device, host: HostResult, ctx: SyncContext):
    """Update discovery metadata custom fields on a device (rate-limited to avoid change-log noise)."""
    ensure_custom_fields_and_tags()
    data = dict(device.custom_field_data or {})
    changed = False
    hours = int(ctx.settings.get("last_seen_update_hours", 24))
    last_seen = data.get(CF_LAST_SEEN)
    if not last_seen or (ctx.now - _parse_dt(last_seen)).total_seconds() >= hours * 3600:
        data[CF_LAST_SEEN] = ctx.now_text
        changed = True
    os_text = None
    if host.facts:
        parts = [p for p in (host.facts.platform and _platform_name(host.facts.platform), host.facts.os_version) if p]
        os_text = " ".join(parts) or None
    if os_text and data.get(CF_OS) != os_text:
        data[CF_OS] = os_text
        changed = True
    if changed:
        device.snapshot()
        device.custom_field_data = data
        device.save()


def _platform_name(key):
    from ..engine.platforms import PLATFORMS

    spec = PLATFORMS.get(key)
    return spec.name if spec else key


def _parse_dt(value):
    from datetime import datetime

    from django.utils import timezone

    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.get_current_timezone())
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed)
    return parsed


class _Executor:
    def __init__(self, ctx: SyncContext, apply: bool, include_sensitive: bool):
        self.ctx = ctx
        self.apply = apply
        self.include_sensitive = include_sensitive
        self.changes: list[Change] = []

    def __call__(self, change: Change, fn=None):
        self.changes.append(change)
        if not self.apply or fn is None or (change.sensitive and not self.include_sensitive):
            return None
        try:
            with transaction.atomic():
                result = fn()
            change.applied = True
            return result
        except (ValidationError, DatabaseError, ValueError) as exc:
            change.error = _error_text(exc)[:500]
            self.ctx.warning(f"{change.describe()}")
            return None


def reconcile_device(device, host: HostResult, ctx: SyncContext, apply: bool = False,
                     include_sensitive: bool = False) -> list[Change]:
    """Plan (and optionally apply) all changes needed to bring ``device`` in line with ``host``."""
    do = _Executor(ctx, apply, include_sensitive)
    facts = host.facts
    tag = get_tag(TAG_DISCOVERED) if apply else None
    overwrite_descriptions = bool(ctx.settings.get("overwrite_interface_descriptions", True))

    # --- Device attributes (existing devices only; new devices get them at creation) ---------------------
    is_existing = device.pk is not None
    if is_existing and facts and facts.serial and (device.serial or "").strip().lower() != facts.serial.strip().lower():
        def set_serial(serial=facts.serial[:50]):
            device.snapshot()
            device.serial = serial
            _save(device)
        do(Change("device", "update", device.name or str(device.pk), {"serial": [device.serial, facts.serial]},
                  sensitive=bool(device.serial),
                  note="serial number changed - hardware replaced?" if device.serial else ""), set_serial)

    if is_existing and facts and facts.platform and device.platform_id is None:
        platform = find_platform(facts.platform)

        def set_platform(key=facts.platform):
            platform_obj, _ = get_or_create_platform(key)
            device.snapshot()
            device.platform = platform_obj
            _save(device)
        do(Change("device", "update", device.name or str(device.pk),
                  {"platform": [None, str(platform) if platform else f"{_platform_name(facts.platform)} (new)"]}),
           set_platform)

    if (is_existing and facts and facts.model and device.device_type.model == "Unknown"
            and device.device_type.tags.filter(slug="discovery-autocreated").exists()):
        def set_device_type():
            device_type, _ = get_or_create_device_type(host, ctx.settings)
            device.snapshot()
            device.device_type = device_type
            _save(device)
        do(Change("device", "update", device.name or str(device.pk),
                  {"device_type": [str(device.device_type), describe_device_type(host)]}, sensitive=True),
           set_device_type)

    # --- Interfaces ---------------------------------------------------------------------------------------
    existing = {canonical_interface_name(i.name): i for i in device.interfaces.all()} if device.pk else {}
    interface_map: dict[str, Interface | None] = {}  # canonical name -> interface (None = planned, not created)
    for discovered in host.interfaces:
        key = canonical_interface_name(discovered.name)
        interface = existing.get(key)
        if interface is None:
            values = {
                "name": discovered.name[:64],
                "type": discovered.type or "other",
                "enabled": True if discovered.enabled is None else discovered.enabled,
                "mtu": discovered.mtu,
                "speed": discovered.speed_kbps if discovered.oper_up else None,
                "description": (discovered.description or "")[:200],
                "mgmt_only": is_management_interface(discovered.name),
            }

            def create_interface(values=values):
                obj = _save(Interface(device=device, **values))
                obj.tags.add(tag)
                return obj
            interface = do(Change("interface", "create", discovered.name,
                                  {k: v for k, v in values.items() if k != "name"}), create_interface)
            if interface is not None:
                existing[key] = interface
        else:
            updates = {}
            if discovered.enabled is not None and interface.enabled != discovered.enabled:
                updates["enabled"] = [interface.enabled, discovered.enabled]
            if discovered.mtu and interface.mtu != discovered.mtu:
                updates["mtu"] = [interface.mtu, discovered.mtu]
            if discovered.oper_up and discovered.speed_kbps and interface.speed != discovered.speed_kbps:
                updates["speed"] = [interface.speed, discovered.speed_kbps]
            description = (discovered.description or "")[:200]
            if overwrite_descriptions and description and interface.description != description:
                updates["description"] = [interface.description, description]
            if interface.type == "other" and discovered.type and discovered.type != "other":
                updates["type"] = [interface.type, discovered.type]
            if updates:
                def update_interface(interface=interface, updates=updates):
                    interface.snapshot()
                    for field_name, (_old, new) in updates.items():
                        setattr(interface, field_name, new)
                    _save(interface)
                do(Change("interface", "update", interface.name, updates), update_interface)
            ctx.mark_seen(interface)
        if interface is not None:
            ctx.mark_seen(interface)
        interface_map[key] = interface

    # LAG membership (second pass so parents exist)
    for discovered in host.interfaces:
        if not discovered.lag:
            continue
        member = interface_map.get(canonical_interface_name(discovered.name))
        parent = interface_map.get(canonical_interface_name(discovered.lag))
        if member is None or parent is None or member.pk == parent.pk:
            if not apply:
                do(Change("interface", "update", discovered.name, {"lag": [None, discovered.lag]}))
            continue
        if parent.type != "lag" or member.lag_id == parent.pk or member.type in NO_CABLE_TYPES:
            continue

        def set_lag(member=member, parent=parent):
            member.snapshot()
            member.lag = parent
            _save(member)
        do(Change("interface", "update", member.name, {"lag": [str(member.lag) if member.lag else None,
                                                               parent.name]}), set_lag)

    # --- MAC addresses ------------------------------------------------------------------------------------
    interface_ct = ContentType.objects.get_for_model(Interface)
    for discovered in host.interfaces:
        mac = discovered.mac_address
        if not mac or not is_usable_mac(mac) or (discovered.type or "") in NO_MAC_TYPES:
            continue
        interface = interface_map.get(canonical_interface_name(discovered.name))
        if interface is None:
            if not apply:
                do(Change("mac", "assign", mac, {"interface": discovered.name}))
            continue
        mac_obj = MACAddress.objects.filter(assigned_object_type=interface_ct, assigned_object_id=interface.pk,
                                            mac_address=mac).first()
        if mac_obj is None:
            def create_mac(interface=interface, mac=mac):
                obj = _save(MACAddress(mac_address=mac, assigned_object=interface))
                obj.tags.add(tag)
                if interface.primary_mac_address_id is None:
                    interface.snapshot()
                    interface.primary_mac_address = obj
                    _save(interface)
                return obj
            mac_obj = do(Change("mac", "assign", mac, {"interface": interface.name}), create_mac)
        elif interface.primary_mac_address_id is None:
            def set_primary_mac(interface=interface, mac_obj=mac_obj):
                interface.snapshot()
                interface.primary_mac_address = mac_obj
                _save(interface)
            do(Change("interface", "update", interface.name, {"primary_mac_address": [None, mac]}), set_primary_mac)
        ctx.mark_seen(mac_obj)

    # --- IP addresses -------------------------------------------------------------------------------------
    vrf = ctx.vrf
    for discovered in host.interfaces:
        interface = interface_map.get(canonical_interface_name(discovered.name))
        for cidr in discovered.ip_addresses:
            try:
                ip_interface = ipaddress.ip_interface(cidr)
            except ValueError:
                continue
            if ip_interface.ip.is_loopback or ip_interface.ip.is_link_local:
                continue
            host_ip = str(ip_interface.ip)
            candidates = list(IPAddress.objects.filter(vrf=vrf, address__net_host=host_ip))
            ip_obj = None
            if interface is not None:
                ip_obj = next((c for c in candidates if c.assigned_object_type_id == interface_ct.pk
                               and c.assigned_object_id == interface.pk), None)
            ip_obj = ip_obj or next((c for c in candidates if c.assigned_object_id is None), None) or (
                candidates[0] if candidates else None)
            if_name = interface.name if interface is not None else discovered.name

            if ip_obj is None:
                dns_name = host.dns_name if host_ip == host.address and host.dns_name else ""

                def create_ip(cidr=str(ip_interface), interface=interface, dns_name=dns_name, name=discovered.name):
                    if interface is None:
                        raise ValidationError(f"interface {name} does not exist")
                    obj = _save(IPAddress(address=cidr, vrf=vrf, tenant=ctx.tenant,
                                          status=IPAddressStatusChoices.STATUS_ACTIVE,
                                          assigned_object=interface, dns_name=(dns_name or "")[:255]))
                    obj.tags.add(tag)
                    return obj
                ip_obj = do(Change("ip", "create", str(ip_interface), {"interface": if_name}), create_ip)
            else:
                assigned_here = (interface is not None and ip_obj.assigned_object_type_id == interface_ct.pk
                                 and ip_obj.assigned_object_id == interface.pk)
                mask_differs = ip_obj.address.prefixlen != ip_interface.network.prefixlen
                if assigned_here:
                    if mask_differs:
                        def update_mask(ip_obj=ip_obj, cidr=str(ip_interface)):
                            ip_obj.snapshot()
                            ip_obj.address = cidr
                            _save(ip_obj)
                        do(Change("ip", "update", host_ip, {"address": [str(ip_obj.address), str(ip_interface)]}),
                           update_mask)
                else:
                    owner = ip_obj.assigned_object
                    owner_device = getattr(owner, "device", None) if owner is not None else None
                    same_device = owner_device is not None and device.pk and owner_device.pk == device.pk
                    sensitive = owner is not None and not same_device
                    note = ""
                    if sensitive:
                        note = f"currently assigned to {owner_device or ''} {owner}".strip()

                    def assign_ip(ip_obj=ip_obj, interface=interface, cidr=str(ip_interface), name=discovered.name):
                        if interface is None:
                            raise ValidationError(f"interface {name} does not exist")
                        ip_obj.snapshot()
                        ip_obj.assigned_object = interface
                        ip_obj.address = cidr
                        _save(ip_obj)
                        if not ip_obj.tags.filter(slug=TAG_DISCOVERED).exists():
                            ip_obj.tags.add(tag)
                    do(Change("ip", "assign", host_ip, {"interface": if_name}, sensitive=sensitive, note=note),
                       assign_ip)
            if ip_obj is not None and getattr(ip_obj, "pk", None):
                ctx.mark_seen(ip_obj)

    # --- Primary IP ---------------------------------------------------------------------------------------
    try:
        version = ipaddress.ip_address(host.address).version
    except ValueError:
        version = None
    if version and host.interface_for_address(host.address) is not None:
        field_name = f"primary_ip{version}"
        if getattr(device, f"{field_name}_id", None) is None:
            def set_primary():
                ip_obj = IPAddress.objects.filter(
                    vrf=vrf, address__net_host=host.address, assigned_object_type=interface_ct,
                    assigned_object_id__in=list(device.interfaces.values_list("pk", flat=True)),
                ).first()
                if ip_obj is None:
                    raise ValidationError(f"{host.address} is not assigned to an interface of this device")
                device.snapshot()
                setattr(device, field_name, ip_obj)
                _save(device)
            do(Change("device", "update", device.name or "new device", {field_name: [None, host.address]}),
               set_primary)

    if apply and device.pk:
        ctx.mark_seen(device)
        ctx.polled_devices.add(device.pk)
        touch_device(device, host, ctx)
    return do.changes


def _device_name(host: HostResult) -> str:
    facts = host.facts
    for candidate in (facts.hostname if facts else None, short_hostname(host.dns_name)):
        if candidate:
            return candidate[:64]
    return host.address


def resolve_new_device(host: HostResult, ctx: SyncContext, overrides: dict | None = None) -> dict:
    """Resolve the attributes a new device would get (without writing anything)."""
    from dcim.models import DeviceRole, DeviceType, Location, Platform, Site
    from tenancy.models import Tenant

    overrides = overrides or {}
    site, location = resolve_site_and_location(host.address, ctx.scan_target)
    role, rule = resolve_role(host, ctx.scan_target)
    def pick(model, key, default=None):
        return model.objects.filter(pk=overrides[key]).first() if overrides.get(key) else default

    resolved = {
        "name": overrides.get("name") or _device_name(host),
        "site": pick(Site, "site", site),
        "location": pick(Location, "location", location),
        "role": pick(DeviceRole, "role", role),
        "role_rule": rule,
        "device_type": pick(DeviceType, "device_type"),
        "platform": pick(Platform, "platform"),
        "tenant": pick(Tenant, "tenant", ctx.tenant),
        "status": overrides.get("status") or getattr(ctx.scan_target, "device_status", "active"),
    }
    if resolved["location"] is not None and resolved["site"] is not None and \
            resolved["location"].site_id != resolved["site"].pk:
        resolved["location"] = None
    return resolved


def describe_new_device(host: HostResult, ctx: SyncContext, overrides: dict | None = None):
    """Return ``(summary, changes, problems)`` describing the creation of a new device for review."""
    resolved = resolve_new_device(host, ctx, overrides)
    facts = host.facts
    device_type = str(resolved["device_type"]) if resolved["device_type"] else describe_device_type(
        host, ctx.settings.get("manufacturer_aliases"))
    platform = resolved["platform"] or (find_platform(facts.platform) if facts and facts.platform else None)
    platform_text = str(platform) if platform else (f"{_platform_name(facts.platform)} (will be created)"
                                                     if facts and facts.platform else None)
    values = {
        "site": str(resolved["site"]) if resolved["site"] else None,
        "location": str(resolved["location"]) if resolved["location"] else None,
        "role": str(resolved["role"]) if resolved["role"] else None,
        "device_type": device_type,
        "platform": platform_text,
        "serial": facts.serial if facts else None,
        "tenant": str(resolved["tenant"]) if resolved["tenant"] else None,
        "status": resolved["status"],
    }
    if resolved["role_rule"]:
        values["role"] += f" (rule: {resolved['role_rule']})"
    changes = [Change("device", "create", resolved["name"], values)]
    preview = Device(name=resolved["name"])
    changes += reconcile_device(preview, host, ctx, apply=False)
    problems = []
    if resolved["site"] is None:
        problems.append("No site could be determined: set one before approving")
    if resolved["role"] is None:
        problems.append("No device role could be determined: set one before approving")
    summary = f"New device {resolved['name']} ({device_type}) at {host.address}"
    return summary[:300], changes, problems


def create_device(host: HostResult, ctx: SyncContext, overrides: dict | None = None):
    """Create a device (and its interfaces, MACs and IPs) from discovered data."""
    resolved = resolve_new_device(host, ctx, overrides)
    if resolved["site"] is None:
        raise ApplyError("No site could be determined for this device; choose a site and approve again.")
    if resolved["role"] is None:
        raise ApplyError("No device role could be determined for this device; choose a role and approve again.")
    facts = host.facts
    device_type = resolved["device_type"]
    if device_type is None:
        device_type, _ = get_or_create_device_type(host, ctx.settings)
    platform = resolved["platform"]
    if platform is None and facts and facts.platform:
        platform, _ = get_or_create_platform(facts.platform)

    name = resolved["name"]
    if Device.objects.filter(name__iexact=name, site=resolved["site"], tenant=resolved["tenant"]).exists():
        raise ApplyError(f"A device named {name} already exists in site {resolved['site']}. Set a different name or "
                         f"add the serial number/MAC to the existing device so discovery can match it.")
    device = Device(
        name=name,
        device_type=device_type,
        role=resolved["role"],
        site=resolved["site"],
        location=resolved["location"],
        tenant=resolved["tenant"],
        platform=platform,
        serial=(facts.serial or "")[:50] if facts else "",
        status=resolved["status"],
    )
    try:
        _save(device)
    except ValidationError as exc:
        raise ApplyError(_error_text(exc)) from exc
    device.tags.add(get_tag(TAG_DISCOVERED))
    ctx.stats["devices_created"] += 1
    reconcile_device(device, host, ctx, apply=True, include_sensitive=True)
    return device
