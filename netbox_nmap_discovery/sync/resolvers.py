"""Resolve the NetBox objects (site, role, manufacturer, platform, device type) a discovered device maps to."""
from __future__ import annotations

import ipaddress

from dcim.models import DeviceRole, DeviceType, Manufacturer, Platform
from django.utils.text import slugify
from ipam.choices import PrefixStatusChoices
from ipam.models import Prefix

from ..engine.platforms import PLATFORMS, normalize_manufacturer
from ..engine.results import HostResult
from ..models import DeviceTypeAlias, RoleRule
from .provision import TAG_AUTOCREATED, get_tag
from .rules import select_role_rule

__all__ = (
    "find_device_type",
    "find_manufacturer",
    "find_platform",
    "get_or_create_device_type",
    "get_or_create_manufacturer",
    "get_or_create_platform",
    "most_specific_prefix",
    "resolve_role",
    "resolve_site_and_location",
)

UNKNOWN_MODEL = "Unknown"
GENERIC_MANUFACTURER = "Generic"


def _unique_slug(model, base: str, field="slug", **filters) -> str:
    base = slugify(base)[:90] or "unknown"
    slug, counter = base, 2
    while model.objects.filter(**{field: slug}, **filters).exists():
        slug = f"{base}-{counter}"
        counter += 1
    return slug


def most_specific_prefix(address: str, vrf=None, exclude_containers=False):
    """Return the most specific NetBox prefix in ``vrf`` containing ``address`` (or None)."""
    candidates = Prefix.objects.filter(vrf=vrf, prefix__net_contains_or_equals=address)
    if exclude_containers:
        candidates = candidates.exclude(status=PrefixStatusChoices.STATUS_CONTAINER)
    best = None
    for prefix in candidates:
        if best is None or prefix.prefix.prefixlen > best.prefix.prefixlen:
            best = prefix
    return best


def resolve_site_and_location(address: str, scan_target):
    """
    A site-scoped NetBox prefix containing ``address`` wins; otherwise the scan target's site and location are used.
    """
    vrf = getattr(scan_target, "vrf", None)
    prefix = most_specific_prefix(address, vrf)
    if prefix is not None and getattr(prefix, "_site", None) is not None:
        location = getattr(prefix, "_location", None)
        target_location = scan_target.location if scan_target else None
        if location is None and target_location and target_location.site_id == prefix._site_id:
            location = target_location
        return prefix._site, location
    if scan_target is not None:
        return scan_target.site, scan_target.location
    return None, None


def resolve_role(host: HostResult, scan_target):
    rules = list(RoleRule.objects.filter(enabled=True).select_related("role").prefetch_related("scan_targets"))
    for rule in rules:
        rule._target_ids = {t.pk for t in rule.scan_targets.all()}
    rule = select_role_rule(rules, host, scan_target.pk if scan_target else None)
    if rule:
        return rule.role, rule
    return (scan_target.default_role if scan_target else None), None


# --- Manufacturer ---------------------------------------------------------------------------------------------
def find_manufacturer(name: str | None):
    if not name:
        return None
    return (Manufacturer.objects.filter(name__iexact=name).first()
            or Manufacturer.objects.filter(slug=slugify(name)).first())


def get_or_create_manufacturer(name: str | None):
    name = name or GENERIC_MANUFACTURER
    manufacturer = find_manufacturer(name)
    if manufacturer:
        return manufacturer, False
    manufacturer = Manufacturer(name=name, slug=_unique_slug(Manufacturer, name))
    manufacturer.full_clean()
    manufacturer.save()
    manufacturer.tags.add(get_tag(TAG_AUTOCREATED))
    return manufacturer, True


# --- Platform -------------------------------------------------------------------------------------------------
def find_platform(key: str | None):
    spec = PLATFORMS.get(key or "")
    if spec is None:
        return None
    return (Platform.objects.filter(name__iexact=spec.name).first()
            or Platform.objects.filter(slug=slugify(spec.name)).first()
            or Platform.objects.filter(slug=key.replace("_", "-")).first())


def get_or_create_platform(key: str | None):
    spec = PLATFORMS.get(key or "")
    if spec is None:
        return None, False
    platform = find_platform(key)
    if platform:
        return platform, False
    manufacturer = None
    if spec.manufacturer:
        manufacturer, _ = get_or_create_manufacturer(spec.manufacturer)
    platform = Platform(name=spec.name, slug=_unique_slug(Platform, spec.name), manufacturer=manufacturer,
                        description=f"Created by network discovery ({spec.key})")
    platform.full_clean()
    platform.save()
    platform.tags.add(get_tag(TAG_AUTOCREATED))
    return platform, True


# --- Device type ----------------------------------------------------------------------------------------------
def _manufacturer_name(host: HostResult, aliases=None) -> str | None:
    facts = host.facts
    if facts and facts.vendor:
        return normalize_manufacturer(facts.vendor, aliases)
    if facts and facts.platform and PLATFORMS[facts.platform].manufacturer:
        return PLATFORMS[facts.platform].manufacturer
    return None


def find_device_type(host: HostResult, aliases=None):
    """Return an existing DeviceType for the host's reported model, or None."""
    model = host.facts.model if host.facts else None
    manufacturer_name = _manufacturer_name(host, aliases)
    manufacturer = find_manufacturer(manufacturer_name)
    if model:
        for alias in DeviceTypeAlias.objects.select_related("device_type").order_by("weight", "pk"):
            if alias.manufacturer_id and (manufacturer is None or alias.manufacturer_id != manufacturer.pk):
                continue
            if alias.matches(model):
                return alias.device_type
        queryset = DeviceType.objects.filter(manufacturer=manufacturer) if manufacturer else DeviceType.objects.all()
        for lookup in ("model__iexact", "part_number__iexact", "slug"):
            value = slugify(model) if lookup == "slug" else model
            matches = list(queryset.filter(**{lookup: value})[:2])
            if len(matches) == 1:
                return matches[0]
        # Many vendors report a licence/PSU suffix the device-type library omits (e.g. "C9300-48P-A" vs "C9300-48P")
        if manufacturer:
            for candidate in queryset.filter(model__isnull=False).only("pk", "model", "part_number"):
                for value in (candidate.part_number, candidate.model):
                    if value and len(value) >= 5 and model.upper().startswith(value.upper() + "-"):
                        return candidate
    elif manufacturer:
        return DeviceType.objects.filter(manufacturer=manufacturer, model=UNKNOWN_MODEL).first()
    else:
        generic = find_manufacturer(GENERIC_MANUFACTURER)
        if generic:
            return DeviceType.objects.filter(manufacturer=generic, model=UNKNOWN_MODEL).first()
    return None


def describe_device_type(host: HostResult, aliases=None) -> str:
    device_type = find_device_type(host, aliases)
    if device_type:
        return str(device_type)
    model = (host.facts.model if host.facts else None) or UNKNOWN_MODEL
    manufacturer = _manufacturer_name(host, aliases) or GENERIC_MANUFACTURER
    return f"{manufacturer} {model} (will be created)"


def get_or_create_device_type(host: HostResult, settings: dict):
    aliases = settings.get("manufacturer_aliases")
    device_type = find_device_type(host, aliases)
    if device_type:
        return device_type, False
    manufacturer, _ = get_or_create_manufacturer(_manufacturer_name(host, aliases))
    model = (host.facts.model if host.facts else None) or UNKNOWN_MODEL
    device_type = DeviceType(
        manufacturer=manufacturer,
        model=model,
        slug=_unique_slug(DeviceType, f"{manufacturer.slug}-{model}"),
        part_number=model if model != UNKNOWN_MODEL else "",
        u_height=settings.get("device_type_u_height", 1),
        comments="Created automatically by network discovery. Consider importing the full definition from the "
                 "NetBox device-type library and adding a device type alias.",
    )
    device_type.full_clean()
    device_type.save()
    device_type.tags.add(get_tag(TAG_AUTOCREATED))
    return device_type, True


def ip_prefix_length(address: str, vrf=None) -> int:
    """Prefix length to use when creating an IP address learned without a mask (e.g. from nmap)."""
    prefix = most_specific_prefix(address, vrf, exclude_containers=True)
    if prefix is not None and not prefix.is_pool and prefix.prefix.version == ipaddress.ip_address(address).version:
        return prefix.prefix.prefixlen
    return 32 if ipaddress.ip_address(address).version == 4 else 128


def role_exists(pk) -> bool:
    return DeviceRole.objects.filter(pk=pk).exists()
