from __future__ import annotations

import re

from dcim.choices import DeviceStatusChoices
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from netbox.models import NetBoxModel, PrimaryModel
from netbox.models.features import JobsMixin

from . import crypto
from .choices import (
    CredentialKindChoices,
    HostSourceChoices,
    MatchTypeChoices,
    PlatformKeyChoices,
    ProposalKindChoices,
    ProposalStatusChoices,
    ScanProfileChoices,
    SnmpAuthProtocolChoices,
    SnmpPrivProtocolChoices,
    SyncModeChoices,
)
from .engine import nmap as nmap_engine
from .engine.snmp import SnmpCredential
from .engine.ssh import SshCredential
from .engine.utils import parse_target_networks

__all__ = (
    "CredentialProfile",
    "DeviceTypeAlias",
    "DiscoveredHost",
    "ObjectSighting",
    "ProposedChange",
    "RoleRule",
    "ScanTarget",
)

ENCRYPTED_FIELDS = (
    "encrypted_secret",
    "encrypted_enable_secret",
    "encrypted_auth_key",
    "encrypted_priv_key",
    "encrypted_private_key",
)


def _owner_field():
    """
    PrimaryModel.owner, declared explicitly on plugin models. NetBox 4.7 added related_name="+" to this inherited
    field (4.5 and 4.6 have none), so inheriting it would make the model state, and therefore the migrations, differ
    between supported NetBox releases. Pinning the 4.7 definition keeps it identical everywhere.
    """
    return models.ForeignKey(to="users.Owner", on_delete=models.PROTECT, related_name="+", blank=True, null=True)


def _encrypted_property(field_name):
    def getter(self):
        return crypto.decrypt(getattr(self, field_name))

    def setter(self, value):
        setattr(self, field_name, crypto.encrypt(value) if value else "")

    return property(getter, setter)


class CredentialProfile(PrimaryModel):
    """An SNMP community / SNMPv3 user or an SSH login, stored encrypted."""

    owner = _owner_field()
    name = models.CharField(verbose_name=_("name"), max_length=100, unique=True)
    kind = models.CharField(verbose_name=_("kind"), max_length=20, choices=CredentialKindChoices)
    priority = models.PositiveSmallIntegerField(
        verbose_name=_("priority"), default=100,
        help_text=_("Credentials are tried in ascending priority order (the last working credential is tried first)"),
    )
    port = models.PositiveIntegerField(
        verbose_name=_("port"), blank=True, null=True,
        help_text=_("Defaults to 161 for SNMP and 22 for SSH"),
    )
    username = models.CharField(
        verbose_name=_("username"), max_length=100, blank=True,
        help_text=_("SSH username or SNMPv3 security name"),
    )
    snmp_auth_protocol = models.CharField(
        verbose_name=_("SNMPv3 auth protocol"), max_length=10, choices=SnmpAuthProtocolChoices, default="none",
    )
    snmp_priv_protocol = models.CharField(
        verbose_name=_("SNMPv3 privacy protocol"), max_length=10, choices=SnmpPrivProtocolChoices, default="none",
    )
    options = models.JSONField(
        verbose_name=_("connection options"), default=dict, blank=True,
        help_text=_('Extra NAPALM optional_args / Netmiko arguments, e.g. {"transport": "ssh"}'),
    )
    encrypted_secret = models.TextField(blank=True, editable=False)
    encrypted_enable_secret = models.TextField(blank=True, editable=False)
    encrypted_auth_key = models.TextField(blank=True, editable=False)
    encrypted_priv_key = models.TextField(blank=True, editable=False)
    encrypted_private_key = models.TextField(blank=True, editable=False)

    # Write-through decrypted accessors
    secret = _encrypted_property("encrypted_secret")  # SSH password or SNMP community
    enable_secret = _encrypted_property("encrypted_enable_secret")
    auth_key = _encrypted_property("encrypted_auth_key")
    priv_key = _encrypted_property("encrypted_priv_key")
    private_key = _encrypted_property("encrypted_private_key")

    clone_fields = ("kind", "priority", "port", "username", "snmp_auth_protocol", "snmp_priv_protocol", "options")

    class Meta:
        ordering = ("priority", "name")
        verbose_name = _("credential profile")
        verbose_name_plural = _("credential profiles")

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_nmap_discovery:credentialprofile", args=[self.pk])

    def get_kind_color(self):
        return CredentialKindChoices.colors.get(self.kind)

    @property
    def is_snmp(self):
        return self.kind in (CredentialKindChoices.SNMP_V2C, CredentialKindChoices.SNMP_V3)

    @property
    def has_secret(self):
        return bool(self.encrypted_secret)

    @property
    def has_private_key(self):
        return bool(self.encrypted_private_key)

    def serialize_object(self, exclude=None):
        # Never write ciphertext into the change log
        return super().serialize_object(exclude=[*(exclude or []), *ENCRYPTED_FIELDS])

    def clean(self):
        super().clean()
        if self.kind == CredentialKindChoices.SNMP_V3 and not self.username:
            raise ValidationError({"username": _("SNMPv3 requires a security name (username).")})
        if self.kind == CredentialKindChoices.SSH and not self.username:
            raise ValidationError({"username": _("SSH credentials require a username.")})
        if self.options and not isinstance(self.options, dict):
            raise ValidationError({"options": _("Connection options must be a JSON object.")})

    def to_snmp_credential(self) -> SnmpCredential:
        return SnmpCredential(
            version="3" if self.kind == CredentialKindChoices.SNMP_V3 else "2c",
            community=self.secret if self.kind == CredentialKindChoices.SNMP_V2C else "",
            username=self.username,
            auth_protocol=self.snmp_auth_protocol,
            auth_key=self.auth_key,
            priv_protocol=self.snmp_priv_protocol,
            priv_key=self.priv_key,
            port=self.port or 161,
            id=self.pk,
        )

    def to_ssh_credential(self) -> SshCredential:
        return SshCredential(
            username=self.username,
            password=self.secret,
            enable_secret=self.enable_secret,
            private_key=self.private_key,
            port=self.port or 22,
            options=self.options or {},
            id=self.pk,
        )


class ScanTarget(JobsMixin, PrimaryModel):
    """A set of networks to scan, with the defaults used for anything discovered in them."""

    owner = _owner_field()
    name = models.CharField(verbose_name=_("name"), max_length=100, unique=True)
    enabled = models.BooleanField(verbose_name=_("enabled"), default=True)
    targets = models.TextField(
        verbose_name=_("targets"),
        help_text=_("One per line: IP address, CIDR prefix (/16 or smaller), a.b.c.x-y range or hostname"),
    )
    exclusions = models.TextField(
        verbose_name=_("exclusions"), blank=True,
        help_text=_("Addresses or prefixes never to scan (one per line), e.g. fragile OT/PLC ranges"),
    )
    site = models.ForeignKey(
        to="dcim.Site", on_delete=models.SET_NULL, related_name="+", blank=True, null=True,
        help_text=_("Default site for new devices (a site-scoped NetBox prefix containing the IP takes precedence)"),
    )
    location = models.ForeignKey(
        to="dcim.Location", on_delete=models.SET_NULL, related_name="+", blank=True, null=True,
    )
    tenant = models.ForeignKey(
        to="tenancy.Tenant", on_delete=models.SET_NULL, related_name="+", blank=True, null=True,
    )
    vrf = models.ForeignKey(
        to="ipam.VRF", on_delete=models.SET_NULL, related_name="+", blank=True, null=True,
        verbose_name=_("VRF"), help_text=_("VRF for discovered IP addresses (blank = global table)"),
    )
    default_role = models.ForeignKey(
        to="dcim.DeviceRole", on_delete=models.SET_NULL, related_name="+", blank=True, null=True,
        help_text=_("Role for new devices when no role rule matches"),
    )
    device_status = models.CharField(
        verbose_name=_("device status"), max_length=50, choices=DeviceStatusChoices,
        default=DeviceStatusChoices.STATUS_ACTIVE,
    )
    scan_profile = models.CharField(
        verbose_name=_("scan profile"), max_length=20, choices=ScanProfileChoices, default="conservative",
    )
    custom_nmap_args = models.CharField(
        verbose_name=_("custom nmap arguments"), max_length=500, blank=True,
        help_text=_("Only used with the custom profile. Output, script and file options are not permitted."),
    )
    snmp_enabled = models.BooleanField(verbose_name=_("SNMP polling"), default=True)
    ssh_enabled = models.BooleanField(verbose_name=_("SSH collection"), default=True)
    collect_neighbors = models.BooleanField(
        verbose_name=_("collect neighbours"), default=True,
        help_text=_("Collect LLDP/CDP neighbours and propose cables"),
    )
    collect_arp = models.BooleanField(
        verbose_name=_("harvest ARP tables"), default=True,
        help_text=_("Learn MAC addresses and in-scope hosts from device ARP tables"),
    )
    credentials = models.ManyToManyField(
        to=CredentialProfile, related_name="scan_targets", blank=True,
    )
    sync_mode = models.CharField(
        verbose_name=_("sync mode"), max_length=20, choices=SyncModeChoices, default=SyncModeChoices.HYBRID,
    )
    stale_threshold = models.PositiveSmallIntegerField(
        verbose_name=_("stale threshold"), default=3, validators=[MinValueValidator(1)],
        help_text=_("Consecutive scans an object must be missing before it is tagged discovery-stale"),
    )
    deprecate_stale_ips = models.BooleanField(
        verbose_name=_("deprecate stale IPs"), default=False,
        help_text=_("Also set the status of stale IP addresses to Deprecated (restored when seen again)"),
    )
    interval = models.PositiveIntegerField(
        verbose_name=_("schedule interval"), blank=True, null=True, validators=[MinValueValidator(5)],
        help_text=_("Run automatically every N minutes (blank = manual only)"),
    )

    clone_fields = (
        "enabled", "site", "location", "tenant", "vrf", "default_role", "device_status", "scan_profile",
        "custom_nmap_args", "snmp_enabled", "ssh_enabled", "collect_neighbors", "collect_arp", "sync_mode",
        "stale_threshold", "deprecate_stale_ips", "interval",
    )

    class Meta:
        ordering = ("name",)
        verbose_name = _("scan target")
        verbose_name_plural = _("scan targets")
        permissions = (("run_scantarget", "Can run discovery scans"),)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_nmap_discovery:scantarget", args=[self.pk])

    def get_sync_mode_color(self):
        return SyncModeChoices.colors.get(self.sync_mode)

    @property
    def target_list(self) -> list[str]:
        return [line.strip() for line in self.targets.splitlines() if line.strip() and not line.startswith("#")]

    @property
    def exclusion_list(self) -> list[str]:
        return [line.strip() for line in self.exclusions.splitlines() if line.strip() and not line.startswith("#")]

    @property
    def networks(self):
        return parse_target_networks(self.target_list)

    def covers(self, address: str) -> bool:
        from .engine.utils import address_in_networks

        return address_in_networks(address, self.networks) and not address_in_networks(
            address, parse_target_networks(self.exclusion_list))

    def clean(self):
        super().clean()
        errors = {}
        try:
            nmap_engine.validate_targets(self.targets.splitlines())
            if not self.target_list:
                errors["targets"] = _("At least one target is required.")
        except ValueError as exc:
            errors["targets"] = str(exc)
        try:
            nmap_engine.validate_targets(self.exclusions.splitlines())
        except ValueError as exc:
            errors["exclusions"] = str(exc)
        if self.scan_profile == ScanProfileChoices.CUSTOM:
            if not self.custom_nmap_args:
                errors["custom_nmap_args"] = _("Custom arguments are required for the custom profile.")
            else:
                try:
                    nmap_engine.validate_custom_arguments(self.custom_nmap_args)
                except ValueError as exc:
                    errors["custom_nmap_args"] = str(exc)
        if self.location_id and self.site_id and self.location.site_id != self.site_id:
            errors["location"] = _("Location must belong to the selected site.")
        if self.location_id and not self.site_id:
            errors["site"] = _("A site is required when a location is set.")
        if errors:
            raise ValidationError(errors)


class RoleRule(NetBoxModel):
    """Assigns a device role to newly discovered devices whose attributes match all configured conditions."""

    name = models.CharField(verbose_name=_("name"), max_length=100, unique=True)
    enabled = models.BooleanField(verbose_name=_("enabled"), default=True)
    weight = models.PositiveSmallIntegerField(
        verbose_name=_("weight"), default=100, help_text=_("Rules are evaluated in ascending weight order"),
    )
    role = models.ForeignKey(to="dcim.DeviceRole", on_delete=models.CASCADE, related_name="+")
    hostname_regex = models.CharField(verbose_name=_("hostname regex"), max_length=200, blank=True)
    sys_descr_regex = models.CharField(verbose_name=_("sysDescr regex"), max_length=200, blank=True)
    sys_object_id_prefix = models.CharField(
        verbose_name=_("sysObjectID prefix"), max_length=100, blank=True,
        help_text=_("e.g. 1.3.6.1.4.1.9.1. for Cisco products"),
    )
    platform = models.CharField(verbose_name=_("platform"), max_length=30, blank=True, choices=PlatformKeyChoices)
    manufacturer_regex = models.CharField(verbose_name=_("manufacturer regex"), max_length=200, blank=True)
    model_regex = models.CharField(verbose_name=_("model regex"), max_length=200, blank=True)
    mac_vendor_regex = models.CharField(verbose_name=_("MAC vendor regex"), max_length=200, blank=True)
    open_ports = models.CharField(
        verbose_name=_("open ports"), max_length=200, blank=True,
        help_text=_("Comma-separated TCP ports; matches when any of them is open (e.g. 9100,631 for printers)"),
    )
    scan_targets = models.ManyToManyField(
        to=ScanTarget, related_name="role_rules", blank=True,
        help_text=_("Limit this rule to these scan targets (blank = all)"),
    )
    description = models.CharField(verbose_name=_("description"), max_length=200, blank=True)

    REGEX_FIELDS = ("hostname_regex", "sys_descr_regex", "manufacturer_regex", "model_regex", "mac_vendor_regex")

    class Meta:
        ordering = ("weight", "name")
        verbose_name = _("role rule")
        verbose_name_plural = _("role rules")

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_nmap_discovery:rolerule", args=[self.pk])

    @property
    def port_list(self) -> list[int]:
        return [int(p) for p in re.split(r"[,\s]+", self.open_ports or "") if p.isdigit()]

    def clean(self):
        super().clean()
        errors = {}
        for field_name in self.REGEX_FIELDS:
            value = getattr(self, field_name)
            if value:
                try:
                    re.compile(value)
                except re.error as exc:
                    errors[field_name] = _("Invalid regular expression: {error}").format(error=exc)
        if self.open_ports and not self.port_list:
            errors["open_ports"] = _("Enter a comma-separated list of port numbers.")
        conditions = [getattr(self, f) for f in self.REGEX_FIELDS] + [self.sys_object_id_prefix, self.platform,
                                                                      self.open_ports]
        if not any(conditions):
            errors["__all__"] = _("At least one match condition is required.")
        if errors:
            raise ValidationError(errors)


class DeviceTypeAlias(NetBoxModel):
    """Maps a model string reported by a device to an existing NetBox device type."""

    reported_model = models.CharField(
        verbose_name=_("reported model"), max_length=200,
        help_text=_("Model string as reported by SNMP/SSH, e.g. WS-C3850-48P-L"),
    )
    match_type = models.CharField(
        verbose_name=_("match type"), max_length=10, choices=MatchTypeChoices, default=MatchTypeChoices.EXACT,
    )
    manufacturer = models.ForeignKey(
        to="dcim.Manufacturer", on_delete=models.CASCADE, related_name="+", blank=True, null=True,
        help_text=_("Only apply to devices from this manufacturer (optional)"),
    )
    device_type = models.ForeignKey(to="dcim.DeviceType", on_delete=models.CASCADE, related_name="+")
    weight = models.PositiveSmallIntegerField(verbose_name=_("weight"), default=100)
    description = models.CharField(verbose_name=_("description"), max_length=200, blank=True)

    class Meta:
        ordering = ("weight", "reported_model")
        verbose_name = _("device type alias")
        verbose_name_plural = _("device type aliases")

    def __str__(self):
        return f"{self.reported_model} → {self.device_type}"

    def get_absolute_url(self):
        return reverse("plugins:netbox_nmap_discovery:devicetypealias", args=[self.pk])

    def matches(self, model: str | None) -> bool:
        if not model:
            return False
        if self.match_type == MatchTypeChoices.REGEX:
            try:
                return re.search(self.reported_model, model, re.I) is not None
            except re.error:
                return False
        return self.reported_model.strip().lower() == model.strip().lower()

    def clean(self):
        super().clean()
        if self.match_type == MatchTypeChoices.REGEX:
            try:
                re.compile(self.reported_model)
            except re.error as exc:
                raise ValidationError({"reported_model": _("Invalid regular expression: {error}").format(error=exc)})


class DiscoveredHost(NetBoxModel):
    """
    The latest discovery data for an IP address. Updated in bulk by every scan (bypassing the change log), this is
    the plugin's own inventory of what was seen on the network, including hosts that are not NetBox devices.
    """

    address = models.GenericIPAddressField(verbose_name=_("address"))
    vrf = models.ForeignKey(to="ipam.VRF", on_delete=models.CASCADE, related_name="+", blank=True, null=True)
    scan_target = models.ForeignKey(
        to=ScanTarget, on_delete=models.SET_NULL, related_name="discovered_hosts", blank=True, null=True,
    )
    source = models.CharField(verbose_name=_("source"), max_length=10, choices=HostSourceChoices, default="nmap")
    hostname = models.CharField(verbose_name=_("hostname"), max_length=255, blank=True)
    dns_name = models.CharField(verbose_name=_("DNS name"), max_length=255, blank=True)
    mac_address = models.CharField(verbose_name=_("MAC address"), max_length=17, blank=True)
    mac_vendor = models.CharField(verbose_name=_("MAC vendor"), max_length=100, blank=True)
    os_guess = models.CharField(verbose_name=_("OS guess"), max_length=200, blank=True)
    open_ports = models.JSONField(verbose_name=_("open ports"), default=list, blank=True)
    platform = models.CharField(verbose_name=_("platform"), max_length=30, blank=True, choices=PlatformKeyChoices)
    methods = models.JSONField(verbose_name=_("methods"), default=list, blank=True)
    snmp_credential = models.ForeignKey(
        to=CredentialProfile, on_delete=models.SET_NULL, related_name="+", blank=True, null=True,
    )
    ssh_credential = models.ForeignKey(
        to=CredentialProfile, on_delete=models.SET_NULL, related_name="+", blank=True, null=True,
    )
    device = models.ForeignKey(
        to="dcim.Device", on_delete=models.SET_NULL, related_name="discovered_hosts", blank=True, null=True,
    )
    ip_address = models.ForeignKey(
        to="ipam.IPAddress", on_delete=models.SET_NULL, related_name="discovered_hosts", blank=True, null=True,
        verbose_name=_("IP address"),
    )
    first_seen = models.DateTimeField(verbose_name=_("first seen"))
    last_seen = models.DateTimeField(verbose_name=_("last seen"))
    miss_count = models.PositiveIntegerField(verbose_name=_("consecutive misses"), default=0)
    is_stale = models.BooleanField(verbose_name=_("stale"), default=False)
    data = models.JSONField(verbose_name=_("raw data"), default=dict, blank=True)

    class Meta:
        ordering = ("address",)
        verbose_name = _("discovered host")
        verbose_name_plural = _("discovered hosts")
        constraints = (
            models.UniqueConstraint(fields=("address", "vrf"), name="%(app_label)s_host_unique_address_vrf"),
            models.UniqueConstraint(
                fields=("address",), condition=models.Q(vrf__isnull=True),
                name="%(app_label)s_host_unique_address_global",
            ),
        )

    def __str__(self):
        return f"{self.address}" + (f" ({self.hostname})" if self.hostname else "")

    def get_absolute_url(self):
        return reverse("plugins:netbox_nmap_discovery:discoveredhost", args=[self.pk])

    @property
    def managed(self):
        return bool(self.methods)

    @property
    def open_ports_display(self):
        return ", ".join(f"{p.get('port')}/{p.get('protocol', 'tcp')}"
                         + (f" {p['service']}" if p.get("service") else "") for p in self.open_ports or [])


class ProposedChange(NetBoxModel):
    """A change discovered by a scan that is waiting for review (the review queue)."""

    kind = models.CharField(verbose_name=_("kind"), max_length=20, choices=ProposalKindChoices)
    status = models.CharField(
        verbose_name=_("status"), max_length=20, choices=ProposalStatusChoices, default=ProposalStatusChoices.PENDING,
    )
    scan_target = models.ForeignKey(
        to=ScanTarget, on_delete=models.SET_NULL, related_name="proposed_changes", blank=True, null=True,
    )
    job = models.ForeignKey(to="core.Job", on_delete=models.SET_NULL, related_name="+", blank=True, null=True)
    object_type = models.ForeignKey(
        to=ContentType, on_delete=models.CASCADE, related_name="+", blank=True, null=True,
    )
    object_id = models.PositiveBigIntegerField(blank=True, null=True)
    object = GenericForeignKey("object_type", "object_id")
    summary = models.CharField(verbose_name=_("summary"), max_length=300)
    fingerprint = models.CharField(max_length=300, db_index=True, editable=False)
    data = models.JSONField(verbose_name=_("data"), default=dict)
    diff = models.JSONField(verbose_name=_("changes"), default=list, blank=True)
    overrides = models.JSONField(
        verbose_name=_("overrides"), default=dict, blank=True,
        help_text=_("Values chosen by the reviewer which replace the discovered/resolved values"),
    )
    decided_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name="+", blank=True, null=True,
    )
    decided_at = models.DateTimeField(blank=True, null=True)
    error = models.TextField(verbose_name=_("error"), blank=True)

    class Meta:
        ordering = ("-created",)
        verbose_name = _("proposed change")
        verbose_name_plural = _("proposed changes")
        indexes = (models.Index(fields=("status", "kind")),)

    def __str__(self):
        return self.summary

    def get_absolute_url(self):
        return reverse("plugins:netbox_nmap_discovery:proposedchange", args=[self.pk])

    def get_status_color(self):
        return ProposalStatusChoices.colors.get(self.status)

    def get_kind_color(self):
        return ProposalKindChoices.colors.get(self.kind)

    @property
    def is_pending(self):
        return self.status == ProposalStatusChoices.PENDING


class ObjectSighting(models.Model):
    """Last-seen bookkeeping for NetBox objects maintained by discovery (used for stale detection)."""

    object_type = models.ForeignKey(to=ContentType, on_delete=models.CASCADE, related_name="+")
    object_id = models.PositiveBigIntegerField()
    object = GenericForeignKey("object_type", "object_id")
    scan_target = models.ForeignKey(to=ScanTarget, on_delete=models.CASCADE, related_name="sightings")
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    miss_count = models.PositiveIntegerField(default=0)
    is_stale = models.BooleanField(default=False)
    previous_status = models.CharField(max_length=50, blank=True)

    class Meta:
        constraints = (
            models.UniqueConstraint(
                fields=("object_type", "object_id", "scan_target"), name="%(app_label)s_sighting_unique",
            ),
        )
        indexes = (models.Index(fields=("object_type", "object_id")),)
        verbose_name = _("object sighting")

    def __str__(self):
        return f"{self.object_type.model} #{self.object_id}"
