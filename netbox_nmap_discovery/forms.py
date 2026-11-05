from dcim.choices import DeviceStatusChoices
from dcim.models import DeviceRole, DeviceType, Location, Manufacturer, Platform, Site
from django import forms
from django.utils.translation import gettext_lazy as _
from ipam.models import VRF
from netbox.forms import (
    NetBoxModelFilterSetForm,
    NetBoxModelForm,
    NetBoxModelImportForm,
    PrimaryModelBulkEditForm,
    PrimaryModelFilterSetForm,
    PrimaryModelForm,
    PrimaryModelImportForm,
)
from tenancy.models import Tenant
from utilities.forms import BOOLEAN_WITH_BLANK_CHOICES, add_blank_choice
from utilities.forms.fields import (
    CSVChoiceField,
    CSVModelChoiceField,
    CSVModelMultipleChoiceField,
    DynamicModelChoiceField,
    DynamicModelMultipleChoiceField,
    TagFilterField,
)
from utilities.forms.rendering import FieldSet

from .choices import (
    CredentialKindChoices,
    HostSourceChoices,
    MatchTypeChoices,
    PlatformKeyChoices,
    ProposalKindChoices,
    ProposalStatusChoices,
    ScanProfileChoices,
    SyncModeChoices,
)
from .models import CredentialProfile, DeviceTypeAlias, DiscoveredHost, ProposedChange, RoleRule, ScanTarget

SECRET_FIELDS = {
    "secret": "encrypted_secret",
    "enable_secret": "encrypted_enable_secret",
    "auth_key": "encrypted_auth_key",
    "priv_key": "encrypted_priv_key",
    "private_key": "encrypted_private_key",
}


#
# Credential profiles
#
class CredentialProfileForm(PrimaryModelForm):
    secret = forms.CharField(
        label=_("Password / community"), required=False, strip=False,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}),
        help_text=_("SSH password or SNMPv2c community. Leave blank to keep the stored value."),
    )
    enable_secret = forms.CharField(
        label=_("Enable secret"), required=False, strip=False,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}),
        help_text=_("Privileged-mode secret (SSH). Leave blank to keep the stored value."),
    )
    auth_key = forms.CharField(
        label=_("Auth passphrase"), required=False, strip=False,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}),
        help_text=_("SNMPv3 authentication passphrase. Leave blank to keep the stored value."),
    )
    priv_key = forms.CharField(
        label=_("Privacy passphrase"), required=False, strip=False,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}),
        help_text=_("SNMPv3 privacy passphrase. Leave blank to keep the stored value."),
    )
    private_key = forms.CharField(
        label=_("SSH private key"), required=False, strip=False,
        widget=forms.Textarea(attrs={"rows": 3, "placeholder": "-----BEGIN OPENSSH PRIVATE KEY-----",
                                     "autocomplete": "off"}),
        help_text=_("PEM-encoded private key (optional). Never displayed after saving; leave blank to keep."),
    )
    clear_secrets = forms.BooleanField(
        label=_("Clear stored secrets"), required=False,
        help_text=_("Remove all stored secrets from this profile"),
    )

    fieldsets = (
        FieldSet("name", "kind", "priority", "port", "description", "tags", name=_("Credential")),
        FieldSet("username", "secret", "enable_secret", "private_key", name=_("Authentication")),
        FieldSet("snmp_auth_protocol", "auth_key", "snmp_priv_protocol", "priv_key", name=_("SNMPv3")),
        FieldSet("options", "clear_secrets", name=_("Advanced")),
    )

    class Meta:
        model = CredentialProfile
        fields = ("name", "kind", "priority", "port", "username", "snmp_auth_protocol", "snmp_priv_protocol",
                  "options", "description", "owner", "comments", "tags")

    def clean(self):
        super().clean()
        kind = self.cleaned_data.get("kind")
        instance = self.instance
        has_secret = bool(self.cleaned_data.get("secret")) or (instance.pk and instance.encrypted_secret
                                                                and not self.cleaned_data.get("clear_secrets"))
        if kind == CredentialKindChoices.SNMP_V2C and not has_secret:
            self.add_error("secret", _("An SNMP community is required."))
        if kind == CredentialKindChoices.SSH and not has_secret and not (
                self.cleaned_data.get("private_key") or (instance.pk and instance.encrypted_private_key)):
            self.add_error("secret", _("A password or private key is required for SSH."))
        if kind == CredentialKindChoices.SNMP_V3:
            if self.cleaned_data.get("snmp_auth_protocol") != "none" and not (
                    self.cleaned_data.get("auth_key") or (instance.pk and instance.encrypted_auth_key)):
                self.add_error("auth_key", _("An authentication passphrase is required."))
            if self.cleaned_data.get("snmp_priv_protocol") != "none":
                if self.cleaned_data.get("snmp_auth_protocol") == "none":
                    self.add_error("snmp_priv_protocol", _("Privacy requires an authentication protocol."))
                if not (self.cleaned_data.get("priv_key") or (instance.pk and instance.encrypted_priv_key)):
                    self.add_error("priv_key", _("A privacy passphrase is required."))
            for field_name in ("auth_key", "priv_key"):
                value = self.cleaned_data.get(field_name)
                if value and len(value) < 8:
                    self.add_error(field_name, _("SNMPv3 passphrases must be at least 8 characters."))
        return self.cleaned_data

    def save(self, *args, **kwargs):
        if self.cleaned_data.get("clear_secrets"):
            for encrypted_field in SECRET_FIELDS.values():
                setattr(self.instance, encrypted_field, "")
        for field_name in SECRET_FIELDS:
            value = self.cleaned_data.get(field_name)
            if value:
                setattr(self.instance, field_name, value)
        return super().save(*args, **kwargs)


class CredentialProfileFilterForm(PrimaryModelFilterSetForm):
    model = CredentialProfile
    fieldsets = (
        FieldSet("q", "filter_id", "tag"),
        FieldSet("kind", "username", name=_("Credential")),
    )
    kind = forms.MultipleChoiceField(choices=CredentialKindChoices, required=False)
    username = forms.CharField(required=False)
    tag = TagFilterField(model)


#
# Scan targets
#
class ScanTargetForm(PrimaryModelForm):
    site = DynamicModelChoiceField(queryset=Site.objects.all(), required=False, label=_("Site"))
    location = DynamicModelChoiceField(queryset=Location.objects.all(), required=False, label=_("Location"),
                                       query_params={"site_id": "$site"})
    tenant = DynamicModelChoiceField(queryset=Tenant.objects.all(), required=False, label=_("Tenant"))
    vrf = DynamicModelChoiceField(queryset=VRF.objects.all(), required=False, label=_("VRF"))
    default_role = DynamicModelChoiceField(queryset=DeviceRole.objects.all(), required=False,
                                           label=_("Default role"))
    credentials = DynamicModelMultipleChoiceField(queryset=CredentialProfile.objects.all(), required=False,
                                                  label=_("Credentials"))
    targets = forms.CharField(widget=forms.Textarea(attrs={"rows": 4, "class": "font-monospace",
                                                           "placeholder": "10.0.0.0/24\n10.0.1.10-50"}),
                              help_text=ScanTarget._meta.get_field("targets").help_text)
    exclusions = forms.CharField(widget=forms.Textarea(attrs={"rows": 2, "class": "font-monospace"}),
                                 required=False, help_text=ScanTarget._meta.get_field("exclusions").help_text)

    fieldsets = (
        FieldSet("name", "enabled", "targets", "exclusions", "description", "tags", name=_("Scan target")),
        FieldSet("scan_profile", "custom_nmap_args", "snmp_enabled", "ssh_enabled", "collect_neighbors",
                 "collect_arp", "credentials", name=_("Discovery")),
        FieldSet("site", "location", "tenant", "vrf", "default_role", "device_status", name=_("Defaults")),
        FieldSet("sync_mode", "stale_threshold", "deprecate_stale_ips", "interval", name=_("Synchronisation")),
    )

    class Meta:
        model = ScanTarget
        fields = ("name", "enabled", "targets", "exclusions", "site", "location", "tenant", "vrf", "default_role",
                  "device_status", "scan_profile", "custom_nmap_args", "snmp_enabled", "ssh_enabled",
                  "collect_neighbors", "collect_arp", "credentials", "sync_mode", "stale_threshold",
                  "deprecate_stale_ips", "interval", "description", "owner", "comments", "tags")


class ScanTargetFilterForm(PrimaryModelFilterSetForm):
    model = ScanTarget
    fieldsets = (
        FieldSet("q", "filter_id", "tag"),
        FieldSet("enabled", "sync_mode", "scan_profile", "scheduled", name=_("Scan target")),
        FieldSet("site_id", "vrf_id", "credential_id", name=_("Related objects")),
    )
    enabled = forms.NullBooleanField(required=False, widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    sync_mode = forms.MultipleChoiceField(choices=SyncModeChoices, required=False)
    scan_profile = forms.MultipleChoiceField(choices=ScanProfileChoices, required=False)
    scheduled = forms.NullBooleanField(required=False, widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    site_id = DynamicModelMultipleChoiceField(queryset=Site.objects.all(), required=False, label=_("Site"))
    vrf_id = DynamicModelMultipleChoiceField(queryset=VRF.objects.all(), required=False, label=_("VRF"))
    credential_id = DynamicModelMultipleChoiceField(queryset=CredentialProfile.objects.all(), required=False,
                                                    label=_("Credential"))
    tag = TagFilterField(model)


class ScanTargetBulkEditForm(PrimaryModelBulkEditForm):
    model = ScanTarget
    enabled = forms.NullBooleanField(required=False, widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    sync_mode = forms.ChoiceField(choices=add_blank_choice(SyncModeChoices), required=False)
    scan_profile = forms.ChoiceField(choices=add_blank_choice(ScanProfileChoices), required=False)
    site = DynamicModelChoiceField(queryset=Site.objects.all(), required=False)
    tenant = DynamicModelChoiceField(queryset=Tenant.objects.all(), required=False)
    vrf = DynamicModelChoiceField(queryset=VRF.objects.all(), required=False)
    default_role = DynamicModelChoiceField(queryset=DeviceRole.objects.all(), required=False)
    snmp_enabled = forms.NullBooleanField(required=False, widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    ssh_enabled = forms.NullBooleanField(required=False, widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    collect_neighbors = forms.NullBooleanField(required=False,
                                               widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    stale_threshold = forms.IntegerField(required=False, min_value=1)
    interval = forms.IntegerField(required=False, min_value=5, label=_("Schedule interval (minutes)"))

    fieldsets = (
        FieldSet("enabled", "sync_mode", "scan_profile", "snmp_enabled", "ssh_enabled", "collect_neighbors",
                 "stale_threshold", "interval", "description"),
        FieldSet("site", "tenant", "vrf", "default_role", name=_("Defaults")),
    )
    nullable_fields = ("site", "tenant", "vrf", "default_role", "interval", "description")


class ScanTargetImportForm(PrimaryModelImportForm):
    site = CSVModelChoiceField(queryset=Site.objects.all(), to_field_name="name", required=False)
    tenant = CSVModelChoiceField(queryset=Tenant.objects.all(), to_field_name="name", required=False)
    vrf = CSVModelChoiceField(queryset=VRF.objects.all(), to_field_name="name", required=False)
    default_role = CSVModelChoiceField(queryset=DeviceRole.objects.all(), to_field_name="name", required=False)
    credentials = CSVModelMultipleChoiceField(queryset=CredentialProfile.objects.all(), to_field_name="name",
                                              required=False)
    scan_profile = CSVChoiceField(choices=ScanProfileChoices, required=False)
    sync_mode = CSVChoiceField(choices=SyncModeChoices, required=False)

    class Meta:
        model = ScanTarget
        fields = ("name", "enabled", "targets", "exclusions", "site", "tenant", "vrf", "default_role",
                  "scan_profile", "custom_nmap_args", "snmp_enabled", "ssh_enabled", "collect_neighbors",
                  "collect_arp", "credentials", "sync_mode", "stale_threshold", "deprecate_stale_ips", "interval",
                  "description", "comments", "tags")


#
# Role rules
#
class RoleRuleForm(NetBoxModelForm):
    role = DynamicModelChoiceField(queryset=DeviceRole.objects.all(), label=_("Role"))
    scan_targets = DynamicModelMultipleChoiceField(queryset=ScanTarget.objects.all(), required=False,
                                                   label=_("Scan targets"))

    fieldsets = (
        FieldSet("name", "enabled", "weight", "role", "description", "tags", name=_("Rule")),
        FieldSet("hostname_regex", "sys_descr_regex", "sys_object_id_prefix", "platform", "manufacturer_regex",
                 "model_regex", "mac_vendor_regex", "open_ports", name=_("Conditions (all must match)")),
        FieldSet("scan_targets", name=_("Scope")),
    )

    class Meta:
        model = RoleRule
        fields = ("name", "enabled", "weight", "role", "hostname_regex", "sys_descr_regex", "sys_object_id_prefix",
                  "platform", "manufacturer_regex", "model_regex", "mac_vendor_regex", "open_ports", "scan_targets",
                  "description", "tags")


class RoleRuleFilterForm(NetBoxModelFilterSetForm):
    model = RoleRule
    fieldsets = (FieldSet("q", "filter_id", "tag"), FieldSet("enabled", "role_id", "platform", name=_("Rule")))
    enabled = forms.NullBooleanField(required=False, widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    role_id = DynamicModelMultipleChoiceField(queryset=DeviceRole.objects.all(), required=False, label=_("Role"))
    platform = forms.MultipleChoiceField(choices=PlatformKeyChoices, required=False)
    tag = TagFilterField(model)


class RoleRuleImportForm(NetBoxModelImportForm):
    role = CSVModelChoiceField(queryset=DeviceRole.objects.all(), to_field_name="name")
    platform = CSVChoiceField(choices=PlatformKeyChoices, required=False)

    class Meta:
        model = RoleRule
        fields = ("name", "enabled", "weight", "role", "hostname_regex", "sys_descr_regex", "sys_object_id_prefix",
                  "platform", "manufacturer_regex", "model_regex", "mac_vendor_regex", "open_ports", "description",
                  "tags")


#
# Device type aliases
#
class DeviceTypeAliasForm(NetBoxModelForm):
    manufacturer = DynamicModelChoiceField(queryset=Manufacturer.objects.all(), required=False)
    device_type = DynamicModelChoiceField(queryset=DeviceType.objects.all(),
                                          query_params={"manufacturer_id": "$manufacturer"})

    fieldsets = (
        FieldSet("reported_model", "match_type", "manufacturer", "device_type", "weight", "description", "tags"),
    )

    class Meta:
        model = DeviceTypeAlias
        fields = ("reported_model", "match_type", "manufacturer", "device_type", "weight", "description", "tags")


class DeviceTypeAliasFilterForm(NetBoxModelFilterSetForm):
    model = DeviceTypeAlias
    fieldsets = (FieldSet("q", "filter_id", "tag"),
                 FieldSet("match_type", "manufacturer_id", "device_type_id", name=_("Alias")))
    match_type = forms.MultipleChoiceField(choices=MatchTypeChoices, required=False)
    manufacturer_id = DynamicModelMultipleChoiceField(queryset=Manufacturer.objects.all(), required=False,
                                                      label=_("Manufacturer"))
    device_type_id = DynamicModelMultipleChoiceField(queryset=DeviceType.objects.all(), required=False,
                                                     label=_("Device type"))
    tag = TagFilterField(model)


class DeviceTypeAliasImportForm(NetBoxModelImportForm):
    manufacturer = CSVModelChoiceField(queryset=Manufacturer.objects.all(), to_field_name="name", required=False)
    device_type = CSVModelChoiceField(queryset=DeviceType.objects.all(), to_field_name="slug")
    match_type = CSVChoiceField(choices=MatchTypeChoices, required=False)

    class Meta:
        model = DeviceTypeAlias
        fields = ("reported_model", "match_type", "manufacturer", "device_type", "weight", "description", "tags")


#
# Review queue
#
class ProposedChangeFilterForm(NetBoxModelFilterSetForm):
    model = ProposedChange
    fieldsets = (FieldSet("q", "filter_id", "tag"),
                 FieldSet("status", "kind", "scan_target_id", name=_("Proposal")))
    status = forms.MultipleChoiceField(choices=ProposalStatusChoices, required=False)
    kind = forms.MultipleChoiceField(choices=ProposalKindChoices, required=False)
    scan_target_id = DynamicModelMultipleChoiceField(queryset=ScanTarget.objects.all(), required=False,
                                                     label=_("Scan target"))
    tag = TagFilterField(model)


class ProposalOverridesForm(forms.Form):
    """Reviewer overrides for a new-device proposal."""

    name = forms.CharField(max_length=64, required=False, help_text=_("Leave blank to use the discovered hostname"))
    site = DynamicModelChoiceField(queryset=Site.objects.all(), required=False)
    location = DynamicModelChoiceField(queryset=Location.objects.all(), required=False,
                                       query_params={"site_id": "$site"})
    role = DynamicModelChoiceField(queryset=DeviceRole.objects.all(), required=False)
    device_type = DynamicModelChoiceField(queryset=DeviceType.objects.all(), required=False,
                                          help_text=_("Leave blank to match or create one automatically"))
    platform = DynamicModelChoiceField(queryset=Platform.objects.all(), required=False)
    tenant = DynamicModelChoiceField(queryset=Tenant.objects.all(), required=False)
    status = forms.ChoiceField(choices=add_blank_choice(DeviceStatusChoices), required=False)
    approve = forms.BooleanField(required=False, initial=False, label=_("Approve now"),
                                 help_text=_("Apply the proposal immediately after saving the overrides"))

    fieldsets = (
        FieldSet("name", "status", "role", "device_type", "platform", name=_("Device")),
        FieldSet("site", "location", "tenant", name=_("Placement")),
        FieldSet("approve", name=_("Review")),
    )

    MODEL_FIELDS = ("site", "location", "role", "device_type", "platform", "tenant")

    def to_overrides(self) -> dict:
        overrides = {}
        for field_name, value in self.cleaned_data.items():
            if field_name == "approve" or value in (None, ""):
                continue
            overrides[field_name] = value.pk if field_name in self.MODEL_FIELDS else value
        return overrides


class DiscoveredHostFilterForm(NetBoxModelFilterSetForm):
    model = DiscoveredHost
    fieldsets = (FieldSet("q", "filter_id", "tag"),
                 FieldSet("scan_target_id", "vrf_id", "source", "platform", "managed", "has_device", "is_stale",
                          name=_("Host")))
    scan_target_id = DynamicModelMultipleChoiceField(queryset=ScanTarget.objects.all(), required=False,
                                                     label=_("Scan target"))
    vrf_id = DynamicModelMultipleChoiceField(queryset=VRF.objects.all(), required=False, label=_("VRF"))
    source = forms.MultipleChoiceField(choices=HostSourceChoices, required=False)
    platform = forms.MultipleChoiceField(choices=PlatformKeyChoices, required=False)
    managed = forms.NullBooleanField(required=False, label=_("Answered SNMP/SSH"),
                                     widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    has_device = forms.NullBooleanField(required=False, label=_("Linked to a device"),
                                        widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    is_stale = forms.NullBooleanField(required=False, label=_("Stale"),
                                      widget=forms.Select(choices=BOOLEAN_WITH_BLANK_CHOICES))
    tag = TagFilterField(model)


class RediscoverForm(forms.Form):
    address = forms.GenericIPAddressField(label=_("Address"))
    scan_target = forms.ModelChoiceField(queryset=ScanTarget.objects.all(), label=_("Scan target"),
                                         help_text=_("Credentials and defaults are taken from this scan target"))
