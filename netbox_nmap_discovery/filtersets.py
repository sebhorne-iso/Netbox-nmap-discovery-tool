import django_filters
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from ipam.models import VRF
from netbox.filtersets import NetBoxModelFilterSet, PrimaryModelFilterSet

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

__all__ = (
    "CredentialProfileFilterSet",
    "DeviceTypeAliasFilterSet",
    "DiscoveredHostFilterSet",
    "ProposedChangeFilterSet",
    "RoleRuleFilterSet",
    "ScanTargetFilterSet",
)


class CredentialProfileFilterSet(PrimaryModelFilterSet):
    kind = django_filters.MultipleChoiceFilter(choices=CredentialKindChoices)
    scan_target_id = django_filters.ModelMultipleChoiceFilter(
        field_name="scan_targets", queryset=ScanTarget.objects.all(), label=_("Scan target (ID)"),
    )

    class Meta:
        model = CredentialProfile
        fields = ("id", "name", "kind", "priority", "port", "username", "description")

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(name__icontains=value) | Q(username__icontains=value) |
                               Q(description__icontains=value))


class ScanTargetFilterSet(PrimaryModelFilterSet):
    sync_mode = django_filters.MultipleChoiceFilter(choices=SyncModeChoices)
    scan_profile = django_filters.MultipleChoiceFilter(choices=ScanProfileChoices)
    site_id = django_filters.ModelMultipleChoiceFilter(queryset=Site.objects.all(), label=_("Site (ID)"))
    vrf_id = django_filters.ModelMultipleChoiceFilter(queryset=VRF.objects.all(), label=_("VRF (ID)"))
    credential_id = django_filters.ModelMultipleChoiceFilter(
        field_name="credentials", queryset=CredentialProfile.objects.all(), label=_("Credential (ID)"),
    )
    scheduled = django_filters.BooleanFilter(field_name="interval", lookup_expr="isnull", exclude=True,
                                             label=_("Scheduled"))

    class Meta:
        model = ScanTarget
        fields = ("id", "name", "enabled", "snmp_enabled", "ssh_enabled", "collect_neighbors", "collect_arp",
                  "interval", "stale_threshold", "deprecate_stale_ips", "description")

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(name__icontains=value) | Q(targets__icontains=value) |
                               Q(description__icontains=value))


class RoleRuleFilterSet(NetBoxModelFilterSet):
    role_id = django_filters.ModelMultipleChoiceFilter(queryset=DeviceRole.objects.all(), label=_("Role (ID)"))
    platform = django_filters.MultipleChoiceFilter(choices=PlatformKeyChoices)

    class Meta:
        model = RoleRule
        fields = ("id", "name", "enabled", "weight", "description")

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(name__icontains=value) | Q(hostname_regex__icontains=value) |
                               Q(description__icontains=value))


class DeviceTypeAliasFilterSet(NetBoxModelFilterSet):
    match_type = django_filters.MultipleChoiceFilter(choices=MatchTypeChoices)
    manufacturer_id = django_filters.ModelMultipleChoiceFilter(queryset=Manufacturer.objects.all(),
                                                               label=_("Manufacturer (ID)"))
    device_type_id = django_filters.ModelMultipleChoiceFilter(queryset=DeviceType.objects.all(),
                                                              label=_("Device type (ID)"))

    class Meta:
        model = DeviceTypeAlias
        fields = ("id", "reported_model", "weight", "description")

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(reported_model__icontains=value) | Q(device_type__model__icontains=value))


class ProposedChangeFilterSet(NetBoxModelFilterSet):
    kind = django_filters.MultipleChoiceFilter(choices=ProposalKindChoices)
    status = django_filters.MultipleChoiceFilter(choices=ProposalStatusChoices)
    scan_target_id = django_filters.ModelMultipleChoiceFilter(queryset=ScanTarget.objects.all(),
                                                              label=_("Scan target (ID)"))
    job_id = django_filters.NumberFilter(field_name="job_id")
    object_id = django_filters.NumberFilter()
    device_id = django_filters.NumberFilter(method="filter_device", label=_("Device (ID)"))

    class Meta:
        model = ProposedChange
        fields = ("id", "kind", "status", "summary", "fingerprint")

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(summary__icontains=value) | Q(fingerprint__icontains=value))

    def filter_device(self, queryset, name, value):
        from django.contrib.contenttypes.models import ContentType

        device_type = ContentType.objects.get_for_model(Device)
        return queryset.filter(object_type=device_type, object_id=value)


class DiscoveredHostFilterSet(NetBoxModelFilterSet):
    scan_target_id = django_filters.ModelMultipleChoiceFilter(queryset=ScanTarget.objects.all(),
                                                              label=_("Scan target (ID)"))
    vrf_id = django_filters.ModelMultipleChoiceFilter(queryset=VRF.objects.all(), label=_("VRF (ID)"))
    device_id = django_filters.ModelMultipleChoiceFilter(queryset=Device.objects.all(), label=_("Device (ID)"))
    source = django_filters.MultipleChoiceFilter(choices=HostSourceChoices)
    platform = django_filters.MultipleChoiceFilter(choices=PlatformKeyChoices)
    managed = django_filters.BooleanFilter(method="filter_managed", label=_("Answered SNMP/SSH"))
    has_device = django_filters.BooleanFilter(field_name="device", lookup_expr="isnull", exclude=True,
                                              label=_("Linked to a device"))

    class Meta:
        model = DiscoveredHost
        fields = ("id", "address", "hostname", "dns_name", "mac_address", "mac_vendor", "os_guess", "is_stale",
                  "miss_count")

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(address__icontains=value) | Q(hostname__icontains=value) |
                               Q(dns_name__icontains=value) | Q(mac_address__icontains=value) |
                               Q(mac_vendor__icontains=value) | Q(os_guess__icontains=value))

    def filter_managed(self, queryset, name, value):
        managed = Q(methods__contains=["snmp"]) | Q(methods__contains=["ssh"])
        return queryset.filter(managed) if value else queryset.exclude(managed)
