from dcim.api.serializers import (
    DeviceRoleSerializer,
    DeviceSerializer,
    DeviceTypeSerializer,
    LocationSerializer,
    ManufacturerSerializer,
    SiteSerializer,
)
from ipam.api.serializers import IPAddressSerializer, VRFSerializer
from netbox.api.fields import ChoiceField
from netbox.api.serializers import NetBoxModelSerializer, PrimaryModelSerializer
from rest_framework import serializers
from tenancy.api.serializers import TenantSerializer

from ..choices import (
    CredentialKindChoices,
    MatchTypeChoices,
    PlatformKeyChoices,
    ProposalKindChoices,
    ProposalStatusChoices,
    ScanProfileChoices,
    SnmpAuthProtocolChoices,
    SnmpPrivProtocolChoices,
    SyncModeChoices,
)
from ..models import CredentialProfile, DeviceTypeAlias, DiscoveredHost, ProposedChange, RoleRule, ScanTarget

SECRET_FIELDS = ("secret", "enable_secret", "auth_key", "priv_key", "private_key")


class CredentialProfileSerializer(PrimaryModelSerializer):
    kind = ChoiceField(choices=CredentialKindChoices)
    snmp_auth_protocol = ChoiceField(choices=SnmpAuthProtocolChoices, required=False)
    snmp_priv_protocol = ChoiceField(choices=SnmpPrivProtocolChoices, required=False)
    # Write-only secrets: accepted on create/update, never returned
    secret = serializers.CharField(write_only=True, required=False, allow_blank=True, trim_whitespace=False,
                                   style={"input_type": "password"})
    enable_secret = serializers.CharField(write_only=True, required=False, allow_blank=True, trim_whitespace=False,
                                          style={"input_type": "password"})
    auth_key = serializers.CharField(write_only=True, required=False, allow_blank=True, trim_whitespace=False,
                                     style={"input_type": "password"})
    priv_key = serializers.CharField(write_only=True, required=False, allow_blank=True, trim_whitespace=False,
                                     style={"input_type": "password"})
    private_key = serializers.CharField(write_only=True, required=False, allow_blank=True, trim_whitespace=False)
    has_secret = serializers.BooleanField(read_only=True)
    has_private_key = serializers.BooleanField(read_only=True)

    class Meta:
        model = CredentialProfile
        fields = ("id", "url", "display_url", "display", "name", "kind", "priority", "port", "username",
                  "snmp_auth_protocol", "snmp_priv_protocol", "options", "secret", "enable_secret", "auth_key",
                  "priv_key", "private_key", "has_secret", "has_private_key", "description", "owner", "comments",
                  "tags", "custom_fields", "created", "last_updated")
        brief_fields = ("id", "url", "display", "name", "kind", "description")

    def _apply_secrets(self, instance, secrets):
        for field_name, value in secrets.items():
            setattr(instance, field_name, value)

    def create(self, validated_data):
        secrets = {k: validated_data.pop(k) for k in SECRET_FIELDS if k in validated_data}
        instance = CredentialProfile(**{k: v for k, v in validated_data.items() if k not in ("tags",)})
        self._apply_secrets(instance, secrets)
        tags = validated_data.get("tags")
        instance.full_clean()
        instance.save()
        if tags is not None:
            instance.tags.set(tags)
        return instance

    def update(self, instance, validated_data):
        secrets = {k: validated_data.pop(k) for k in SECRET_FIELDS if k in validated_data}
        self._apply_secrets(instance, secrets)
        return super().update(instance, validated_data)


class ScanTargetSerializer(PrimaryModelSerializer):
    site = SiteSerializer(nested=True, required=False, allow_null=True)
    location = LocationSerializer(nested=True, required=False, allow_null=True)
    tenant = TenantSerializer(nested=True, required=False, allow_null=True)
    vrf = VRFSerializer(nested=True, required=False, allow_null=True)
    default_role = DeviceRoleSerializer(nested=True, required=False, allow_null=True)
    credentials = CredentialProfileSerializer(nested=True, many=True, required=False)
    scan_profile = ChoiceField(choices=ScanProfileChoices, required=False)
    sync_mode = ChoiceField(choices=SyncModeChoices, required=False)

    class Meta:
        model = ScanTarget
        fields = ("id", "url", "display_url", "display", "name", "enabled", "targets", "exclusions", "site",
                  "location", "tenant", "vrf", "default_role", "device_status", "scan_profile", "custom_nmap_args",
                  "snmp_enabled", "ssh_enabled", "collect_neighbors", "collect_arp", "credentials", "sync_mode",
                  "stale_threshold", "deprecate_stale_ips", "interval", "description", "owner", "comments", "tags",
                  "custom_fields", "created", "last_updated")
        brief_fields = ("id", "url", "display", "name", "description")

    def create(self, validated_data):
        credentials = validated_data.pop("credentials", None)
        instance = super().create(validated_data)
        if credentials is not None:
            instance.credentials.set(credentials)
        return instance

    def update(self, instance, validated_data):
        credentials = validated_data.pop("credentials", None)
        instance = super().update(instance, validated_data)
        if credentials is not None:
            instance.credentials.set(credentials)
        return instance


class RoleRuleSerializer(NetBoxModelSerializer):
    role = DeviceRoleSerializer(nested=True)
    platform = ChoiceField(choices=PlatformKeyChoices, required=False, allow_blank=True)
    scan_targets = ScanTargetSerializer(nested=True, many=True, required=False)

    class Meta:
        model = RoleRule
        fields = ("id", "url", "display_url", "display", "name", "enabled", "weight", "role", "hostname_regex",
                  "sys_descr_regex", "sys_object_id_prefix", "platform", "manufacturer_regex", "model_regex",
                  "mac_vendor_regex", "open_ports", "scan_targets", "description", "tags", "custom_fields",
                  "created", "last_updated")
        brief_fields = ("id", "url", "display", "name", "description")


class DeviceTypeAliasSerializer(NetBoxModelSerializer):
    match_type = ChoiceField(choices=MatchTypeChoices, required=False)
    manufacturer = ManufacturerSerializer(nested=True, required=False, allow_null=True)
    device_type = DeviceTypeSerializer(nested=True)

    class Meta:
        model = DeviceTypeAlias
        fields = ("id", "url", "display_url", "display", "reported_model", "match_type", "manufacturer",
                  "device_type", "weight", "description", "tags", "custom_fields", "created", "last_updated")
        brief_fields = ("id", "url", "display", "reported_model", "device_type")


class ProposedChangeSerializer(NetBoxModelSerializer):
    kind = ChoiceField(choices=ProposalKindChoices, read_only=True)
    status = ChoiceField(choices=ProposalStatusChoices, read_only=True)
    scan_target = ScanTargetSerializer(nested=True, read_only=True)
    object_type = serializers.SerializerMethodField(read_only=True)
    decided_by = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = ProposedChange
        fields = ("id", "url", "display_url", "display", "kind", "status", "summary", "scan_target", "job",
                  "object_type", "object_id", "fingerprint", "data", "diff", "overrides", "decided_by", "decided_at",
                  "error", "tags", "custom_fields", "created", "last_updated")
        read_only_fields = ("summary", "job", "object_id", "fingerprint", "data", "diff", "decided_at", "error")
        brief_fields = ("id", "url", "display", "kind", "status", "summary")

    def get_object_type(self, obj) -> str | None:
        return f"{obj.object_type.app_label}.{obj.object_type.model}" if obj.object_type_id else None

    def validate_overrides(self, value):
        allowed = {"name", "site", "location", "role", "device_type", "platform", "tenant", "status"}
        if not isinstance(value, dict) or set(value) - allowed:
            raise serializers.ValidationError(f"Overrides must be an object with keys from {sorted(allowed)}")
        return value


class DiscoveredHostSerializer(NetBoxModelSerializer):
    vrf = VRFSerializer(nested=True, read_only=True)
    scan_target = ScanTargetSerializer(nested=True, read_only=True)
    device = DeviceSerializer(nested=True, read_only=True)
    ip_address = IPAddressSerializer(nested=True, read_only=True)

    class Meta:
        model = DiscoveredHost
        fields = ("id", "url", "display_url", "display", "address", "vrf", "scan_target", "source", "hostname",
                  "dns_name", "mac_address", "mac_vendor", "os_guess", "open_ports", "platform", "methods", "device",
                  "ip_address", "first_seen", "last_seen", "miss_count", "is_stale", "data", "tags",
                  "custom_fields", "created", "last_updated")
        read_only_fields = fields
        brief_fields = ("id", "url", "display", "address", "hostname")


class RunScanSerializer(serializers.Serializer):
    address = serializers.IPAddressField(required=False, help_text="Rediscover a single address instead")


class DecisionSerializer(serializers.Serializer):
    ids = serializers.ListField(child=serializers.IntegerField(), required=False)
    reason = serializers.CharField(required=False, allow_blank=True)
