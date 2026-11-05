import django_tables2 as tables
from django.utils.translation import gettext_lazy as _
from netbox.tables import NetBoxTable, PrimaryModelTable, columns

from .models import CredentialProfile, DeviceTypeAlias, DiscoveredHost, ProposedChange, RoleRule, ScanTarget

__all__ = (
    "CredentialProfileTable",
    "DeviceTypeAliasTable",
    "DiscoveredHostTable",
    "ProposedChangeTable",
    "RoleRuleTable",
    "ScanTargetTable",
)


class CredentialProfileTable(PrimaryModelTable):
    name = tables.Column(linkify=True)
    kind = columns.ChoiceFieldColumn()
    has_secret = columns.BooleanColumn(verbose_name=_("Secret set"), orderable=False)
    scan_target_count = columns.LinkedCountColumn(
        viewname="plugins:netbox_nmap_discovery:scantarget_list", url_params={"credential_id": "pk"},
        verbose_name=_("Scan targets"),
    )
    tags = columns.TagColumn(url_name="plugins:netbox_nmap_discovery:credentialprofile_list")

    class Meta(PrimaryModelTable.Meta):
        model = CredentialProfile
        fields = ("pk", "id", "name", "kind", "priority", "port", "username", "snmp_auth_protocol",
                  "snmp_priv_protocol", "has_secret", "scan_target_count", "description", "tags", "created",
                  "last_updated")
        default_columns = ("pk", "name", "kind", "priority", "username", "has_secret", "scan_target_count",
                           "description")


class ScanTargetTable(PrimaryModelTable):
    name = tables.Column(linkify=True)
    enabled = columns.BooleanColumn()
    targets = tables.TemplateColumn(
        template_code="{{ record.target_list|join:', '|truncatechars:60 }}", orderable=False,
    )
    site = tables.Column(linkify=True)
    tenant = tables.Column(linkify=True)
    vrf = tables.Column(linkify=True, verbose_name=_("VRF"))
    default_role = tables.Column(linkify=True)
    sync_mode = columns.ChoiceFieldColumn()
    scan_profile = columns.ChoiceFieldColumn()
    snmp_enabled = columns.BooleanColumn(verbose_name=_("SNMP"))
    ssh_enabled = columns.BooleanColumn(verbose_name=_("SSH"))
    collect_neighbors = columns.BooleanColumn(verbose_name=_("Neighbours"))
    interval = tables.Column(verbose_name=_("Interval (min)"))
    host_count = columns.LinkedCountColumn(
        viewname="plugins:netbox_nmap_discovery:discoveredhost_list", url_params={"scan_target_id": "pk"},
        verbose_name=_("Hosts"),
    )
    pending_count = tables.TemplateColumn(
        template_code=(
            "{% if value %}<a href=\"{% url 'plugins:netbox_nmap_discovery:proposedchange_list' %}"
            "?scan_target_id={{ record.pk }}&status=pending\">{{ value }}</a>{% else %}{{ value }}{% endif %}"
        ),
        verbose_name=_("Pending"),
    )
    tags = columns.TagColumn(url_name="plugins:netbox_nmap_discovery:scantarget_list")

    class Meta(PrimaryModelTable.Meta):
        model = ScanTarget
        fields = ("pk", "id", "name", "enabled", "targets", "site", "tenant", "vrf", "default_role", "sync_mode",
                  "scan_profile", "snmp_enabled", "ssh_enabled", "collect_neighbors", "interval", "stale_threshold",
                  "host_count", "pending_count", "description", "tags", "created", "last_updated")
        default_columns = ("pk", "name", "enabled", "targets", "site", "sync_mode", "scan_profile", "interval",
                           "host_count", "pending_count")


class RoleRuleTable(NetBoxTable):
    name = tables.Column(linkify=True)
    enabled = columns.BooleanColumn()
    role = tables.Column(linkify=True)
    platform = columns.ChoiceFieldColumn()
    tags = columns.TagColumn(url_name="plugins:netbox_nmap_discovery:rolerule_list")

    class Meta(NetBoxTable.Meta):
        model = RoleRule
        fields = ("pk", "id", "name", "enabled", "weight", "role", "hostname_regex", "sys_descr_regex",
                  "sys_object_id_prefix", "platform", "manufacturer_regex", "model_regex", "mac_vendor_regex",
                  "open_ports", "description", "tags", "created", "last_updated")
        default_columns = ("pk", "name", "enabled", "weight", "role", "hostname_regex", "platform", "open_ports",
                           "description")


class DeviceTypeAliasTable(NetBoxTable):
    reported_model = tables.Column(linkify=True)
    match_type = columns.ChoiceFieldColumn()
    manufacturer = tables.Column(linkify=True)
    device_type = tables.Column(linkify=True)
    tags = columns.TagColumn(url_name="plugins:netbox_nmap_discovery:devicetypealias_list")

    class Meta(NetBoxTable.Meta):
        model = DeviceTypeAlias
        fields = ("pk", "id", "reported_model", "match_type", "manufacturer", "device_type", "weight", "description",
                  "tags", "created", "last_updated")
        default_columns = ("pk", "reported_model", "match_type", "manufacturer", "device_type", "weight")


class ProposedChangeTable(NetBoxTable):
    summary = tables.Column(linkify=True)
    kind = columns.ChoiceFieldColumn()
    status = columns.ChoiceFieldColumn()
    scan_target = tables.Column(linkify=True)
    object = tables.Column(linkify=True, orderable=False, verbose_name=_("Object"))
    change_count = tables.TemplateColumn(template_code="{{ record.diff|length }}", orderable=False,
                                         verbose_name=_("Changes"))
    decided_by = tables.Column()
    actions = columns.ActionsColumn(actions=("edit", "delete"))

    class Meta(NetBoxTable.Meta):
        model = ProposedChange
        fields = ("pk", "id", "summary", "kind", "status", "scan_target", "object", "change_count", "error",
                  "decided_by", "decided_at", "created", "last_updated")
        default_columns = ("pk", "summary", "kind", "status", "scan_target", "change_count", "last_updated")


class DiscoveredHostTable(NetBoxTable):
    address = tables.Column(linkify=True)
    vrf = tables.Column(linkify=True, verbose_name=_("VRF"))
    scan_target = tables.Column(linkify=True)
    source = columns.ChoiceFieldColumn()
    platform = columns.ChoiceFieldColumn()
    methods = columns.ArrayColumn(orderable=False)
    device = tables.Column(linkify=True)
    ip_address = tables.Column(linkify=True, verbose_name=_("IP address"))
    open_ports = tables.TemplateColumn(template_code="{{ record.open_ports_display|truncatechars:60 }}",
                                       orderable=False)
    is_stale = columns.BooleanColumn(verbose_name=_("Stale"))
    actions = columns.ActionsColumn(actions=("delete",))

    class Meta(NetBoxTable.Meta):
        model = DiscoveredHost
        fields = ("pk", "id", "address", "vrf", "hostname", "dns_name", "mac_address", "mac_vendor", "os_guess",
                  "open_ports", "platform", "methods", "device", "ip_address", "scan_target", "source", "first_seen",
                  "last_seen", "miss_count", "is_stale")
        default_columns = ("pk", "address", "hostname", "mac_address", "mac_vendor", "os_guess", "methods", "device",
                           "last_seen", "is_stale")
