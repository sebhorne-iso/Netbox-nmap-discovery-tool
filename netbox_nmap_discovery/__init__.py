"""
NetBox Network Discovery plugin.

Discovers hosts with nmap, enriches them over SNMP and SSH (NAPALM / Netmiko), and synchronises the
results into NetBox DCIM and IPAM, with a review queue for new devices and cables.

The ``engine`` sub-package has no dependency on NetBox or Django so that it can be unit tested and reused
on its own; the plugin configuration below is therefore only defined when NetBox is importable.
"""

__version__ = "0.1.1"

try:
    from netbox.plugins import PluginConfig
except ImportError:  # pragma: no cover - NetBox is not installed (standalone engine use / unit tests)
    PluginConfig = None


DEFAULT_SETTINGS = {
    # nmap
    "nmap_path": "nmap",
    # None = auto-detect (root or NMAP_PRIVILEGED env var), True = assume raw-socket privileges, False = never
    "nmap_privileged": None,
    "nmap_timeout": 3600,
    # SNMP / SSH
    "snmp_timeout": 2,
    "snmp_retries": 1,
    "ssh_timeout": 30,
    "ssh_autodetect": True,
    "max_workers": 16,
    # Username used for change-log attribution when a scheduled job has no user
    "scheduled_job_user": None,
    # Encryption key(s) for stored credentials. A string or a list of strings (first = current key, the rest
    # are accepted for decryption during key rotation). Falls back to the NETBOX_DISCOVERY_ENCRYPTION_KEY
    # environment variable, then to a key derived from SECRET_KEY.
    "encryption_key": None,
    # Synchronisation behaviour
    # Interfaces matching this regex are never synchronised (pseudo / container / internal interfaces)
    "interface_exclude_regex": (
        r"^(lo|ifb\d+|Null\d*|nve\d+|sit\d+|docker\d+|veth[0-9a-f]+|br-[0-9a-f]{12}|virbr\d+(-nic)?|"
        r"tunl0|ip6tnl0|ip6gre0|gre0|gretap0|erspan0|ip_vti0|ip6_vti0|"
        r"EOBC\d*/?\d*|Embedded-Service-Engine.*|StackPort\d+|StackSub.*)$"
    ),
    "overwrite_interface_descriptions": True,
    "last_seen_update_hours": 24,
    "poll_lldp_neighbors": True,
    "manufacturer_aliases": {},
    "device_type_u_height": 1,
    # Interface created when promoting a host that only nmap could see to a device
    "promoted_interface_name": "eth0",
}


if PluginConfig is not None:

    class NetBoxDiscoveryConfig(PluginConfig):
        name = "netbox_nmap_discovery"
        verbose_name = "Network Discovery"
        description = "Discover devices with nmap, SNMP and SSH and synchronise them into NetBox DCIM and IPAM."
        version = __version__
        author = "sebhorne-iso"
        base_url = "discovery"
        min_version = "4.5.0"
        max_version = "4.7.99"
        default_settings = DEFAULT_SETTINGS
        required_settings = []

        def ready(self):
            super().ready()
            from . import jobs, signals  # noqa: F401  (registers job runners and signal handlers)

            signals.connect_post_migrate(self)

    config = NetBoxDiscoveryConfig
