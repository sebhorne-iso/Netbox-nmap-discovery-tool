# netbox-docker loads every *.py file in /etc/netbox/config, so this file only needs to define the plugin settings.
from os import environ

PLUGINS = [
    "netbox_nmap_discovery",
]

PLUGINS_CONFIG = {
    "netbox_nmap_discovery": {
        # Read from NETBOX_DISCOVERY_ENCRYPTION_KEY when unset. Use a list [new, old] to rotate keys, then run
        #   docker compose exec netbox /opt/netbox/netbox/manage.py discovery_rotate_key
        "encryption_key": environ.get("NETBOX_DISCOVERY_ENCRYPTION_KEY"),
        # None = auto (root or NMAP_PRIVILEGED=1). False forces unprivileged TCP-connect scans without OS detection.
        "nmap_privileged": None,
        "snmp_timeout": 2,
        "snmp_retries": 1,
        "ssh_timeout": 30,
        "max_workers": 16,
        # Account used for change-log attribution of scheduled scans created without a user
        "scheduled_job_user": environ.get("NETBOX_DISCOVERY_JOB_USER"),
        # "manufacturer_aliases": {"Cisco Systems, Inc.": "Cisco"},
    },
}
