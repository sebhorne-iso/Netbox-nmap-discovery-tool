from django.utils.translation import gettext_lazy as _
from utilities.choices import ChoiceSet

from .engine.nmap import SCAN_PROFILES
from .engine.platforms import PLATFORMS


class CredentialKindChoices(ChoiceSet):
    SNMP_V2C = "snmp-v2c"
    SNMP_V3 = "snmp-v3"
    SSH = "ssh"

    CHOICES = (
        (SNMP_V2C, _("SNMP v2c"), "blue"),
        (SNMP_V3, _("SNMP v3"), "indigo"),
        (SSH, _("SSH"), "teal"),
    )


class SnmpAuthProtocolChoices(ChoiceSet):
    CHOICES = (
        ("none", _("None")),
        ("md5", "MD5"),
        ("sha", "SHA-1"),
        ("sha224", "SHA-224"),
        ("sha256", "SHA-256"),
        ("sha384", "SHA-384"),
        ("sha512", "SHA-512"),
    )


class SnmpPrivProtocolChoices(ChoiceSet):
    CHOICES = (
        ("none", _("None")),
        ("des", "DES"),
        ("3des", "3DES"),
        ("aes128", "AES-128"),
        ("aes192", "AES-192"),
        ("aes256", "AES-256"),
    )


class ScanProfileChoices(ChoiceSet):
    CUSTOM = "custom"

    CHOICES = tuple((key, spec["label"]) for key, spec in SCAN_PROFILES.items()) + (
        (CUSTOM, _("Custom nmap arguments")),
    )


class SyncModeChoices(ChoiceSet):
    HYBRID = "hybrid"
    REVIEW = "review"
    AUTOMATIC = "automatic"

    CHOICES = (
        (HYBRID, _("Hybrid: auto-update existing objects, review new devices & cables"), "blue"),
        (REVIEW, _("Review everything"), "orange"),
        (AUTOMATIC, _("Fully automatic"), "red"),
    )


class ProposalKindChoices(ChoiceSet):
    CREATE_DEVICE = "create-device"
    UPDATE_DEVICE = "update-device"
    CREATE_CABLE = "create-cable"
    CREATE_IP = "create-ip"
    UPDATE_IP = "update-ip"

    CHOICES = (
        (CREATE_DEVICE, _("New device"), "green"),
        (UPDATE_DEVICE, _("Device update"), "blue"),
        (CREATE_CABLE, _("New cable"), "purple"),
        (CREATE_IP, _("New IP address"), "teal"),
        (UPDATE_IP, _("IP address update"), "cyan"),
    )


class ProposalStatusChoices(ChoiceSet):
    PENDING = "pending"
    APPLIED = "applied"
    REJECTED = "rejected"
    FAILED = "failed"
    SUPERSEDED = "superseded"

    CHOICES = (
        (PENDING, _("Pending"), "yellow"),
        (APPLIED, _("Applied"), "green"),
        (REJECTED, _("Rejected"), "gray"),
        (FAILED, _("Failed"), "red"),
        (SUPERSEDED, _("Superseded"), "light-gray"),
    )


class MatchTypeChoices(ChoiceSet):
    EXACT = "exact"
    REGEX = "regex"

    CHOICES = (
        (EXACT, _("Exact (case-insensitive)")),
        (REGEX, _("Regular expression")),
    )


class PlatformKeyChoices(ChoiceSet):
    CHOICES = tuple((key, spec.name) for key, spec in PLATFORMS.items())


class HostSourceChoices(ChoiceSet):
    CHOICES = (
        ("nmap", _("nmap"), "blue"),
        ("arp", _("ARP table"), "orange"),
        ("lldp", _("LLDP/CDP neighbour"), "purple"),
        ("manual", _("Rediscovery"), "gray"),
    )
