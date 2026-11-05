import pytest

from netbox_nmap_discovery.engine.interfaces import guess_interface_type, is_management_interface
from netbox_nmap_discovery.engine.platforms import detect_platform, normalize_manufacturer
from netbox_nmap_discovery.engine.results import DeviceFacts, DiscoveredInterface, HostResult, NmapHost, OpenPort
from netbox_nmap_discovery.engine.utils import (
    address_in_networks,
    canonical_interface_name,
    is_usable_mac,
    normalize_mac,
    parse_target_networks,
    short_hostname,
)


@pytest.mark.parametrize("value,expected", [
    (b"\x00\x11\x22\x33\x44\x55", "00:11:22:33:44:55"),
    ("0011.2233.4455", "00:11:22:33:44:55"),
    ("00-11-22-33-44-55", "00:11:22:33:44:55"),
    ("0:1b:2c:3:4:5", "00:1B:2C:03:04:05"),
    ("9020c2-a1b2c3", "90:20:C2:A1:B2:C3"),
    ("0x001122334455", "00:11:22:33:44:55"),
    (b"\x00\x11", None),
    ("not-a-mac", None),
    (None, None),
])
def test_normalize_mac(value, expected):
    assert normalize_mac(value) == expected


@pytest.mark.parametrize("mac,usable", [
    ("00:11:22:33:44:55", True),
    ("00:00:0C:07:AC:0A", False),  # HSRP
    ("00:00:5E:00:01:01", False),  # VRRP
    ("01:00:5E:00:00:01", False),  # multicast
    ("00:00:00:00:00:00", False),
    (None, False),
])
def test_usable_mac(mac, usable):
    assert is_usable_mac(mac) is usable


@pytest.mark.parametrize("a,b", [
    ("Gi1/0/1", "GigabitEthernet1/0/1"),
    ("Te1/1/1", "TenGigabitEthernet1/1/1"),
    ("Po10", "Port-channel10"),
    ("Eth1/49", "Ethernet1/49"),
    ("Et1", "Ethernet1"),
    ("ge-0/0/0", "GE-0/0/0"),
    ("GigabitEthernet 1/0/1", "GigabitEthernet1/0/1"),
])
def test_canonical_interface_names_match(a, b):
    assert canonical_interface_name(a) == canonical_interface_name(b)


def test_junos_et_is_not_cisco_ethernet():
    assert canonical_interface_name("et-0/0/0") != canonical_interface_name("Ethernet0/0/0")


@pytest.mark.parametrize("name,if_type,speed,expected", [
    ("Port-channel1", 53, None, "lag"),
    ("ae0", None, None, "lag"),
    ("Vlan10", 53, None, "virtual"),
    ("Loopback0", 24, None, "virtual"),
    ("GigabitEthernet0/0.100", None, None, "virtual"),
    ("TenGigabitEthernet1/1/1", 6, None, "10gbase-x-sfpp"),
    ("xe-0/0/1", 6, None, "10gbase-x-sfpp"),
    ("Ethernet1", 6, 25_000_000, "25gbase-x-sfp28"),
    ("eth0", 6, None, "1000base-t"),
    ("port1", 6, 1_000_000, "1000base-t"),
    ("wlan0", 71, None, "ieee802.11ac"),
    ("weird", None, None, "other"),
])
def test_guess_interface_type(name, if_type, speed, expected):
    assert guess_interface_type(name, if_type, speed) == expected


def test_management_interfaces():
    assert is_management_interface("mgmt0") and is_management_interface("fxp0")
    assert not is_management_interface("GigabitEthernet1/0/1")


@pytest.mark.parametrize("kwargs,expected", [
    ({"sys_object_id": "1.3.6.1.4.1.9.1.2494", "sys_descr": "Cisco IOS Software [Cupertino], IOS-XE"}, "cisco_xe"),
    ({"sys_object_id": "1.3.6.1.4.1.9.12.3.1.3.1812", "sys_descr": "Cisco NX-OS(tm) n9000"}, "cisco_nxos"),
    ({"sys_object_id": "1.3.6.1.4.1.9.1.1208", "sys_descr": "Cisco IOS Software, C2960X Software"}, "cisco_ios"),
    ({"sys_object_id": ".1.3.6.1.4.1.2636.1.1.1.2.132"}, "juniper_junos"),
    ({"sys_object_id": "1.3.6.1.4.1.30065.1.3011.7050"}, "arista_eos"),
    ({"sys_object_id": "1.3.6.1.4.1.12356.101.1.1004"}, "fortinet_fortios"),
    ({"sys_object_id": "1.3.6.1.4.1.25461.2.3.18"}, "paloalto_panos"),
    ({"sys_object_id": "1.3.6.1.4.1.47196.4.1.1.1.200"}, "aruba_aoscx"),
    ({"sys_object_id": "1.3.6.1.4.1.11.2.3.7.11.181"}, "hp_procurve"),
    ({"sys_object_id": "1.3.6.1.4.1.311.1.1.3.1.2"}, "windows"),
    ({"sys_object_id": "1.3.6.1.4.1.8072.3.2.10", "sys_descr": "Linux host 6.1"}, "linux"),
    ({"sys_descr": "Arista Networks EOS version 4.28"}, "arista_eos"),
    ({"ssh_banner": "Cisco SSH 1.25"}, "cisco_ios"),
    ({"nmap_os": "Linux 5.0 - 5.7"}, "linux"),
    ({}, None),
])
def test_detect_platform(kwargs, expected):
    assert detect_platform(**kwargs) == expected


@pytest.mark.parametrize("raw,expected", [
    ("Cisco Systems Inc.", "Cisco"), ("Juniper Networks", "Juniper"), ("Hewlett Packard Enterprise", "HPE"),
    ("HPE Aruba Networking", "Aruba"), ("Dell Inc.", "Dell"), ("Acme Networks, Inc.", "Acme"), (None, None),
])
def test_normalize_manufacturer(raw, expected):
    assert normalize_manufacturer(raw) == expected


def test_manufacturer_alias_override():
    assert normalize_manufacturer("Cisco Systems", {"cisco systems": "Cisco Systems Inc"}) == "Cisco Systems Inc"


def test_short_hostname():
    assert short_hostname("SW1.example.com.") == "sw1"
    assert short_hostname("N9K-2(FDO12345678)") == "n9k-2"
    assert short_hostname("10.0.0.1") == "10.0.0.1"
    assert short_hostname(None) is None


def test_target_networks():
    networks = parse_target_networks(["10.0.0.0/24", "10.0.1.10-20", "# comment", "host.example.com", "10.0.2.5"])
    assert address_in_networks("10.0.0.200", networks)
    assert address_in_networks("10.0.1.15", networks) and not address_in_networks("10.0.1.21", networks)
    assert address_in_networks("10.0.2.5/32", networks)
    assert not address_in_networks("2001:db8::1", networks)


def test_host_result_round_trip():
    host = HostResult(
        address="10.0.0.1",
        nmap=NmapHost(address="10.0.0.1", hostnames=["a.example.com"], ports=[OpenPort(22)], ports_scanned=True),
        facts=DeviceFacts(hostname="a", serial="X"),
        interfaces=[DiscoveredInterface(name="eth0", ip_addresses=["10.0.0.1/24"], mac_address="00:11:22:33:44:55")],
        methods=["snmp"],
    )
    restored = HostResult.from_dict(host.to_dict())
    assert restored == host
    assert restored.managed and restored.dns_name == "a.example.com"
    assert restored.interface_for_address("10.0.0.1").name == "eth0"
    assert restored.all_macs() == {"00:11:22:33:44:55"}


def test_facts_merge_prefers_other():
    merged = DeviceFacts(hostname="a", model="X", serial=None).merge(DeviceFacts(model="Y", serial="S", vendor=""))
    assert (merged.hostname, merged.model, merged.serial, merged.vendor) == ("a", "Y", "S", None)
