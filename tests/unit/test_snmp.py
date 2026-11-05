import pytest

from netbox_nmap_discovery.engine import snmp as s
from netbox_nmap_discovery.engine.snmp import SnmpError, collect_snmp, parse_os_version


class FakeAgent:
    """Answers get/walk from a static {oid: value} map, like an SNMP agent would."""

    def __init__(self, data):
        self.data = data

    def get(self, oids):
        return {o: self.data[o] for o in oids if o in self.data}

    def walk(self, oid):
        return {k: v for k, v in self.data.items() if k.startswith(oid + ".")}


def mac(text):
    return bytes(int(x, 16) for x in text.split(":"))


def cisco_switch():
    d = {
        s.SYS_DESCR: b"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4, "
                     b"RELEASE SOFTWARE (fc5)",
        s.SYS_OBJECT_ID: "1.3.6.1.4.1.9.1.2494",
        s.SYS_NAME: b"sw1.example.com",
        s.SYS_LOCATION: b"HQ Rack 4",
    }
    ifaces = {
        1: ("GigabitEthernet1/0/1", "Gi1/0/1", 6, 1000, "00:11:22:33:44:01", 1, 1, b"uplink to sw2"),
        2: ("GigabitEthernet1/0/2", "Gi1/0/2", 6, 1000, "00:11:22:33:44:02", 1, 1, b""),
        3: ("Vlan10", "Vl10", 53, 1000, "00:11:22:33:44:00", 1, 1, b"users"),
        4: ("Port-channel1", "Po1", 53, 2000, "00:11:22:33:44:03", 1, 1, b""),
        5: ("Null0", "Nu0", 1, 0, None, 1, 1, b""),
    }
    for idx, (descr, name, iftype, high, phys, admin, oper, alias) in ifaces.items():
        d[f"{s.IF_DESCR}.{idx}"] = descr.encode()
        d[f"{s.IF_NAME}.{idx}"] = name.encode()
        d[f"{s.IF_TYPE}.{idx}"] = iftype
        d[f"{s.IF_HIGH_SPEED}.{idx}"] = high
        d[f"{s.IF_MTU}.{idx}"] = 1500
        d[f"{s.IF_PHYS_ADDRESS}.{idx}"] = mac(phys) if phys else b""
        d[f"{s.IF_ADMIN_STATUS}.{idx}"] = admin
        d[f"{s.IF_OPER_STATUS}.{idx}"] = oper
        d[f"{s.IF_ALIAS}.{idx}"] = alias
    d[f"{s.IP_AD_ENT_IF_INDEX}.10.0.0.1"] = 3
    d[f"{s.IP_AD_ENT_NETMASK}.10.0.0.1"] = "255.255.255.0"
    d[f"{s.IP_AD_ENT_IF_INDEX}.127.0.0.1"] = 5  # loopback ignored
    v6 = "2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1"  # 2001:db8::1
    d[f"{s.IP_ADDRESS_IF_INDEX}.{v6}"] = 3
    d[f"{s.IP_ADDRESS_TYPE}.{v6}"] = 1
    d[f"{s.IP_ADDRESS_PREFIX}.{v6}"] = "1.3.6.1.2.1.4.32.1.5.3.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.0.64"
    d[f"{s.DOT3AD_AGG_PORT_ATTACHED_AGG_ID}.1"] = 4
    d[f"{s.DOT3AD_AGG_PORT_ATTACHED_AGG_ID}.2"] = 4
    d[f"{s.ENT_PHYSICAL_CLASS}.1"] = 3
    d[f"{s.ENT_PHYSICAL_CLASS}.1000"] = 9  # module
    d[f"{s.ENT_PHYSICAL_CONTAINED_IN}.1"] = 0
    d[f"{s.ENT_PHYSICAL_SERIAL}.1"] = b"FOC1111A1AA"
    d[f"{s.ENT_PHYSICAL_MODEL_NAME}.1"] = b"C9300-48P"
    d[f"{s.ENT_PHYSICAL_MFG_NAME}.1"] = b"Cisco Systems Inc."
    # LLDP: neighbour sw2 on local port 1 (port id = interface name)
    d[f"{s.LLDP_LOC_PORT_ID_SUBTYPE}.1"] = 5
    d[f"{s.LLDP_LOC_PORT_ID}.1"] = b"Gi1/0/1"
    d[f"{s.LLDP_LOC_PORT_DESC}.1"] = b"GigabitEthernet1/0/1"
    d[f"{s.LLDP_REM_SYS_NAME}.0.1.1"] = b"sw2.example.com"
    d[f"{s.LLDP_REM_PORT_ID_SUBTYPE}.0.1.1"] = 5
    d[f"{s.LLDP_REM_PORT_ID}.0.1.1"] = b"Gi1/0/49"
    d[f"{s.LLDP_REM_PORT_DESC}.0.1.1"] = b"GigabitEthernet1/0/49"
    d[f"{s.LLDP_REM_CHASSIS_ID_SUBTYPE}.0.1.1"] = 4
    d[f"{s.LLDP_REM_CHASSIS_ID}.0.1.1"] = mac("00:11:22:33:55:00")
    d[f"{s.LLDP_REM_MAN_ADDR_IF_SUBTYPE}.0.1.1.1.4.10.0.0.2"] = 2
    # CDP: same neighbour
    d[f"{s.CDP_CACHE_DEVICE_ID}.1.7"] = b"sw2.example.com"
    d[f"{s.CDP_CACHE_DEVICE_PORT}.1.7"] = b"GigabitEthernet1/0/49"
    d[f"{s.CDP_CACHE_ADDRESS_TYPE}.1.7"] = 1
    d[f"{s.CDP_CACHE_ADDRESS}.1.7"] = bytes([10, 0, 0, 2])
    d[f"{s.CDP_CACHE_PLATFORM}.1.7"] = b"cisco C9300-48P"
    # ARP
    d[f"{s.IP_NET_TO_MEDIA_PHYS_ADDRESS}.3.10.0.0.50"] = mac("aa:bb:cc:00:00:50")
    d[f"{s.IP_NET_TO_MEDIA_TYPE}.3.10.0.0.50"] = 3
    d[f"{s.IP_NET_TO_MEDIA_PHYS_ADDRESS}.3.10.0.0.51"] = mac("aa:bb:cc:00:00:51")
    d[f"{s.IP_NET_TO_MEDIA_TYPE}.3.10.0.0.51"] = 2  # invalid entry ignored
    return d


def test_cisco_facts_and_interfaces():
    result = collect_snmp(FakeAgent(cisco_switch()))
    facts = result.facts
    assert (facts.hostname, facts.fqdn) == ("sw1", "sw1.example.com")
    assert facts.platform == "cisco_xe"
    assert (facts.vendor, facts.model, facts.serial) == ("Cisco", "C9300-48P", "FOC1111A1AA")
    assert facts.os_version == "17.9.4"
    assert facts.sys_location == "HQ Rack 4"
    by_name = {i.name: i for i in result.interfaces}
    # Cisco: long ifDescr names are used
    assert set(by_name) == {"GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "Vlan10", "Port-channel1", "Null0"}
    gi1 = by_name["GigabitEthernet1/0/1"]
    assert (gi1.type, gi1.speed_kbps, gi1.mac_address, gi1.description) == (
        "1000base-t", 1_000_000, "00:11:22:33:44:01", "uplink to sw2")
    assert gi1.lag == "Port-channel1"
    assert by_name["Port-channel1"].type == "lag"
    assert by_name["Vlan10"].type == "virtual"
    assert by_name["Vlan10"].ip_addresses == ["10.0.0.1/24", "2001:db8::1/64"]
    assert by_name["Null0"].ip_addresses == []


def test_neighbors_and_arp():
    result = collect_snmp(FakeAgent(cisco_switch()))
    lldp = [n for n in result.neighbors if n.protocol == "lldp"]
    cdp = [n for n in result.neighbors if n.protocol == "cdp"]
    assert len(lldp) == 1 and len(cdp) == 1
    assert lldp[0].local_interface == "GigabitEthernet1/0/1"
    assert (lldp[0].remote_name, lldp[0].remote_interface) == ("sw2.example.com", "Gi1/0/49")
    assert lldp[0].remote_chassis_id == "00:11:22:33:55:00"
    assert lldp[0].remote_mgmt_address == "10.0.0.2"
    assert (cdp[0].local_interface, cdp[0].remote_mgmt_address) == ("GigabitEthernet1/0/1", "10.0.0.2")
    assert [(a.ip_address, a.mac_address, a.interface) for a in result.arp] == [
        ("10.0.0.50", "AA:BB:CC:00:00:50", "Vlan10")]


def test_collection_flags():
    result = collect_snmp(FakeAgent(cisco_switch()), collect_neighbors=False, collect_arp=False)
    assert result.neighbors == [] and result.arp == []


def test_no_response():
    with pytest.raises(SnmpError):
        collect_snmp(FakeAgent({}))


def test_linux_net_snmp_uses_ifname():
    data = {
        s.SYS_DESCR: b"Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64",
        s.SYS_OBJECT_ID: "1.3.6.1.4.1.8072.3.2.10",
        s.SYS_NAME: b"web01",
        f"{s.IF_DESCR}.2": b"Intel Corporation Ethernet Controller",
        f"{s.IF_NAME}.2": b"ens192",
        f"{s.IF_TYPE}.2": 6,
    }
    result = collect_snmp(FakeAgent(data))
    assert result.facts.platform == "linux"
    assert result.facts.os_version == "5.15.0-91-generic"
    assert [i.name for i in result.interfaces] == ["ens192"]


def test_juniper_vendor_scalars():
    data = {
        s.SYS_DESCR: b"Juniper Networks, Inc. ex2300-24p Ethernet Switch, kernel JUNOS 21.4R3-S1.6",
        s.SYS_OBJECT_ID: "1.3.6.1.4.1.2636.1.1.1.2.132",
        s.SYS_NAME: b"ex1",
        s.JNX_BOX_SERIAL: b"JW3619AN0000",
        s.JNX_BOX_DESCR: b"Juniper EX2300-24P Switch",
    }
    facts = collect_snmp(FakeAgent(data)).facts
    assert facts.platform == "juniper_junos"
    assert facts.serial == "JW3619AN0000"
    assert facts.model == "EX2300-24P"
    assert facts.os_version == "21.4R3-S1.6"


@pytest.mark.parametrize("descr,version", [
    ("Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(8), RELEASE SOFTWARE", "9.3(8)"),
    ("Arista Networks EOS version 4.28.3M running on an Arista Networks DCS-7050SX3-48YC8", "4.28.3M"),
    ("HP J9772A 2530-48G-PoEP Switch, revision YA.16.10.0012, ROM YA.15.20", "YA.16.10.0012"),
    ("Aruba JL658A 6300M 24SFP+ 4SFP56 Swch FL.10.10.1020", "FL.10.10.1020"),
    ("", None),
])
def test_parse_os_version(descr, version):
    assert parse_os_version(descr) == version
