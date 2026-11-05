from netbox_nmap_discovery.engine.ssh import parsers


def test_cdp_ios(fixture_text):
    neighbors = parsers.parse_cdp_neighbors_detail(fixture_text("cdp_detail_ios.txt"))
    assert [(n.local_interface, n.remote_name, n.remote_interface, n.remote_mgmt_address) for n in neighbors] == [
        ("GigabitEthernet1/0/1", "sw2.example.com", "GigabitEthernet1/0/49", "192.168.0.2"),
        ("GigabitEthernet1/0/10", "AP01", "GigabitEthernet0", "10.0.0.30"),
    ]
    assert neighbors[0].remote_platform == "cisco C9300-48P"


def test_cdp_nxos(fixture_text):
    (neighbor,) = parsers.parse_cdp_neighbors_detail(fixture_text("cdp_detail_nxos.txt"))
    assert neighbor.remote_name == "N9K-2"  # System Name preferred over Device ID with serial
    assert (neighbor.local_interface, neighbor.remote_interface) == ("Ethernet1/49", "Ethernet1/49")
    assert neighbor.remote_mgmt_address == "192.168.0.3"


def test_linux_ip_addr(fixture_text):
    interfaces = {i.name: i for i in parsers.parse_linux_ip_addr(fixture_text("linux_ip_addr.json"),
                                                                 {"eno1": 10000, "eno2": 10000})}
    assert interfaces["bond0"].type == "lag"
    assert interfaces["bond0"].ip_addresses == ["10.0.0.20/24"]  # link-local excluded
    assert interfaces["eno1"].lag == "bond0" and interfaces["eno2"].lag == "bond0"
    assert interfaces["eno1"].type == "10gbase-x-sfpp" and interfaces["eno1"].speed_kbps == 10_000_000
    assert interfaces["eno1"].mac_address == "3C:EC:EF:00:00:01"
    assert interfaces["docker0"].type == "bridge"
    assert interfaces["lo"].type == "virtual" and interfaces["lo"].ip_addresses == []


def test_linux_lldpctl(fixture_text):
    neighbors = parsers.parse_linux_lldpctl(fixture_text("linux_lldpctl.json"))
    assert [(n.local_interface, n.remote_name, n.remote_interface, n.remote_mgmt_address) for n in neighbors] == [
        ("eno1", "sw1.example.com", "Gi1/0/5", "10.0.0.1"),
        ("eno2", "sw2.example.com", "00:11:22:33:55:05", "10.0.0.2"),
    ]
    assert neighbors[1].remote_interface_description == "GigabitEthernet1/0/5"


def test_linux_neigh_and_dmi():
    text = '[{"dst":"10.0.0.1","dev":"bond0","lladdr":"00:11:22:33:44:00","state":["REACHABLE"]},' \
           '{"dst":"10.0.0.9","dev":"bond0","state":["FAILED"]},' \
           '{"dst":"fe80::1","dev":"bond0","lladdr":"00:11:22:33:44:00","state":["STALE"]}]'
    assert [(a.ip_address, a.interface) for a in parsers.parse_linux_ip_neigh(text)] == [("10.0.0.1", "bond0")]
    dmi = parsers.parse_linux_dmi("sys_vendor=Dell Inc.\nproduct_name=PowerEdge R650\nproduct_serial=\n")
    assert dmi == {"sys_vendor": "Dell Inc.", "product_name": "PowerEdge R650"}


def test_fortios(fixture_text):
    facts = parsers.parse_fortios_system_status(fixture_text("fortios_status.txt"))
    assert (facts.hostname, facts.model, facts.serial, facts.os_version) == (
        "FGT-HQ", "FortiGate-60F", "FGT60FTK21000001", "7.2.5")
    interfaces = {i.name: i for i in parsers.parse_fortios_interfaces(fixture_text("fortios_interfaces.txt"))}
    assert set(interfaces) == {"wan1", "internal1", "lan"}
    assert interfaces["wan1"].ip_addresses == ["203.0.113.10/24"]
    assert interfaces["internal1"].ip_addresses == [] and interfaces["internal1"].oper_up is False
    assert interfaces["lan"].speed_kbps == 1_000_000


def test_panos(fixture_text):
    facts = parsers.parse_panos_system_info(fixture_text("panos_system_info.txt"))
    assert (facts.hostname, facts.model, facts.serial, facts.os_version) == (
        "PA-FW01", "PA-220", "012801012345", "10.1.6")
    interfaces = {i.name: i for i in parsers.parse_panos_interfaces(fixture_text("panos_interfaces.txt"))}
    assert interfaces["ethernet1/1"].ip_addresses == ["203.0.113.2/24"]
    assert interfaces["ethernet1/1"].mac_address == "00:1B:17:00:01:10"
    assert interfaces["ethernet1/2"].oper_up is False
    assert interfaces["ethernet1/3"].ip_addresses == ["192.168.1.1/24"]


def test_aoscx(fixture_text):
    facts = parsers.parse_aoscx_system(fixture_text("aoscx_system.txt"))
    assert (facts.hostname, facts.model, facts.serial, facts.os_version) == (
        "sw-core-01", "JL658A", "SG0ZKZZ123", "FL.10.10.1020")
    (neighbor,) = parsers.parse_aoscx_lldp_detail(fixture_text("aoscx_lldp.txt"))
    assert (neighbor.local_interface, neighbor.remote_name, neighbor.remote_interface) == (
        "1/1/49", "sw-access-01", "1/1/52")
    assert neighbor.remote_mgmt_address == "10.0.0.12"
    assert neighbor.remote_chassis_id == "90:20:C2:00:00:01"


def test_procurve(fixture_text):
    facts = parsers.parse_procurve_system(fixture_text("procurve_system.txt"))
    assert (facts.hostname, facts.serial, facts.os_version) == ("HP-2530-48G", "CN6BFP0001", "YA.16.10.0012")
    (neighbor,) = parsers.parse_procurve_lldp_detail(fixture_text("procurve_lldp.txt"))
    assert (neighbor.local_interface, neighbor.remote_name, neighbor.remote_interface) == ("49", "sw-core-01", "1/1/1")
    assert neighbor.remote_chassis_id == "90:20:C2:00:00:01"
    assert neighbor.remote_mgmt_address == "10.0.0.11"


def test_key_values_two_per_line():
    kv = parsers.parse_key_values("  Software revision  : YA.16.10.0012        Base MAC Addr      : 9cdc71-000001")
    assert kv == {"Software revision": "YA.16.10.0012", "Base MAC Addr": "9cdc71-000001"}
