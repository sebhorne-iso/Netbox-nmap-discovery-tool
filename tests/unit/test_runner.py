import pytest

from netbox_nmap_discovery import DEFAULT_SETTINGS
from netbox_nmap_discovery.engine import runner as runner_mod
from netbox_nmap_discovery.engine.results import (
    ArpEntry,
    DeviceFacts,
    DiscoveredInterface,
    Neighbor,
    NmapHost,
    OpenPort,
)
from netbox_nmap_discovery.engine.runner import DiscoveryEngine, ScanRequest, merge_interfaces
from netbox_nmap_discovery.engine.snmp import SnmpCredential, SnmpError, SnmpResult
from netbox_nmap_discovery.engine.ssh import SshAuthError, SshCredential, SshResult


class FakeClient:
    def __init__(self, host, credential, **kwargs):
        self.host, self.credential = host, credential

    def close(self):
        pass


@pytest.fixture
def engine(monkeypatch):
    calls = {"snmp": [], "ssh": []}
    agents = {
        # address -> (working community, SnmpResult)
        "10.0.0.1": ("good", SnmpResult(
            facts=DeviceFacts(hostname="sw1", platform="cisco_ios", vendor="Cisco", serial="S1"),
            interfaces=[DiscoveredInterface(name="Gi0/1", mac_address="00:11:22:33:44:01"),
                        DiscoveredInterface(name="Null0"),
                        DiscoveredInterface(name="Vlan1", ip_addresses=["10.0.0.1/24"],
                                            mac_address="00:11:22:33:44:00")],
            neighbors=[Neighbor(local_interface="Gi0/1", remote_name="sw2", remote_mgmt_address="10.0.0.2"),
                       Neighbor(local_interface="Gi0/1", protocol="cdp", remote_name="sw2(FOC1)",
                                remote_interface="", remote_platform="cisco")],
            arp=[ArpEntry("10.0.0.99", "AA:AA:AA:AA:AA:99", "Vlan1"),
                 ArpEntry("192.168.99.1", "AA:AA:AA:AA:AA:01", "Vlan1"),
                 ArpEntry("10.0.0.5", "AA:BB:CC:00:00:05", "Vlan1")],
        )),
        "10.0.0.2": ("good", SnmpResult(facts=DeviceFacts(hostname="sw2", platform="cisco_ios"))),
    }

    def probe(client):
        calls["snmp"].append((client.host, client.credential.community))
        working = agents.get(client.host)
        if not working or working[0] != client.credential.community:
            raise SnmpError("timeout")
        return {"sys": 1}

    def collect(client, *args, **kwargs):
        return agents[client.host][1]

    def ssh(address, credential, platform, *args):
        calls["ssh"].append((address, credential.username, platform))
        if credential.username == "bad":
            raise SshAuthError("auth failed")
        return SshResult(facts=DeviceFacts(model="WS-C2960X", serial="SSH-SERIAL"),
                         interfaces=[DiscoveredInterface(name="GigabitEthernet0/1", description="from ssh")])

    monkeypatch.setattr(runner_mod, "SnmpClient", FakeClient)
    monkeypatch.setattr(runner_mod, "probe_snmp", probe)
    monkeypatch.setattr(runner_mod, "collect_snmp", collect)
    monkeypatch.setattr(runner_mod, "collect_ssh", ssh)
    monkeypatch.setattr(runner_mod, "autodetect_platform", lambda *a, **k: None)
    monkeypatch.setattr(runner_mod.nmap_mod, "run_nmap", lambda command, timeout: "<xml/>")
    monkeypatch.setattr(runner_mod.nmap_mod, "parse_nmap_xml", lambda xml, ports_scanned=True: [
        NmapHost("10.0.0.1", ports=[OpenPort(22)], ports_scanned=True),
        NmapHost("10.0.0.5", mac_address="AA:BB:CC:00:00:05", ports=[OpenPort(9100)], ports_scanned=True),
    ])
    eng = DiscoveryEngine({**DEFAULT_SETTINGS, "nmap_privileged": False}, log=lambda level, msg: None)
    return eng, calls


def request(**kwargs):
    defaults = dict(
        targets=["10.0.0.0/24"],
        snmp_credentials=[SnmpCredential(community="bad", id=1), SnmpCredential(community="good", id=2)],
        ssh_credentials=[SshCredential(username="bad", id=3), SshCredential(username="netops", id=4)],
    )
    defaults.update(kwargs)
    return ScanRequest(**defaults)


def test_full_pipeline(engine):
    eng, calls = engine
    result = eng.run(request())
    hosts = {h.address: h for h in result.hosts}
    # nmap hosts + LLDP neighbour follow-up + ARP-only host inside the target range (192.168.99.1 is out of scope)
    assert set(hosts) == {"10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.99"}
    sw1 = hosts["10.0.0.1"]
    assert sw1.methods == ["snmp", "ssh"]
    assert (sw1.snmp_credential_id, sw1.ssh_credential_id) == (2, 4)  # fell back past the bad credentials
    assert sw1.facts.serial == "SSH-SERIAL" and sw1.facts.hostname == "sw1"  # SSH facts override SNMP
    names = [i.name for i in sw1.interfaces]
    assert "Null0" not in names  # excluded by interface_exclude_regex
    assert "GigabitEthernet0/1" in names and "Gi0/1" not in names  # merged, long name kept
    assert next(i for i in sw1.interfaces if i.name == "GigabitEthernet0/1").description == "from ssh"
    assert len(sw1.neighbors) == 1  # LLDP + CDP duplicates merged
    assert sw1.mac_address == "00:11:22:33:44:00"  # from the interface holding the scanned IP
    assert hosts["10.0.0.2"].source == "lldp"
    assert hosts["10.0.0.99"].source == "arp" and hosts["10.0.0.99"].mac_address == "AA:AA:AA:AA:AA:99"
    printer = hosts["10.0.0.5"]
    assert not printer.managed and printer.mac_address == "AA:BB:CC:00:00:05"
    # SSH is attempted where port 22 is open, or where ports are unknown but SNMP answered (LLDP follow-up);
    # never against the printer, whose port scan showed SSH closed
    assert {c[0] for c in calls["ssh"]} == {"10.0.0.1", "10.0.0.2"}
    assert result.stats["managed"] == 2


def test_hints_order_credentials(engine):
    eng, calls = engine
    eng.run(request(hints={"10.0.0.1": {"snmp": 2, "ssh": 4}}, collect_neighbors=False, collect_arp=False))
    first_attempt = next(c for c in calls["snmp"] if c[0] == "10.0.0.1")
    assert first_attempt == ("10.0.0.1", "good")
    assert calls["ssh"][0][1] == "netops"


def test_no_credentials_is_nmap_only(engine):
    eng, calls = engine
    result = eng.run(request(snmp_credentials=[], ssh_credentials=[]))
    assert {h.address for h in result.hosts} == {"10.0.0.1", "10.0.0.5"}
    assert not any(h.managed for h in result.hosts)
    assert calls["snmp"] == []


def test_skip_nmap_rediscovery(engine):
    eng, calls = engine
    result = eng.run(request(targets=["10.0.0.1"], skip_nmap=True, collect_neighbors=False, collect_arp=False))
    assert [h.address for h in result.hosts] == ["10.0.0.1"]
    assert result.hosts[0].source == "manual"
    assert result.nmap_command == []


def test_merge_interfaces_unions_addresses():
    merged = merge_interfaces(
        [DiscoveredInterface(name="Gi0/1", ip_addresses=["10.0.0.1/24"], type="1000base-t")],
        [DiscoveredInterface(name="GigabitEthernet0/1", ip_addresses=["10.0.1.1/24"], type="other"),
         DiscoveredInterface(name="Loopback0")],
    )
    assert [i.name for i in merged] == ["GigabitEthernet0/1", "Loopback0"]
    assert merged[0].ip_addresses == ["10.0.0.1/24", "10.0.1.1/24"]
    assert merged[0].type == "1000base-t"  # "other" never overrides a known type
