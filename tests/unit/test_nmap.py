import pytest

from netbox_nmap_discovery.engine import nmap


def test_parse_scan(fixture_text):
    hosts = nmap.parse_nmap_xml(fixture_text("nmap_scan.xml"))
    assert [h.address for h in hosts] == ["10.0.0.1", "10.0.0.5"]  # down host skipped
    switch, printer = hosts
    assert switch.mac_address == "00:11:22:33:44:01"
    assert switch.mac_vendor == "Cisco Systems"
    assert switch.hostname == "sw1.example.com"
    assert [(p.port, p.service) for p in switch.ports] == [(22, "ssh"), (443, "https")]  # filtered port excluded
    assert switch.ports[0].product == "Cisco SSH"
    assert switch.os_guess == "Cisco IOS XE 16.x" and switch.os_accuracy == 98  # best match wins
    assert switch.os_family == "IOS XE"
    assert switch.ports_scanned
    assert printer.hostnames[0] == "printer1.example.com"  # PTR preferred over user-supplied name
    assert printer.has_port(9100)


def test_parse_invalid_xml():
    with pytest.raises(nmap.NmapError):
        nmap.parse_nmap_xml("<nmaprun><host>")


def test_build_command_privileged():
    cmd = nmap.build_nmap_command(["10.0.0.0/24"], ["10.0.0.5"], "conservative", privileged=True)
    assert cmd[0] == "nmap"
    assert "-sS" in cmd and "-O" in cmd
    assert cmd[cmd.index("--exclude") + 1] == "10.0.0.5"
    assert cmd[-1] == "10.0.0.0/24"
    assert cmd[cmd.index("-oX") + 1] == "-"


def test_build_command_unprivileged_degrades():
    cmd = nmap.build_nmap_command(["10.0.0.0/24"], profile="thorough", privileged=False)
    assert "-sT" in cmd and "-sS" not in cmd and "-O" not in cmd and "--privileged" not in cmd
    assert "-sV" in cmd


def test_discovery_profile_is_ping_only():
    cmd = nmap.build_nmap_command(["10.0.0.1"], profile="discovery", privileged=True)
    assert "-sn" in cmd and "--top-ports" not in cmd


@pytest.mark.parametrize("args", ["-sT -p 22,80,443 -T4", "-sS --top-ports=200 --max-retries 1", "-PS22,443 -n",
                                  "--host-timeout 10m -sV --version-light"])
def test_custom_arguments_allowed(args):
    assert nmap.validate_custom_arguments(args)


@pytest.mark.parametrize("args", ["--script=vuln", "-oN /tmp/out", "-iL /etc/hosts", "--datadir /tmp",
                                  "--resume x", "-p '22;id'", "--stylesheet http://x", "-sC", "-A",
                                  "--max-retries"])
def test_custom_arguments_rejected(args):
    with pytest.raises(ValueError):
        nmap.validate_custom_arguments(args)


@pytest.mark.parametrize("target", ["10.0.0.1", "10.0.0.0/24", "10.0.0.10-20", "2001:db8::/120", "sw1.example.com"])
def test_valid_targets(target):
    assert nmap.validate_targets([target]) == [target]


@pytest.mark.parametrize("target", ["10.0.0.0/8", "-sV", "10.0.0.1;reboot", "2001:db8::/64", "a b"])
def test_invalid_targets(target):
    with pytest.raises(ValueError):
        nmap.validate_targets([target])


def test_run_nmap_missing_binary():
    with pytest.raises(nmap.NmapError, match="not found"):
        nmap.run_nmap(["/nonexistent/nmap", "-sn", "127.0.0.1"])
