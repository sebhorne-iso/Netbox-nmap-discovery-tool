"""Fixtures shared by the integration tests (run with ``manage.py test netbox_nmap_discovery``)."""
from dcim.models import DeviceRole, DeviceType, Manufacturer, Site

from ..engine.results import (
    DeviceFacts,
    DiscoveredInterface,
    HostResult,
    Neighbor,
    NmapHost,
    OpenPort,
)
from ..engine.runner import ScanResult
from ..models import ScanTarget
from ..sync.context import SyncContext
from ..utils import get_settings


def make_switch(address="10.0.0.1", name="sw1", serial="FOC1111A1AA", mac_suffix="01", neighbors=None,
                extra_interfaces=None, model="C9300-48P"):
    interfaces = [
        DiscoveredInterface(name="GigabitEthernet1/0/1", type="1000base-t", speed_kbps=1_000_000, mtu=1500,
                            mac_address=f"00:11:22:33:44:{mac_suffix}", enabled=True, oper_up=True,
                            description="uplink"),
        DiscoveredInterface(name="GigabitEthernet1/0/2", type="1000base-t", mac_address=f"00:11:22:33:45:{mac_suffix}",
                            enabled=True, oper_up=False),
        DiscoveredInterface(name="Vlan10", type="virtual", mac_address=f"00:11:22:33:46:{mac_suffix}", enabled=True,
                            oper_up=True, ip_addresses=[f"{address}/24"]),
        *(extra_interfaces or []),
    ]
    return HostResult(
        address=address,
        nmap=NmapHost(address=address, hostnames=[f"{name}.example.com"], ports=[OpenPort(22, service="ssh")],
                      ports_scanned=True),
        facts=DeviceFacts(hostname=name, vendor="Cisco", model=model, serial=serial, os_version="17.9.4",
                          platform="cisco_xe", sys_object_id="1.3.6.1.4.1.9.1.2494"),
        interfaces=interfaces,
        neighbors=neighbors or [],
        methods=["snmp"],
    )


def make_printer(address="10.0.0.50"):
    return HostResult(
        address=address,
        nmap=NmapHost(address=address, hostnames=["printer1.example.com"], mac_address="AA:BB:CC:00:00:50",
                      mac_vendor="Hewlett Packard", os_guess="HP printer", os_accuracy=95,
                      ports=[OpenPort(80, service="http"), OpenPort(9100, service="jetdirect")], ports_scanned=True),
        mac_address="AA:BB:CC:00:00:50",
        mac_vendor="Hewlett Packard",
    )


def lldp(local, remote_name, remote_port):
    return Neighbor(local_interface=local, protocol="lldp", remote_name=remote_name, remote_interface=remote_port)


class SyncTestMixin:
    @classmethod
    def setUpTestData(cls):
        cls.site = Site.objects.create(name="HQ", slug="hq")
        cls.role = DeviceRole.objects.create(name="Switch", slug="switch")
        cls.manufacturer = Manufacturer.objects.create(name="Cisco", slug="cisco")
        cls.device_type = DeviceType.objects.create(manufacturer=cls.manufacturer, model="C9300-48P",
                                                    slug="c9300-48p")
        cls.target = ScanTarget.objects.create(name="Campus", targets="10.0.0.0/24", site=cls.site,
                                               default_role=cls.role, stale_threshold=2)

    def ctx(self, mode=None, full_scan=True):
        target = ScanTarget.objects.get(pk=self.target.pk)
        if mode:
            target.sync_mode = mode
        return SyncContext(scan_target=target, settings=get_settings(), mode=mode or target.sync_mode,
                           full_scan=full_scan)

    @staticmethod
    def result(*hosts):
        return ScanResult(hosts=list(hosts))
