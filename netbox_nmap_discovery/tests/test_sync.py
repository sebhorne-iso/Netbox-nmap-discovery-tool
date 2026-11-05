from dcim.models import Cable, Device, Interface, MACAddress
from django.test import TestCase
from ipam.choices import IPAddressStatusChoices
from ipam.models import IPAddress, Prefix

from ..choices import ProposalKindChoices, ProposalStatusChoices
from ..engine.results import DiscoveredInterface
from ..models import DeviceTypeAlias, DiscoveredHost, ObjectSighting, ProposedChange, RoleRule
from ..sync.matching import match_device
from ..sync.proposals import apply_proposal, reject_proposal
from ..sync.provision import CF_LAST_SEEN, CF_MAC, CF_PORTS, TAG_STALE
from ..sync.runner import synchronize
from .helpers import SyncTestMixin, lldp, make_printer, make_switch


class HybridModeTests(SyncTestMixin, TestCase):

    def test_new_device_is_proposed_not_created(self):
        stats = synchronize(self.result(make_switch()), self.ctx("hybrid"))
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(stats["proposals_created"], 1)
        proposal = ProposedChange.objects.get()
        self.assertEqual(proposal.kind, ProposalKindChoices.CREATE_DEVICE)
        self.assertIn("sw1", proposal.summary)
        texts = [c["text"] for c in proposal.diff]
        self.assertTrue(any("Create interface GigabitEthernet1/0/1" in t for t in texts))
        self.assertTrue(any("Create ip 10.0.0.1/24" in t for t in texts))
        # The scanned address is still recorded in IPAM (unassigned) with metadata
        ip = IPAddress.objects.get(address="10.0.0.1/24")
        self.assertIsNone(ip.assigned_object)
        self.assertIn(CF_LAST_SEEN, ip.custom_field_data)

    def test_approving_proposal_creates_device_bundle(self):
        synchronize(self.result(make_switch()), self.ctx("hybrid"))
        ok, message = apply_proposal(ProposedChange.objects.get())
        self.assertTrue(ok, message)
        device = Device.objects.get()
        self.assertEqual(device.name, "sw1")
        self.assertEqual(device.serial, "FOC1111A1AA")
        self.assertEqual(device.device_type, self.device_type)
        self.assertEqual(device.site, self.site)
        self.assertEqual(device.role, self.role)
        self.assertEqual(device.platform.name, "Cisco IOS-XE")
        self.assertEqual(device.interfaces.count(), 3)
        uplink = device.interfaces.get(name="GigabitEthernet1/0/1")
        self.assertEqual(str(uplink.primary_mac_address.mac_address), "00:11:22:33:44:01")
        self.assertEqual(uplink.description, "uplink")
        self.assertEqual(str(device.primary_ip4.address), "10.0.0.1/24")
        self.assertEqual(device.primary_ip4.assigned_object.name, "Vlan10")
        # The previously unassigned IP was reused, not duplicated
        self.assertEqual(IPAddress.objects.filter(address__net_host="10.0.0.1").count(), 1)
        self.assertEqual(ProposedChange.objects.get().status, ProposalStatusChoices.APPLIED)

    def test_rescan_is_idempotent(self):
        synchronize(self.result(make_switch()), self.ctx("hybrid"))
        apply_proposal(ProposedChange.objects.get())
        counts = (Device.objects.count(), Interface.objects.count(), IPAddress.objects.count(),
                  MACAddress.objects.count())
        stats = synchronize(self.result(make_switch()), self.ctx("hybrid"))
        self.assertEqual(stats.get("devices_matched"), 1)
        self.assertNotIn("proposals_created", stats)
        self.assertEqual(counts, (Device.objects.count(), Interface.objects.count(), IPAddress.objects.count(),
                                  MACAddress.objects.count()))

    def test_safe_updates_apply_and_sensitive_updates_are_queued(self):
        synchronize(self.result(make_switch()), self.ctx("hybrid"))
        apply_proposal(ProposedChange.objects.get())
        host = make_switch(serial="FOC9999Z9ZZ", extra_interfaces=[
            DiscoveredInterface(name="GigabitEthernet1/0/3", type="1000base-t", enabled=True)])
        synchronize(self.result(host), self.ctx("hybrid"))
        device = Device.objects.get()
        # matched by MAC/name despite the serial change; new interface added automatically
        self.assertTrue(device.interfaces.filter(name="GigabitEthernet1/0/3").exists())
        self.assertEqual(device.serial, "FOC1111A1AA")
        proposal = ProposedChange.objects.get(kind=ProposalKindChoices.UPDATE_DEVICE)
        self.assertEqual(proposal.object, device)
        self.assertTrue(all(c["sensitive"] for c in proposal.diff))
        ok, _ = apply_proposal(proposal)
        self.assertTrue(ok)
        device.refresh_from_db()
        self.assertEqual(device.serial, "FOC9999Z9ZZ")

    def test_rejected_proposals_are_not_recreated(self):
        synchronize(self.result(make_switch()), self.ctx("hybrid"))
        reject_proposal(ProposedChange.objects.get())
        stats = synchronize(self.result(make_switch()), self.ctx("hybrid"))
        self.assertEqual(stats.get("proposals_previously_rejected"), 1)
        self.assertEqual(ProposedChange.objects.count(), 1)

    def test_cables_are_proposed_from_lldp(self):
        sw1 = make_switch(neighbors=[lldp("Gi1/0/1", "sw2.example.com", "Gi1/0/1")])
        sw2 = make_switch(address="10.0.0.2", name="sw2", serial="FOC2222B2BB", mac_suffix="02",
                          neighbors=[lldp("GigabitEthernet1/0/1", "sw1", "GigabitEthernet1/0/1")])
        synchronize(self.result(sw1, sw2), self.ctx("automatic"))
        self.assertEqual(Device.objects.count(), 2)
        Cable.objects.all().delete()
        stats = synchronize(self.result(sw1, sw2), self.ctx("hybrid"))
        self.assertEqual(Cable.objects.count(), 0)
        proposal = ProposedChange.objects.get(kind=ProposalKindChoices.CREATE_CABLE)
        self.assertNotIn("cable_conflicts", stats)
        ok, message = apply_proposal(proposal)
        self.assertTrue(ok, message)
        cable = Cable.objects.get()
        names = {t.name for t in cable.a_terminations + cable.b_terminations}
        self.assertEqual(names, {"GigabitEthernet1/0/1"})


class AutomaticModeTests(SyncTestMixin, TestCase):

    def test_devices_and_cables_created(self):
        sw1 = make_switch(neighbors=[lldp("Gi1/0/1", "sw2", "Gi1/0/1")])
        sw2 = make_switch(address="10.0.0.2", name="sw2", serial="FOC2222B2BB", mac_suffix="02")
        stats = synchronize(self.result(sw1, sw2), self.ctx("automatic"))
        self.assertEqual(stats["devices_created"], 2)
        self.assertEqual(stats["cables_created"], 1)
        self.assertEqual(ProposedChange.objects.count(), 0)

    def test_missing_role_falls_back_to_proposal(self):
        target = self.target
        target.default_role = None
        target.save()
        synchronize(self.result(make_switch()), self.ctx("automatic"))
        self.assertEqual(Device.objects.count(), 0)
        proposal = ProposedChange.objects.get()
        self.assertTrue(proposal.data["problems"])
        ok, message = apply_proposal(proposal)
        self.assertFalse(ok)
        self.assertIn("role", message)
        proposal.refresh_from_db()
        self.assertEqual(proposal.status, ProposalStatusChoices.FAILED)
        proposal.overrides = {"role": self.role.pk}
        proposal.save()
        ok, message = apply_proposal(proposal)
        self.assertTrue(ok, message)

    def test_unknown_model_creates_minimal_device_type(self):
        host = make_switch(model="WS-C9999-XX")
        synchronize(self.result(host), self.ctx("automatic"))
        device = Device.objects.get()
        self.assertEqual(device.device_type.model, "WS-C9999-XX")
        self.assertTrue(device.device_type.tags.filter(slug="discovery-autocreated").exists())

    def test_device_type_alias(self):
        DeviceTypeAlias.objects.create(reported_model="WS-C9999-XX", device_type=self.device_type)
        synchronize(self.result(make_switch(model="WS-C9999-XX")), self.ctx("automatic"))
        self.assertEqual(Device.objects.get().device_type, self.device_type)

    def test_role_rule(self):
        from dcim.models import DeviceRole

        core = DeviceRole.objects.create(name="Core", slug="core")
        RoleRule.objects.create(name="core switches", role=core, hostname_regex=r"^core-")
        synchronize(self.result(make_switch(name="core-sw1")), self.ctx("automatic"))
        self.assertEqual(Device.objects.get().role, core)

    def test_site_from_prefix_scope(self):
        from dcim.models import Site

        branch = Site.objects.create(name="Branch", slug="branch")
        Prefix.objects.create(prefix="10.0.0.0/25", scope=branch)
        synchronize(self.result(make_switch()), self.ctx("automatic"))
        self.assertEqual(Device.objects.get().site, branch)


class IpamTests(SyncTestMixin, TestCase):

    def test_nmap_only_host_recorded_in_ipam(self):
        Prefix.objects.create(prefix="10.0.0.0/24")
        synchronize(self.result(make_printer()), self.ctx("hybrid"))
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(ProposedChange.objects.count(), 0)
        ip = IPAddress.objects.get()
        self.assertEqual(str(ip.address), "10.0.0.50/24")
        self.assertEqual(ip.dns_name, "printer1.example.com")
        self.assertEqual(ip.custom_field_data[CF_MAC], "AA:BB:CC:00:00:50")
        self.assertIn("9100/tcp", ip.custom_field_data[CF_PORTS])
        record = DiscoveredHost.objects.get()
        self.assertEqual(record.ip_address, ip)
        self.assertFalse(record.managed)

    def test_review_mode_stages_new_ips(self):
        synchronize(self.result(make_printer()), self.ctx("review"))
        self.assertEqual(IPAddress.objects.count(), 0)
        proposal = ProposedChange.objects.get()
        self.assertEqual(proposal.kind, ProposalKindChoices.CREATE_IP)
        ok, _ = apply_proposal(proposal)
        self.assertTrue(ok)
        self.assertEqual(IPAddress.objects.count(), 1)

    def test_manual_dns_name_is_not_overwritten(self):
        IPAddress.objects.create(address="10.0.0.50/24", dns_name="manual.example.com")
        synchronize(self.result(make_printer()), self.ctx("hybrid"))
        self.assertEqual(IPAddress.objects.get().dns_name, "manual.example.com")


class StaleTests(SyncTestMixin, TestCase):

    def test_ip_becomes_stale_and_recovers(self):
        target = self.target
        target.deprecate_stale_ips = True
        target.save()
        synchronize(self.result(make_printer()), self.ctx("hybrid"))
        ip = IPAddress.objects.get()
        for _ in range(2):  # stale_threshold = 2
            synchronize(self.result(), self.ctx("hybrid"))
        ip.refresh_from_db()
        self.assertTrue(ip.tags.filter(slug=TAG_STALE).exists())
        self.assertEqual(ip.status, IPAddressStatusChoices.STATUS_DEPRECATED)
        self.assertTrue(DiscoveredHost.objects.get().is_stale)
        synchronize(self.result(make_printer()), self.ctx("hybrid"))
        ip.refresh_from_db()
        self.assertFalse(ip.tags.filter(slug=TAG_STALE).exists())
        self.assertEqual(ip.status, IPAddressStatusChoices.STATUS_ACTIVE)
        self.assertFalse(DiscoveredHost.objects.get().is_stale)

    def test_interfaces_only_missed_when_device_polled(self):
        host = make_switch(extra_interfaces=[DiscoveredInterface(name="GigabitEthernet1/0/9", type="1000base-t")])
        synchronize(self.result(host), self.ctx("automatic"))
        interface = Interface.objects.get(name="GigabitEthernet1/0/9")
        # Device not polled at all: no misses counted for its interfaces
        synchronize(self.result(), self.ctx("automatic"))
        sighting = ObjectSighting.objects.get(object_id=interface.pk, object_type__model="interface")
        self.assertEqual(sighting.miss_count, 0)
        # Device polled without that interface: counted
        for _ in range(2):
            synchronize(self.result(make_switch()), self.ctx("automatic"))
        sighting.refresh_from_db()
        self.assertTrue(sighting.is_stale)
        self.assertTrue(interface.tags.filter(slug=TAG_STALE).exists())

    def test_rediscovery_does_not_count_misses(self):
        synchronize(self.result(make_printer()), self.ctx("hybrid"))
        for _ in range(3):
            synchronize(self.result(), self.ctx("hybrid", full_scan=False))
        self.assertEqual(DiscoveredHost.objects.get().miss_count, 0)


class MatchingTests(SyncTestMixin, TestCase):

    def _device(self, name, serial=""):
        return Device.objects.create(name=name, serial=serial, site=self.site, role=self.role,
                                     device_type=self.device_type)

    def test_match_priority(self):
        by_serial = self._device("other-name", serial="FOC1111A1AA")
        self._device("sw1")
        device, reason = match_device(make_switch())
        self.assertEqual(device, by_serial)
        self.assertIn("serial", reason)

    def test_match_by_mac(self):
        device = self._device("renamed")
        interface = Interface.objects.create(device=device, name="Gi1/0/1", type="1000base-t")
        MACAddress.objects.create(mac_address="00:11:22:33:44:01", assigned_object=interface)
        matched, reason = match_device(make_switch(serial=None))
        self.assertEqual(matched, device)
        self.assertIn("MAC", reason)

    def test_match_by_fqdn_and_short_name(self):
        device = self._device("sw1.example.com")
        self.assertEqual(match_device(make_switch(serial=None))[0], device)

    def test_virtual_macs_ignored(self):
        device = self._device("unrelated")
        interface = Interface.objects.create(device=device, name="Vlan1", type="virtual")
        MACAddress.objects.create(mac_address="00:00:0C:07:AC:01", assigned_object=interface)
        host = make_switch(serial=None, name="nomatch")
        host.interfaces[0].mac_address = "00:00:0C:07:AC:01"
        host.nmap.hostnames = []
        self.assertIsNone(match_device(host)[0])
