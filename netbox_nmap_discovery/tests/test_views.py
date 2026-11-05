from unittest import mock

from dcim.models import Device
from django.test import override_settings
from django.urls import reverse
from utilities.testing import TestCase

from ..models import CredentialProfile, DeviceTypeAlias, DiscoveredHost, ProposedChange, RoleRule
from ..sync.runner import synchronize
from .helpers import SyncTestMixin, make_printer, make_switch


class ViewTests(SyncTestMixin, TestCase):

    def setUp(self):
        super().setUp()
        self.user.is_superuser = True
        self.user.save()
        credential = CredentialProfile(name="snmp", kind="snmp-v2c")
        credential.secret = "public"
        credential.save()
        self.target.credentials.add(credential)
        RoleRule.objects.create(name="rule", role=self.role, hostname_regex="^sw")
        DeviceTypeAlias.objects.create(reported_model="C9300-48P-A", device_type=self.device_type)
        synchronize(self.result(make_switch(), make_printer()), self.ctx("hybrid"))

    def test_list_and_detail_views_render(self):
        for model in ("scantarget", "credentialprofile", "rolerule", "devicetypealias", "proposedchange",
                      "discoveredhost"):
            with self.subTest(model=model):
                response = self.client.get(reverse(f"plugins:netbox_nmap_discovery:{model}_list"))
                self.assertHttpStatus(response, 200)
                obj = {"scantarget": self.target, "credentialprofile": CredentialProfile.objects.first(),
                       "rolerule": RoleRule.objects.first(), "devicetypealias": DeviceTypeAlias.objects.first(),
                       "proposedchange": ProposedChange.objects.first(),
                       "discoveredhost": DiscoveredHost.objects.first()}[model]
                self.assertHttpStatus(self.client.get(obj.get_absolute_url()), 200)

    def test_edit_forms_render(self):
        for name in ("scantarget_add", "credentialprofile_add", "rolerule_add", "devicetypealias_add"):
            with self.subTest(view=name):
                self.assertHttpStatus(self.client.get(reverse(f"plugins:netbox_nmap_discovery:{name}")), 200)
        proposal = ProposedChange.objects.get(kind="create-device")
        self.assertHttpStatus(self.client.get(
            reverse("plugins:netbox_nmap_discovery:proposedchange_edit", args=[proposal.pk])), 200)
        self.assertHttpStatus(self.client.get(reverse("plugins:netbox_nmap_discovery:scantarget_jobs",
                                                      args=[self.target.pk])), 200)

    def test_secret_never_rendered(self):
        credential = CredentialProfile.objects.get()
        response = self.client.get(reverse("plugins:netbox_nmap_discovery:credentialprofile_edit",
                                           args=[credential.pk]))
        self.assertNotContains(response, "public")
        self.assertNotContains(response, credential.encrypted_secret)

    def test_credential_form_keeps_secret_when_blank(self):
        credential = CredentialProfile.objects.get()
        response = self.client.post(
            reverse("plugins:netbox_nmap_discovery:credentialprofile_edit", args=[credential.pk]),
            {"name": "snmp", "kind": "snmp-v2c", "priority": 50, "snmp_auth_protocol": "none",
             "snmp_priv_protocol": "none", "options": "{}"})
        self.assertHttpStatus(response, 302)
        credential.refresh_from_db()
        self.assertEqual((credential.priority, credential.secret), (50, "public"))

    def test_approve_and_reject(self):
        proposal = ProposedChange.objects.get(kind="create-device")
        response = self.client.post(reverse("plugins:netbox_nmap_discovery:proposedchange_approve",
                                            args=[proposal.pk]))
        self.assertHttpStatus(response, 302)
        self.assertEqual(Device.objects.count(), 1)
        proposal.refresh_from_db()
        self.assertEqual(proposal.status, "applied")
        self.assertEqual(proposal.decided_by, self.user)

    def test_bulk_approve(self):
        proposal = ProposedChange.objects.get(kind="create-device")
        response = self.client.post(reverse("plugins:netbox_nmap_discovery:proposedchange_bulk_approve"),
                                    {"pk": [proposal.pk]})
        self.assertHttpStatus(response, 302)
        self.assertEqual(Device.objects.count(), 1)
        device = Device.objects.get()
        self.assertHttpStatus(self.client.get(device.get_absolute_url()), 200)

    def test_overrides_and_approve(self):
        proposal = ProposedChange.objects.get(kind="create-device")
        response = self.client.post(
            reverse("plugins:netbox_nmap_discovery:proposedchange_edit", args=[proposal.pk]),
            {"name": "renamed-switch", "approve": "on"})
        self.assertHttpStatus(response, 302)
        self.assertEqual(Device.objects.get().name, "renamed-switch")

    def test_promote_nmap_only_host(self):
        host = DiscoveredHost.objects.get(address="10.0.0.50")
        response = self.client.post(reverse("plugins:netbox_nmap_discovery:discoveredhost_promote", args=[host.pk]))
        self.assertHttpStatus(response, 302)
        proposal = ProposedChange.objects.get(summary__contains="printer1")
        self.assertEqual(proposal.kind, "create-device")

    @mock.patch("netbox_nmap_discovery.jobs.DiscoveryScanJob.enqueue")
    def test_run_and_rediscover(self, enqueue):
        enqueue.return_value = mock.Mock(get_absolute_url=lambda: "/core/jobs/1/")
        response = self.client.post(reverse("plugins:netbox_nmap_discovery:scantarget_run", args=[self.target.pk]))
        self.assertHttpStatus(response, 302)
        enqueue.assert_called_once()
        self.assertHttpStatus(self.client.get(reverse("plugins:netbox_nmap_discovery:rediscover") +
                                              "?address=10.0.0.1"), 200)
        response = self.client.post(reverse("plugins:netbox_nmap_discovery:rediscover"),
                                    {"address": "10.0.0.1", "scan_target": self.target.pk})
        self.assertHttpStatus(response, 302)
        self.assertEqual(enqueue.call_args.kwargs.get("address"), "10.0.0.1")


class ViewPermissionTests(SyncTestMixin, TestCase):

    @override_settings(EXEMPT_VIEW_PERMISSIONS=["*"])
    @mock.patch("netbox_nmap_discovery.jobs.DiscoveryScanJob.enqueue")
    def test_rediscover_outside_target_requires_change(self, enqueue):
        enqueue.return_value = mock.Mock(get_absolute_url=lambda: "/core/jobs/1/")
        self.add_permissions("netbox_nmap_discovery.run_scantarget")
        url = reverse("plugins:netbox_nmap_discovery:rediscover")
        self.client.post(url, {"address": "192.168.50.1", "scan_target": self.target.pk})
        enqueue.assert_not_called()
        self.client.post(url, {"address": "10.0.0.7", "scan_target": self.target.pk})
        enqueue.assert_called_once()

    @override_settings(EXEMPT_VIEW_PERMISSIONS=["*"])
    def test_run_requires_permission(self):
        response = self.client.post(reverse("plugins:netbox_nmap_discovery:scantarget_run", args=[self.target.pk]))
        self.assertHttpStatus(response, 404)

    @override_settings(EXEMPT_VIEW_PERMISSIONS=["*"])
    def test_approve_requires_target_model_permissions(self):
        synchronize(self.result(make_switch()), self.ctx("hybrid"))
        self.add_permissions("netbox_nmap_discovery.change_proposedchange",
                             "netbox_nmap_discovery.view_proposedchange")
        proposal = ProposedChange.objects.get()
        self.client.post(reverse("plugins:netbox_nmap_discovery:proposedchange_approve", args=[proposal.pk]))
        self.assertEqual(Device.objects.count(), 0)
        proposal.refresh_from_db()
        self.assertEqual(proposal.status, "pending")
