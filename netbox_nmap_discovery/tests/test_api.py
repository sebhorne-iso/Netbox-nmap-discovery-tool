from unittest import mock

from dcim.models import Device
from django.urls import reverse
from rest_framework import status
from utilities.testing import APITestCase

from ..models import CredentialProfile, ProposedChange, ScanTarget
from ..sync.runner import synchronize
from .helpers import SyncTestMixin, make_switch


class APITests(SyncTestMixin, APITestCase):

    def setUp(self):
        super().setUp()
        self.user.is_superuser = True
        self.user.save()

    def url(self, name, *args):
        return reverse(f"plugins-api:netbox_nmap_discovery-api:{name}", args=args)

    def test_root_and_lists(self):
        self.assertHttpStatus(self.client.get(reverse("plugins-api:netbox_nmap_discovery-api:api-root"),
                                              **self.header), 200)
        for name in ("credentialprofile", "scantarget", "rolerule", "devicetypealias", "proposedchange",
                     "discoveredhost"):
            with self.subTest(endpoint=name):
                self.assertHttpStatus(self.client.get(self.url(f"{name}-list"), **self.header), 200)

    def test_credentials_are_write_only(self):
        response = self.client.post(self.url("credentialprofile-list"), {
            "name": "api-ssh", "kind": "ssh", "username": "netops", "secret": "hunter2",
        }, format="json", **self.header)
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        self.assertNotIn("secret", response.data)
        self.assertTrue(response.data["has_secret"])
        self.assertEqual(CredentialProfile.objects.get(name="api-ssh").secret, "hunter2")
        detail = self.client.get(self.url("credentialprofile-detail", response.data["id"]), **self.header)
        self.assertNotIn("hunter2", detail.content.decode())

    def test_create_scan_target(self):
        response = self.client.post(self.url("scantarget-list"), {
            "name": "api-target", "targets": "192.168.10.0/24", "site": self.site.pk, "sync_mode": "review",
        }, format="json", **self.header)
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        self.assertEqual(ScanTarget.objects.get(name="api-target").sync_mode, "review")
        response = self.client.post(self.url("scantarget-list"), {"name": "bad", "targets": "-iL /etc/passwd"},
                                    format="json", **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    @mock.patch("netbox_nmap_discovery.jobs.DiscoveryScanJob.enqueue")
    def test_run_action(self, enqueue):
        from core.models import Job

        enqueue.return_value = Job.objects.create(name="Network discovery scan",
                                                  job_id="00000000-0000-0000-0000-000000000001")
        response = self.client.post(self.url("scantarget-run", self.target.pk), {"address": "10.0.0.1"},
                                    format="json", **self.header)
        self.assertHttpStatus(response, status.HTTP_202_ACCEPTED)
        self.assertEqual(enqueue.call_args.kwargs.get("address"), "10.0.0.1")

    def test_approve_action(self):
        synchronize(self.result(make_switch()), self.ctx("hybrid"))
        proposal = ProposedChange.objects.get()
        response = self.client.post(self.url("proposedchange-approve", proposal.pk), {}, format="json", **self.header)
        self.assertHttpStatus(response, 200)
        self.assertTrue(response.data["result"]["success"])
        self.assertEqual(Device.objects.count(), 1)

    def test_bulk_reject_and_no_create(self):
        synchronize(self.result(make_switch()), self.ctx("hybrid"))
        proposal = ProposedChange.objects.get()
        response = self.client.post(self.url("proposedchange-bulk-reject"), {"ids": [proposal.pk]}, format="json",
                                    **self.header)
        self.assertHttpStatus(response, 200)
        proposal.refresh_from_db()
        self.assertEqual(proposal.status, "rejected")
        response = self.client.post(self.url("proposedchange-list"), {"summary": "x"}, format="json", **self.header)
        self.assertHttpStatus(response, status.HTTP_405_METHOD_NOT_ALLOWED)
