"""Background jobs (executed by NetBox's RQ worker)."""
from __future__ import annotations

import logging
import uuid
from contextlib import contextmanager, nullcontext

from core.exceptions import JobFailed
from django.contrib.auth import get_user_model
from netbox.jobs import JobRunner

from .crypto import CredentialDecryptionError
from .engine import DiscoveryEngine, ScanRequest
from .engine.nmap import NmapError
from .utils import get_settings

__all__ = ("DiscoveryScanJob", "change_logging", "schedule_scan_target")


@contextmanager
def change_logging(user):
    """
    Run the wrapped block as if it were a request made by ``user`` so that NetBox records change-log entries and
    fires event rules for the objects discovery creates or modifies.
    """
    if user is None:
        with nullcontext():
            yield
        return
    from utilities.request import NetBoxFakeRequest

    request = NetBoxFakeRequest({
        "META": {}, "COOKIES": {}, "POST": {}, "GET": {}, "FILES": {}, "user": user, "method": "POST",
        "path": "/plugins/discovery/", "path_info": "/plugins/discovery/", "id": uuid.uuid4(),
    })
    try:
        from utilities.request import apply_request_processors

        manager = apply_request_processors(request)
    except ImportError:  # pragma: no cover - older NetBox releases
        from netbox.context_managers import event_tracking

        manager = event_tracking(request)
    with manager:
        yield


def _job_user(job):
    if job.user is not None:
        return job.user
    username = get_settings().get("scheduled_job_user")
    if username:
        return get_user_model().objects.filter(username=username).first()
    return None


class DiscoveryScanJob(JobRunner):
    class Meta:
        name = "Network discovery scan"

    def _log(self, level, message):
        self.logger.log(level, message)

    def run(self, *args, address=None, **kwargs):
        from .models import DiscoveredHost, ScanTarget
        from .sync.context import SyncContext
        from .sync.runner import synchronize

        target = ScanTarget.objects.select_related("site", "location", "tenant", "vrf", "default_role").get(
            pk=self.job.object_id)
        if not target.enabled and address is None:
            self.logger.warning(f"Scan target {target} is disabled; skipping")
            return
        settings = get_settings()

        snmp_credentials, ssh_credentials = [], []
        for credential in target.credentials.order_by("priority", "name"):
            try:
                if credential.is_snmp:
                    snmp_credentials.append(credential.to_snmp_credential())
                else:
                    ssh_credentials.append(credential.to_ssh_credential())
            except CredentialDecryptionError as exc:
                self.logger.error(f"Credential {credential}: {exc}")

        hints = {
            h.address: {"snmp": h.snmp_credential_id, "ssh": h.ssh_credential_id, "platform": h.platform or None}
            for h in DiscoveredHost.objects.filter(vrf=target.vrf).only(
                "address", "snmp_credential_id", "ssh_credential_id", "platform")
        }
        request = ScanRequest(
            targets=[address] if address else target.target_list,
            exclusions=target.exclusion_list,
            profile=target.scan_profile,
            custom_args=target.custom_nmap_args,
            snmp_enabled=target.snmp_enabled,
            ssh_enabled=target.ssh_enabled,
            collect_neighbors=target.collect_neighbors,
            collect_arp=target.collect_arp,
            snmp_credentials=snmp_credentials,
            ssh_credentials=ssh_credentials,
            hints=hints,
        )
        engine = DiscoveryEngine(settings, log=self._log)
        self.logger.info(
            f"Scanning {'address ' + address if address else target.name} "
            f"({len(snmp_credentials)} SNMP / {len(ssh_credentials)} SSH credential(s), sync mode {target.sync_mode})"
        )
        try:
            result = engine.run(request)
            if address and not result.hosts:
                self.logger.info(f"{address} did not respond to nmap; polling it directly")
                request.skip_nmap = True
                result = engine.run(request)
        except (NmapError, ValueError) as exc:
            self.logger.error(str(exc))
            raise JobFailed() from exc
        self.logger.info(f"Discovery finished in {result.duration:.1f}s: {result.stats}")

        user = _job_user(self.job)
        if user is None:
            self.logger.warning("Job has no user; changes will not be attributed in the change log. Set the "
                                "scheduled_job_user plugin setting to a service account.")
        ctx = SyncContext(scan_target=target, settings=settings, mode=target.sync_mode, job=self.job, user=user,
                          log_callback=self._log, full_scan=address is None)
        with change_logging(user):
            stats = synchronize(result, ctx)
        self.logger.info(f"Synchronisation complete: {stats}")
        self.job.data = {
            "engine": result.stats,
            "sync": stats,
            "nmap_command": " ".join(result.nmap_command[1:]),
            "errors": ctx.errors[:100],
        }


def schedule_scan_target(target, user=None):
    """
    Create, update or remove the recurring job for a scan target. One-off (manual / rediscovery) jobs are never
    touched. The first recurring run is scheduled one interval from now.
    """
    from datetime import timedelta

    from core.choices import JobStatusChoices
    from django.utils import timezone

    recurring = list(DiscoveryScanJob.get_jobs(target).filter(
        status__in=JobStatusChoices.ENQUEUED_STATE_CHOICES, interval__isnull=False))
    wanted = target.interval if target.enabled and target.interval else None
    keep = None
    for job in recurring:
        if wanted and keep is None and job.interval == wanted:
            keep = job
        else:
            job.delete()
    if wanted and keep is None:
        DiscoveryScanJob.enqueue(instance=target, user=user, interval=wanted,
                                 schedule_at=timezone.now() + timedelta(minutes=wanted))


def enqueue_scan(target, user=None, address=None):
    kwargs = {"address": address} if address else {}
    return DiscoveryScanJob.enqueue(instance=target, user=user, **kwargs)


logging.getLogger("netbox_nmap_discovery").addHandler(logging.NullHandler())
