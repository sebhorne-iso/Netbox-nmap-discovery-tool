import logging

from django.db.models.signals import post_delete, post_migrate, post_save
from django.dispatch import receiver

from .models import ScanTarget

logger = logging.getLogger("netbox_nmap_discovery")


def _current_user():
    try:
        from netbox.context import current_request

        request = current_request.get()
    except (ImportError, LookupError):
        return None
    user = getattr(request, "user", None) if request is not None else None
    return user if getattr(user, "is_authenticated", False) else None


@receiver(post_save, sender=ScanTarget)
def update_schedule(sender, instance, **kwargs):
    """Keep the recurring discovery job in step with the scan target's interval."""
    if kwargs.get("raw"):
        return
    from .jobs import schedule_scan_target

    try:
        schedule_scan_target(instance, user=_current_user())
    except Exception as exc:  # e.g. Redis unavailable: never block saving the object
        logger.warning("Unable to update the discovery schedule for %s: %s", instance, exc)


@receiver(post_delete, sender=ScanTarget)
def remove_schedule(sender, instance, **kwargs):
    from core.choices import JobStatusChoices

    from .jobs import DiscoveryScanJob

    try:
        for job in DiscoveryScanJob.get_jobs(instance).filter(status__in=JobStatusChoices.ENQUEUED_STATE_CHOICES):
            job.delete()
    except Exception as exc:
        logger.warning("Unable to remove discovery jobs for %s: %s", instance, exc)


def provision(sender, **kwargs):
    from .sync.provision import ensure_custom_fields_and_tags

    try:
        ensure_custom_fields_and_tags(force=True)
    except Exception as exc:  # database not fully migrated yet
        logger.debug("Skipping discovery custom field provisioning: %s", exc)


def connect_post_migrate(app_config):
    post_migrate.connect(provision, sender=app_config, dispatch_uid="netbox_nmap_discovery_provision")
