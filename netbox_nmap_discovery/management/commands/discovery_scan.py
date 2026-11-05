from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from netbox_nmap_discovery.jobs import DiscoveryScanJob
from netbox_nmap_discovery.models import ScanTarget


class Command(BaseCommand):
    help = "Run a network discovery scan for one or more scan targets (in the foreground, or queued for the worker)."

    def add_arguments(self, parser):
        parser.add_argument("targets", nargs="*", help="Scan target names (default: all enabled targets)")
        parser.add_argument("--address", help="Rediscover a single address instead of the whole target")
        parser.add_argument("--user", help="Username to attribute changes to in the change log")
        parser.add_argument("--background", action="store_true", help="Queue the job for the RQ worker")

    def handle(self, *args, **options):
        queryset = ScanTarget.objects.all()
        if options["targets"]:
            queryset = queryset.filter(name__in=options["targets"])
            missing = set(options["targets"]) - set(queryset.values_list("name", flat=True))
            if missing:
                raise CommandError(f"Unknown scan target(s): {', '.join(sorted(missing))}")
        else:
            queryset = queryset.filter(enabled=True)
        user = None
        if options["user"]:
            user = get_user_model().objects.filter(username=options["user"]).first()
            if user is None:
                raise CommandError(f"Unknown user {options['user']}")
        for target in queryset:
            kwargs = {"address": options["address"]} if options["address"] else {}
            job = DiscoveryScanJob.enqueue(instance=target, user=user, immediate=not options["background"], **kwargs)
            if options["background"]:
                self.stdout.write(f"{target}: queued job {job.pk}")
                continue
            job.refresh_from_db()
            for entry in job.log_entries or []:
                self.stdout.write(f"  [{entry.get('level')}] {entry.get('message')}")
            style = self.style.SUCCESS if job.status == "completed" else self.style.ERROR
            self.stdout.write(style(f"{target}: {job.status} {job.data.get('sync') if job.data else ''}"))
