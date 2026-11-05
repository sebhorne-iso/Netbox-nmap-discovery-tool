from django.core.management.base import BaseCommand
from django.db import transaction

from netbox_nmap_discovery import crypto
from netbox_nmap_discovery.models import ENCRYPTED_FIELDS, CredentialProfile


class Command(BaseCommand):
    help = (
        "Re-encrypt all stored credentials with the current encryption key. Configure the new key first in "
        "encryption_key as a list: [new_key, old_key]; after rotation the old key can be removed."
    )

    def handle(self, *args, **options):
        count = 0
        with transaction.atomic():
            for profile in CredentialProfile.objects.select_for_update():
                for field_name in ENCRYPTED_FIELDS:
                    token = getattr(profile, field_name)
                    if token:
                        setattr(profile, field_name, crypto.rotate(token))
                # Bulk-style update: secrets are excluded from the change log anyway
                CredentialProfile.objects.filter(pk=profile.pk).update(
                    **{f: getattr(profile, f) for f in ENCRYPTED_FIELDS})
                count += 1
        self.stdout.write(self.style.SUCCESS(f"Re-encrypted {count} credential profile(s)."))
