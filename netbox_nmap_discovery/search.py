from netbox.search import SearchIndex

from .models import CredentialProfile, ScanTarget


class ScanTargetIndex(SearchIndex):
    model = ScanTarget
    fields = (
        ("name", 100),
        ("targets", 500),
        ("description", 500),
    )


class CredentialProfileIndex(SearchIndex):
    model = CredentialProfile
    fields = (
        ("name", 100),
        ("description", 500),
    )


indexes = (ScanTargetIndex, CredentialProfileIndex)
