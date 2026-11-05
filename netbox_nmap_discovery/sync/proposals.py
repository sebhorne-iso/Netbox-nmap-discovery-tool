"""The review queue: creating/refreshing proposals during a scan, and approving or rejecting them."""
from __future__ import annotations

import logging

from dcim.models import Interface
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from ipam.models import IPAddress

from ..choices import ProposalKindChoices, ProposalStatusChoices, SyncModeChoices
from ..engine.results import HostResult
from ..models import DiscoveredHost, ProposedChange
from ..utils import get_settings
from .context import SyncContext
from .devices import ApplyError, create_device, reconcile_device

__all__ = ("ProposalWriter", "apply_proposal", "reject_proposal", "required_permissions")

logger = logging.getLogger("netbox_nmap_discovery.sync")

OPEN_STATUSES = (ProposalStatusChoices.PENDING, ProposalStatusChoices.FAILED)


class ProposalWriter:
    """Creates or refreshes proposals for one scan, de-duplicating by fingerprint."""

    def __init__(self, ctx: SyncContext):
        self.ctx = ctx
        self.touched: set[int] = set()

    def upsert(self, kind, fingerprint, summary, data, diff, obj=None):
        ctx = self.ctx
        existing = (ProposedChange.objects.filter(fingerprint=fingerprint)
                    .exclude(status__in=(ProposalStatusChoices.APPLIED, ProposalStatusChoices.SUPERSEDED))
                    .order_by("-created").first())
        if existing is not None and existing.status == ProposalStatusChoices.REJECTED:
            ctx.stats["proposals_previously_rejected"] += 1
            return existing
        object_type = ContentType.objects.get_for_model(obj) if obj is not None else None
        values = {
            "kind": kind,
            "summary": summary[:300],
            "data": data,
            "diff": diff,
            "scan_target": ctx.scan_target,
            "job": ctx.job,
            "object_type": object_type,
            "object_id": obj.pk if obj is not None else None,
        }
        if existing is not None:
            # Refresh in place without a change-log entry for every scan
            values["last_updated"] = timezone.now()
            ProposedChange.objects.filter(pk=existing.pk).update(**values)
            ctx.stats["proposals_refreshed"] += 1
            self.touched.add(existing.pk)
            return existing
        proposal = ProposedChange(fingerprint=fingerprint, status=ProposalStatusChoices.PENDING, **values)
        proposal.save()
        ctx.stats["proposals_created"] += 1
        self.touched.add(proposal.pk)
        return proposal

    def supersede(self, fingerprints, reason=""):
        count = ProposedChange.objects.filter(fingerprint__in=list(fingerprints), status__in=OPEN_STATUSES).update(
            status=ProposalStatusChoices.SUPERSEDED, error=reason, last_updated=timezone.now())
        if count:
            self.ctx.stats["proposals_superseded"] += count


def required_permissions(proposal) -> list[str]:
    return {
        ProposalKindChoices.CREATE_DEVICE: ["dcim.add_device", "dcim.add_interface", "ipam.add_ipaddress"],
        ProposalKindChoices.UPDATE_DEVICE: ["dcim.change_device", "dcim.add_interface", "dcim.change_interface",
                                            "ipam.change_ipaddress"],
        ProposalKindChoices.CREATE_CABLE: ["dcim.add_cable"],
        ProposalKindChoices.CREATE_IP: ["ipam.add_ipaddress"],
        ProposalKindChoices.UPDATE_IP: ["ipam.change_ipaddress"],
    }.get(proposal.kind, [])


def _context_for(proposal, user=None) -> SyncContext:
    # Approved proposals are applied in full (as if in automatic mode)
    return SyncContext(scan_target=proposal.scan_target, settings=get_settings(), mode=SyncModeChoices.AUTOMATIC,
                       user=user, full_scan=False)


def _apply(proposal, ctx: SyncContext):
    data = proposal.data or {}
    kind = proposal.kind
    if kind == ProposalKindChoices.CREATE_DEVICE:
        from .cables import sync_cables
        from .ipam import sync_address
        from .matching import match_device

        host = HostResult.from_dict(data.get("host"))
        device, _reason = match_device(host, ctx.vrf)
        if device is not None:
            reconcile_device(device, host, ctx, apply=True, include_sensitive=True)
            message = f"Matched existing device {device}; updated it instead of creating a new one"
        else:
            device = create_device(host, ctx, proposal.overrides)
            message = f"Created device {device}"
        ip = sync_address(host, ctx, device)
        # Link the discovery record straight away (otherwise only done by the next scan)
        DiscoveredHost.objects.filter(address=host.address, vrf=ctx.vrf).update(
            device=device, **({"ip_address": ip} if ip is not None else {}))
        if host.neighbors:
            # Neighbour cables for the new device go through the normal review flow
            cable_ctx = SyncContext(scan_target=proposal.scan_target, settings=ctx.settings,
                                    mode=SyncModeChoices.HYBRID, full_scan=False)
            sync_cables([(host, device)], cable_ctx, ProposalWriter(cable_ctx))
        return device, message

    if kind == ProposalKindChoices.UPDATE_DEVICE:
        device = proposal.object
        if device is None:
            raise ApplyError("The device no longer exists.")
        host = HostResult.from_dict(data.get("host"))
        changes = reconcile_device(device, host, ctx, apply=True, include_sensitive=True)
        failed = [c for c in changes if c.error]
        if failed and not any(c.applied for c in changes):
            raise ApplyError("; ".join(c.describe() for c in failed)[:2000])
        message = f"Applied {sum(1 for c in changes if c.applied)} change(s) to {device}"
        if failed:
            message += f"; {len(failed)} failed: " + "; ".join(c.describe() for c in failed)[:1000]
        return device, message

    if kind == ProposalKindChoices.CREATE_CABLE:
        from .cables import create_cable

        a = Interface.objects.filter(pk=data.get("a_interface")).first()
        b = Interface.objects.filter(pk=data.get("b_interface")).first()
        if a is None or b is None:
            raise ApplyError("One of the interfaces no longer exists.")
        if a.cable_id or b.cable_id:
            if a.cable_id and a.cable_id == b.cable_id:
                return a.cable, "Cable already exists"
            raise ApplyError(f"{'A' if a.cable_id else 'B'}-side interface is already connected to another cable.")
        cable = create_cable(a, b)
        return cable, f"Created cable {cable}"

    if kind == ProposalKindChoices.CREATE_IP:
        from .ipam import create_ip_address, find_ip

        existing = find_ip(data["address"], ctx.vrf)
        if existing is not None:
            return existing, f"{existing} already exists"
        ip = create_ip_address(data["address"], data.get("prefix_length", 32), data.get("metadata"), ctx,
                               dns_name=data.get("dns_name", ""))
        return ip, f"Created IP address {ip}"

    if kind == ProposalKindChoices.UPDATE_IP:
        ip = IPAddress.objects.filter(pk=data.get("ip_id")).first()
        if ip is None:
            raise ApplyError("The IP address no longer exists.")
        ip.snapshot()
        ip.dns_name = data.get("dns_name", ip.dns_name)
        ip.full_clean()
        ip.save()
        return ip, f"Updated IP address {ip}"

    raise ApplyError(f"Unknown proposal kind {kind}")


def apply_proposal(proposal: ProposedChange, user=None) -> tuple[bool, str]:
    """Apply a pending (or previously failed) proposal. Returns ``(success, message)``."""
    if proposal.status not in OPEN_STATUSES:
        return False, f"Proposal is {proposal.get_status_display().lower()}"
    ctx = _context_for(proposal, user)
    try:
        with transaction.atomic():
            obj, message = _apply(proposal, ctx)
    except (ApplyError, ValidationError) as exc:
        text = "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc)
        ProposedChange.objects.filter(pk=proposal.pk).update(
            status=ProposalStatusChoices.FAILED, error=text[:2000], decided_by=user, decided_at=timezone.now(),
            last_updated=timezone.now())
        proposal.refresh_from_db()
        return False, text
    proposal.snapshot()
    proposal.status = ProposalStatusChoices.APPLIED
    proposal.error = message[:2000] if message else ""
    proposal.decided_by = user
    proposal.decided_at = timezone.now()
    if obj is not None and getattr(obj, "pk", None):
        proposal.object_type = ContentType.objects.get_for_model(obj)
        proposal.object_id = obj.pk
    proposal.save()
    return True, message


def reject_proposal(proposal: ProposedChange, user=None, reason: str = "") -> bool:
    if proposal.status not in OPEN_STATUSES:
        return False
    proposal.snapshot()
    proposal.status = ProposalStatusChoices.REJECTED
    proposal.decided_by = user
    proposal.decided_at = timezone.now()
    proposal.error = reason[:2000]
    proposal.save()
    return True
