"""Synchronise a complete scan result into NetBox according to the scan target's sync mode."""
from __future__ import annotations

import logging

from django.db import transaction

from ..choices import ProposalKindChoices, SyncModeChoices
from ..engine.results import HostResult
from ..engine.runner import ScanResult
from .cables import sync_cables
from .context import SyncContext
from .devices import ApplyError, create_device, describe_new_device, reconcile_device, touch_device
from .ipam import sync_address
from .matching import match_device
from .proposals import ProposalWriter
from .provision import ensure_custom_fields_and_tags
from .resolvers import resolve_site_and_location
from .stale import process_sightings, update_discovered_hosts

__all__ = ("device_fingerprints", "sync_host", "synchronize")


def device_fingerprints(host: HostResult, vrf=None) -> list[str]:
    prints = []
    if host.facts and host.facts.serial:
        prints.append(f"create-device:serial:{host.facts.serial.strip().lower()}")
    prints.append(f"create-device:addr:{vrf.pk if vrf else 0}:{host.address}")
    return prints


def _propose_new_device(host: HostResult, ctx: SyncContext, proposals: ProposalWriter, reason=""):
    summary, changes, problems = describe_new_device(host, ctx)
    data = {"host": host.to_dict(), "problems": problems}
    diff = [c.to_dict() for c in changes]
    proposal = proposals.upsert(ProposalKindChoices.CREATE_DEVICE, device_fingerprints(host, ctx.vrf)[0], summary,
                                data, diff)
    if reason:
        ctx.info(f"{host.address}: {reason}; proposed new device")
    return proposal


def sync_host(host: HostResult, ctx: SyncContext, proposals: ProposalWriter):
    """Synchronise one host. Returns ``(device or None, ip or None)``."""
    device = None
    if host.managed:
        site, _location = resolve_site_and_location(host.address, ctx.scan_target)
        device, reason = match_device(host, ctx.vrf, site)
        if device is not None:
            ctx.debug(f"{host.address}: matched {device} by {reason}")
            proposals.supersede(device_fingerprints(host, ctx.vrf), reason=f"Matched existing device {device}")
            ctx.stats["devices_matched"] += 1
            if ctx.mode == SyncModeChoices.AUTOMATIC:
                changes = reconcile_device(device, host, ctx, apply=True, include_sensitive=True)
            elif ctx.mode == SyncModeChoices.HYBRID:
                changes = reconcile_device(device, host, ctx, apply=True, include_sensitive=False)
                changes = [c for c in changes if c.sensitive]
            else:
                changes = reconcile_device(device, host, ctx, apply=False)
                ctx.mark_seen(device)
                ctx.polled_devices.add(device.pk)
                touch_device(device, host, ctx)
            pending = [c for c in changes if not c.applied]
            applied = [c for c in changes if c.applied]
            if applied:
                ctx.stats["device_changes_applied"] += len(applied)
            if pending:
                proposals.upsert(
                    ProposalKindChoices.UPDATE_DEVICE, f"update-device:{device.pk}",
                    f"Update {device}: {len(pending)} change(s)", {"host": host.to_dict()},
                    [c.to_dict() for c in pending], obj=device,
                )
        else:
            if reason != "no match":
                ctx.warning(f"{host.address}: could not match an existing device unambiguously ({reason})")
            if ctx.mode == SyncModeChoices.AUTOMATIC and reason == "no match":
                try:
                    with transaction.atomic():
                        device = create_device(host, ctx)
                    ctx.info(f"{host.address}: created device {device}")
                except ApplyError as exc:
                    device = None
                    _propose_new_device(host, ctx, proposals, reason=str(exc))
            else:
                _propose_new_device(host, ctx, proposals)
    ip = sync_address(host, ctx, device, proposals)
    return device, ip


def synchronize(result: ScanResult, ctx: SyncContext) -> dict:
    ensure_custom_fields_and_tags()
    proposals = ProposalWriter(ctx)
    records = []
    polled = []
    for host in result.hosts:
        try:
            with transaction.atomic():
                device, ip = sync_host(host, ctx, proposals)
        except Exception as exc:  # isolate failures to one host
            ctx.log(logging.ERROR, f"{host.address}: synchronisation failed: {exc!r}")
            device, ip = None, None
        records.append((host, device, ip))
        if device is not None and device.pk and host.managed and host.neighbors:
            polled.append((host, device))

    if ctx.scan_target is None or ctx.scan_target.collect_neighbors:
        try:
            with transaction.atomic():
                sync_cables(polled, ctx, proposals)
        except Exception as exc:
            ctx.log(logging.ERROR, f"Cable synchronisation failed: {exc!r}")

    with transaction.atomic():
        update_discovered_hosts(records, ctx)
        process_sightings(ctx)

    ctx.stats["hosts"] = len(result.hosts)
    ctx.stats["managed_hosts"] = sum(1 for h in result.hosts if h.managed)
    return dict(ctx.stats)
