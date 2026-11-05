"""Build cables from LLDP/CDP neighbour data."""
from __future__ import annotations

from dcim.choices import LinkStatusChoices
from dcim.models import Cable, Interface
from django.core.exceptions import ValidationError
from django.db import transaction

from ..choices import ProposalKindChoices
from .context import Change, SyncContext
from .devices import NO_CABLE_TYPES
from .matching import find_interface, match_neighbor_device
from .provision import TAG_DISCOVERED, get_tag

__all__ = ("create_cable", "sync_cables")


def _cable_allowed(interface) -> bool:
    return (interface.type not in NO_CABLE_TYPES and not interface.is_wireless and not interface.mark_connected
            and not interface.is_virtual)


def create_cable(a: Interface, b: Interface, label: str = ""):
    cable = Cable(a_terminations=[a], b_terminations=[b], status=LinkStatusChoices.STATUS_CONNECTED, label=label)
    cable.full_clean()
    cable.save()
    cable.tags.add(get_tag(TAG_DISCOVERED))
    return cable


def sync_cables(pairs, ctx: SyncContext, proposals=None):
    """``pairs`` is an iterable of ``(HostResult, Device)`` for devices that were polled successfully."""
    cache = {}
    handled = set()
    for host, device in pairs:
        for neighbor in host.neighbors:
            local = find_interface(device, neighbor.local_interface)
            if local is None:
                ctx.stats["neighbors_unknown_local_interface"] += 1
                continue
            remote_device = match_neighbor_device(neighbor, ctx.vrf, cache)
            if remote_device is None:
                ctx.stats["neighbors_not_in_netbox"] += 1
                remote = neighbor.remote_name or neighbor.remote_chassis_id
                ctx.debug(f"{device}: {neighbor.protocol.upper()} neighbour {remote} on {local.name} is not in NetBox")
                continue
            if remote_device.pk == device.pk:
                continue
            remote = find_interface(remote_device, neighbor.remote_interface, neighbor.remote_interface_description)
            if remote is None:
                ctx.stats["neighbors_unknown_remote_interface"] += 1
                ctx.debug(f"{device} {local.name}: interface {neighbor.remote_interface} not found on {remote_device}")
                continue
            pair = tuple(sorted((local.pk, remote.pk)))
            if pair in handled:
                continue
            handled.add(pair)
            if not (_cable_allowed(local) and _cable_allowed(remote)):
                continue

            if local.cable_id and local.cable_id == remote.cable_id:
                ctx.mark_seen(local.cable)
                continue
            if local.cable_id or remote.cable_id:
                ctx.stats["cable_conflicts"] += 1
                side = "the local" if local.cable_id else "the remote"
                ctx.warning(f"{neighbor.protocol.upper()} reports {device} {local.name} <-> {remote_device} "
                            f"{remote.name}, but {side} interface is already cabled elsewhere in NetBox")
                continue

            description = f"{device} {local.name} ↔ {remote_device} {remote.name}"
            if ctx.auto_apply_new:
                try:
                    with transaction.atomic():
                        cable = create_cable(local, remote)
                    ctx.mark_seen(cable)
                    ctx.stats["cables_created"] += 1
                    ctx.info(f"Created cable {description} ({neighbor.protocol.upper()})")
                except ValidationError as exc:
                    ctx.warning(f"Unable to create cable {description}: {'; '.join(exc.messages)}")
            elif proposals is not None:
                a, b = (local, remote) if local.pk < remote.pk else (remote, local)
                proposals.upsert(
                    kind=ProposalKindChoices.CREATE_CABLE,
                    fingerprint=f"create-cable:{a.pk}:{b.pk}",
                    summary=f"New cable {description}"[:300],
                    data={
                        "a_interface": a.pk, "a_device": a.device_id, "a_name": f"{a.device} {a.name}",
                        "b_interface": b.pk, "b_device": b.device_id, "b_name": f"{b.device} {b.name}",
                        "protocol": neighbor.protocol,
                    },
                    diff=[Change("cable", "create", description, {"source": neighbor.protocol.upper()}).to_dict()],
                )
