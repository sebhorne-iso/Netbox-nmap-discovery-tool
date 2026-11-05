import ipaddress

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views.generic import View
from netbox.object_actions import (
    AddObject,
    BulkDelete,
    BulkEdit,
    BulkExport,
    BulkImport,
    CloneObject,
    DeleteObject,
    EditObject,
)
from netbox.views import generic
from utilities.views import register_model_view

from . import filtersets, forms, tables
from .choices import ProposalKindChoices, ProposalStatusChoices
from .engine.results import HostResult, NmapHost, OpenPort
from .models import CredentialProfile, DeviceTypeAlias, DiscoveredHost, ProposedChange, RoleRule, ScanTarget


def _require_login(request):
    if not request.user.is_authenticated:
        raise PermissionDenied


def _safe_return(request, default):
    from utilities.request import safe_for_redirect

    url = request.POST.get("return_url") or request.GET.get("return_url")
    return url if url and safe_for_redirect(url) else default


#
# Credential profiles
#
@register_model_view(CredentialProfile, "list", path="", detail=False)
class CredentialProfileListView(generic.ObjectListView):
    queryset = CredentialProfile.objects.annotate(scan_target_count=Count("scan_targets"))
    table = tables.CredentialProfileTable
    filterset = filtersets.CredentialProfileFilterSet
    filterset_form = forms.CredentialProfileFilterForm
    actions = (AddObject, BulkExport, BulkDelete)


@register_model_view(CredentialProfile)
class CredentialProfileView(generic.ObjectView):
    queryset = CredentialProfile.objects.all()
    template_name = "netbox_nmap_discovery/credentialprofile.html"
    actions = (CloneObject, EditObject, DeleteObject)


@register_model_view(CredentialProfile, "add", detail=False)
@register_model_view(CredentialProfile, "edit")
class CredentialProfileEditView(generic.ObjectEditView):
    queryset = CredentialProfile.objects.all()
    form = forms.CredentialProfileForm


@register_model_view(CredentialProfile, "delete")
class CredentialProfileDeleteView(generic.ObjectDeleteView):
    queryset = CredentialProfile.objects.all()


@register_model_view(CredentialProfile, "bulk_delete", path="delete", detail=False)
class CredentialProfileBulkDeleteView(generic.BulkDeleteView):
    queryset = CredentialProfile.objects.all()
    filterset = filtersets.CredentialProfileFilterSet
    table = tables.CredentialProfileTable


#
# Scan targets
#
@register_model_view(ScanTarget, "list", path="", detail=False)
class ScanTargetListView(generic.ObjectListView):
    queryset = ScanTarget.objects.annotate(
        host_count=Count("discovered_hosts", distinct=True),
        pending_count=Count("proposed_changes", filter=Q(proposed_changes__status=ProposalStatusChoices.PENDING),
                            distinct=True),
    )
    table = tables.ScanTargetTable
    filterset = filtersets.ScanTargetFilterSet
    filterset_form = forms.ScanTargetFilterForm
    actions = (AddObject, BulkImport, BulkExport, BulkEdit, BulkDelete)


@register_model_view(ScanTarget)
class ScanTargetView(generic.ObjectView):
    queryset = ScanTarget.objects.prefetch_related("credentials")
    template_name = "netbox_nmap_discovery/scantarget.html"
    actions = (CloneObject, EditObject, DeleteObject)

    def get_extra_context(self, request, instance):
        from .jobs import DiscoveryScanJob

        pending = ProposedChange.objects.restrict(request.user, "view").filter(
            scan_target=instance, status=ProposalStatusChoices.PENDING)
        proposals_table = tables.ProposedChangeTable(pending[:25], exclude=("scan_target", "actions"))
        proposals_table.configure(request)
        jobs = DiscoveryScanJob.get_jobs(instance).order_by("-created")
        hosts = DiscoveredHost.objects.filter(scan_target=instance)
        return {
            "proposals_table": proposals_table,
            "pending_count": pending.count(),
            "last_job": jobs.exclude(status__in=("pending", "scheduled")).first(),
            "next_job": jobs.filter(status="scheduled").order_by("scheduled").first(),
            "host_count": hosts.count(),
            "managed_count": hosts.filter(Q(methods__contains=["snmp"]) | Q(methods__contains=["ssh"])).count(),
            "stale_count": hosts.filter(is_stale=True).count(),
            "can_run": request.user.has_perm("netbox_nmap_discovery.run_scantarget"),
        }


@register_model_view(ScanTarget, "add", detail=False)
@register_model_view(ScanTarget, "edit")
class ScanTargetEditView(generic.ObjectEditView):
    queryset = ScanTarget.objects.all()
    form = forms.ScanTargetForm


@register_model_view(ScanTarget, "delete")
class ScanTargetDeleteView(generic.ObjectDeleteView):
    queryset = ScanTarget.objects.all()


@register_model_view(ScanTarget, "bulk_import", path="import", detail=False)
class ScanTargetBulkImportView(generic.BulkImportView):
    queryset = ScanTarget.objects.all()
    model_form = forms.ScanTargetImportForm


@register_model_view(ScanTarget, "bulk_edit", path="edit", detail=False)
class ScanTargetBulkEditView(generic.BulkEditView):
    queryset = ScanTarget.objects.all()
    filterset = filtersets.ScanTargetFilterSet
    table = tables.ScanTargetTable
    form = forms.ScanTargetBulkEditForm


@register_model_view(ScanTarget, "bulk_delete", path="delete", detail=False)
class ScanTargetBulkDeleteView(generic.BulkDeleteView):
    queryset = ScanTarget.objects.all()
    filterset = filtersets.ScanTargetFilterSet
    table = tables.ScanTargetTable


@register_model_view(ScanTarget, "run")
class ScanTargetRunView(View):
    """Queue an immediate scan."""

    def post(self, request, pk):
        from .jobs import enqueue_scan

        _require_login(request)
        target = get_object_or_404(ScanTarget.objects.restrict(request.user, "run"), pk=pk)
        job = enqueue_scan(target, user=request.user)
        messages.success(request, _("Discovery scan of {target} queued.").format(target=target))
        return redirect(job.get_absolute_url())


#
# Role rules
#
@register_model_view(RoleRule, "list", path="", detail=False)
class RoleRuleListView(generic.ObjectListView):
    queryset = RoleRule.objects.select_related("role")
    table = tables.RoleRuleTable
    filterset = filtersets.RoleRuleFilterSet
    filterset_form = forms.RoleRuleFilterForm
    actions = (AddObject, BulkImport, BulkExport, BulkDelete)


@register_model_view(RoleRule)
class RoleRuleView(generic.ObjectView):
    queryset = RoleRule.objects.all()
    template_name = "netbox_nmap_discovery/rolerule.html"
    actions = (CloneObject, EditObject, DeleteObject)


@register_model_view(RoleRule, "add", detail=False)
@register_model_view(RoleRule, "edit")
class RoleRuleEditView(generic.ObjectEditView):
    queryset = RoleRule.objects.all()
    form = forms.RoleRuleForm


@register_model_view(RoleRule, "delete")
class RoleRuleDeleteView(generic.ObjectDeleteView):
    queryset = RoleRule.objects.all()


@register_model_view(RoleRule, "bulk_import", path="import", detail=False)
class RoleRuleBulkImportView(generic.BulkImportView):
    queryset = RoleRule.objects.all()
    model_form = forms.RoleRuleImportForm


@register_model_view(RoleRule, "bulk_delete", path="delete", detail=False)
class RoleRuleBulkDeleteView(generic.BulkDeleteView):
    queryset = RoleRule.objects.all()
    filterset = filtersets.RoleRuleFilterSet
    table = tables.RoleRuleTable


#
# Device type aliases
#
@register_model_view(DeviceTypeAlias, "list", path="", detail=False)
class DeviceTypeAliasListView(generic.ObjectListView):
    queryset = DeviceTypeAlias.objects.select_related("manufacturer", "device_type")
    table = tables.DeviceTypeAliasTable
    filterset = filtersets.DeviceTypeAliasFilterSet
    filterset_form = forms.DeviceTypeAliasFilterForm
    actions = (AddObject, BulkImport, BulkExport, BulkDelete)


@register_model_view(DeviceTypeAlias)
class DeviceTypeAliasView(generic.ObjectView):
    queryset = DeviceTypeAlias.objects.all()
    template_name = "netbox_nmap_discovery/devicetypealias.html"
    actions = (CloneObject, EditObject, DeleteObject)


@register_model_view(DeviceTypeAlias, "add", detail=False)
@register_model_view(DeviceTypeAlias, "edit")
class DeviceTypeAliasEditView(generic.ObjectEditView):
    queryset = DeviceTypeAlias.objects.all()
    form = forms.DeviceTypeAliasForm


@register_model_view(DeviceTypeAlias, "delete")
class DeviceTypeAliasDeleteView(generic.ObjectDeleteView):
    queryset = DeviceTypeAlias.objects.all()


@register_model_view(DeviceTypeAlias, "bulk_import", path="import", detail=False)
class DeviceTypeAliasBulkImportView(generic.BulkImportView):
    queryset = DeviceTypeAlias.objects.all()
    model_form = forms.DeviceTypeAliasImportForm


@register_model_view(DeviceTypeAlias, "bulk_delete", path="delete", detail=False)
class DeviceTypeAliasBulkDeleteView(generic.BulkDeleteView):
    queryset = DeviceTypeAlias.objects.all()
    filterset = filtersets.DeviceTypeAliasFilterSet
    table = tables.DeviceTypeAliasTable


#
# Review queue
#
@register_model_view(ProposedChange, "list", path="", detail=False)
class ProposedChangeListView(generic.ObjectListView):
    queryset = ProposedChange.objects.select_related("scan_target", "decided_by", "object_type")
    table = tables.ProposedChangeTable
    filterset = filtersets.ProposedChangeFilterSet
    filterset_form = forms.ProposedChangeFilterForm
    template_name = "netbox_nmap_discovery/proposedchange_list.html"
    actions = (BulkExport, BulkDelete)


@register_model_view(ProposedChange)
class ProposedChangeView(generic.ObjectView):
    queryset = ProposedChange.objects.all()
    template_name = "netbox_nmap_discovery/proposedchange.html"
    actions = (DeleteObject,)

    def get_extra_context(self, request, instance):
        host = None
        if instance.data.get("host"):
            host = HostResult.from_dict(instance.data["host"])
        return {
            "host": host,
            "problems": instance.data.get("problems") or [],
            "can_decide": instance.is_pending or instance.status == ProposalStatusChoices.FAILED,
            "is_device_proposal": instance.kind == ProposalKindChoices.CREATE_DEVICE,
        }


@register_model_view(ProposedChange, "edit")
class ProposedChangeEditView(View):
    """Edit the reviewer overrides of a new-device proposal (and optionally approve it)."""

    template_name = "netbox_nmap_discovery/proposedchange_edit.html"

    def _get(self, request, pk):
        _require_login(request)
        proposal = get_object_or_404(ProposedChange.objects.restrict(request.user, "change"), pk=pk)
        if proposal.kind != ProposalKindChoices.CREATE_DEVICE:
            messages.warning(request, _("Only new-device proposals have editable values."))
            return proposal, False
        return proposal, True

    def get(self, request, pk):
        proposal, editable = self._get(request, pk)
        if not editable:
            return redirect(proposal.get_absolute_url())
        form = forms.ProposalOverridesForm(initial=proposal.overrides or {})
        return render(request, self.template_name, {"object": proposal, "form": form,
                                                    "return_url": proposal.get_absolute_url()})

    def post(self, request, pk):
        from .sync.proposals import apply_proposal, required_permissions

        proposal, editable = self._get(request, pk)
        if not editable:
            return redirect(proposal.get_absolute_url())
        form = forms.ProposalOverridesForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"object": proposal, "form": form,
                                                        "return_url": proposal.get_absolute_url()})
        proposal.snapshot()
        proposal.overrides = form.to_overrides()
        proposal.save()
        if form.cleaned_data.get("approve"):
            if not request.user.has_perms(required_permissions(proposal)):
                raise PermissionDenied
            ok, message = apply_proposal(proposal, request.user)
            (messages.success if ok else messages.error)(request, message)
        else:
            messages.success(request, _("Saved overrides."))
        return redirect(proposal.get_absolute_url())


@register_model_view(ProposedChange, "delete")
class ProposedChangeDeleteView(generic.ObjectDeleteView):
    queryset = ProposedChange.objects.all()


@register_model_view(ProposedChange, "bulk_delete", path="delete", detail=False)
class ProposedChangeBulkDeleteView(generic.BulkDeleteView):
    queryset = ProposedChange.objects.all()
    filterset = filtersets.ProposedChangeFilterSet
    table = tables.ProposedChangeTable


class _DecisionMixin:
    def decide(self, request, proposals, approve: bool):
        from .sync.proposals import apply_proposal, reject_proposal, required_permissions

        applied = failed = rejected = 0
        for proposal in proposals:
            if approve:
                if not request.user.has_perms(required_permissions(proposal)):
                    messages.error(request, _("You do not have permission to apply {proposal}.").format(
                        proposal=proposal))
                    failed += 1
                    continue
                ok, message = apply_proposal(proposal, request.user)
                if ok:
                    applied += 1
                else:
                    failed += 1
                    messages.error(request, f"{proposal}: {message}")
            elif reject_proposal(proposal, request.user, reason=request.POST.get("reason", "")):
                rejected += 1
        if approve:
            if applied:
                messages.success(request, _("Applied {count} proposal(s).").format(count=applied))
        elif rejected:
            messages.success(request, _("Rejected {count} proposal(s).").format(count=rejected))


@register_model_view(ProposedChange, "approve")
class ProposedChangeApproveView(_DecisionMixin, View):
    def post(self, request, pk):
        _require_login(request)
        proposal = get_object_or_404(ProposedChange.objects.restrict(request.user, "change"), pk=pk)
        self.decide(request, [proposal], approve=True)
        return redirect(_safe_return(request, proposal.get_absolute_url()))


@register_model_view(ProposedChange, "reject")
class ProposedChangeRejectView(_DecisionMixin, View):
    def post(self, request, pk):
        _require_login(request)
        proposal = get_object_or_404(ProposedChange.objects.restrict(request.user, "change"), pk=pk)
        self.decide(request, [proposal], approve=False)
        return redirect(_safe_return(request, proposal.get_absolute_url()))


@register_model_view(ProposedChange, "bulk_approve", path="approve", detail=False)
class ProposedChangeBulkApproveView(_DecisionMixin, View):
    approve = True

    def post(self, request):
        _require_login(request)
        pks = [int(pk) for pk in request.POST.getlist("pk") if str(pk).isdigit()]
        proposals = ProposedChange.objects.restrict(request.user, "change").filter(
            pk__in=pks, status__in=(ProposalStatusChoices.PENDING, ProposalStatusChoices.FAILED)).order_by("created")
        if not pks:
            messages.warning(request, _("No proposals were selected."))
        else:
            # Apply devices before cables so cables to newly approved devices can be created later
            order = {ProposalKindChoices.CREATE_DEVICE: 0, ProposalKindChoices.CREATE_IP: 1,
                     ProposalKindChoices.UPDATE_DEVICE: 2, ProposalKindChoices.UPDATE_IP: 3,
                     ProposalKindChoices.CREATE_CABLE: 4}
            self.decide(request, sorted(proposals, key=lambda p: order.get(p.kind, 9)), approve=self.approve)
        return redirect(_safe_return(request, reverse("plugins:netbox_nmap_discovery:proposedchange_list")))


@register_model_view(ProposedChange, "bulk_reject", path="reject", detail=False)
class ProposedChangeBulkRejectView(ProposedChangeBulkApproveView):
    approve = False


#
# Discovered hosts
#
@register_model_view(DiscoveredHost, "list", path="", detail=False)
class DiscoveredHostListView(generic.ObjectListView):
    queryset = DiscoveredHost.objects.select_related("vrf", "scan_target", "device", "ip_address")
    table = tables.DiscoveredHostTable
    filterset = filtersets.DiscoveredHostFilterSet
    filterset_form = forms.DiscoveredHostFilterForm
    actions = (BulkExport, BulkDelete)


@register_model_view(DiscoveredHost)
class DiscoveredHostView(generic.ObjectView):
    queryset = DiscoveredHost.objects.all()
    template_name = "netbox_nmap_discovery/discoveredhost.html"
    actions = (DeleteObject,)

    def get_extra_context(self, request, instance):
        host = HostResult.from_dict(instance.data) if instance.data else None
        return {
            "host": host,
            "proposals": ProposedChange.objects.restrict(request.user, "view").filter(
                fingerprint__endswith=f":{instance.address}").order_by("-created")[:10],
        }


@register_model_view(DiscoveredHost, "delete")
class DiscoveredHostDeleteView(generic.ObjectDeleteView):
    queryset = DiscoveredHost.objects.all()


@register_model_view(DiscoveredHost, "bulk_delete", path="delete", detail=False)
class DiscoveredHostBulkDeleteView(generic.BulkDeleteView):
    queryset = DiscoveredHost.objects.all()
    filterset = filtersets.DiscoveredHostFilterSet
    table = tables.DiscoveredHostTable


@register_model_view(DiscoveredHost, "promote")
class DiscoveredHostPromoteView(View):
    """Turn a host that only nmap could see into a new-device proposal."""

    def post(self, request, pk):
        from .sync.context import SyncContext
        from .sync.devices import describe_new_device
        from .sync.proposals import ProposalWriter
        from .sync.runner import device_fingerprints
        from .utils import get_settings

        _require_login(request)
        if not request.user.has_perm("netbox_nmap_discovery.add_proposedchange"):
            raise PermissionDenied
        record = get_object_or_404(DiscoveredHost.objects.restrict(request.user, "view"), pk=pk)
        if record.device_id:
            messages.info(request, _("This host is already linked to {device}.").format(device=record.device))
            return redirect(record.device.get_absolute_url())
        host = HostResult.from_dict(record.data) if record.data else HostResult(address=record.address)
        if host.facts is None:
            from .engine.results import DeviceFacts

            host.facts = DeviceFacts(hostname=(record.hostname or record.dns_name or "").split(".")[0] or None)
            host.methods = host.methods or ["manual"]
        if not host.interfaces:
            from .engine.results import DiscoveredInterface
            from .sync.resolvers import ip_prefix_length

            host.interfaces = [DiscoveredInterface(
                name=get_settings().get("promoted_interface_name") or "eth0", type="other",
                mac_address=record.mac_address or None,
                ip_addresses=[f"{record.address}/{ip_prefix_length(record.address, record.vrf)}"],
            )]
        if host.nmap is None and record.open_ports:
            host.nmap = NmapHost(address=record.address, ports=[OpenPort.from_dict(p) for p in record.open_ports],
                                 ports_scanned=True)
        ctx = SyncContext(scan_target=record.scan_target, settings=get_settings())
        summary, changes, problems = describe_new_device(host, ctx)
        proposal = ProposalWriter(ctx).upsert(
            ProposalKindChoices.CREATE_DEVICE, device_fingerprints(host, record.vrf)[0], summary,
            {"host": host.to_dict(), "problems": problems}, [c.to_dict() for c in changes])
        messages.success(request, _("Created a new-device proposal; review the values and approve it."))
        return redirect(reverse("plugins:netbox_nmap_discovery:proposedchange_edit", args=[proposal.pk]))


#
# Rediscovery of a single device / address
#
class RediscoverView(View):
    template_name = "netbox_nmap_discovery/rediscover.html"

    @staticmethod
    def _targets_for(address, user):
        targets = ScanTarget.objects.restrict(user, "run").order_by("name")
        return [t for t in targets if t.covers(address)] if address else list(targets)

    def get(self, request):
        _require_login(request)
        address = request.GET.get("address", "").split("/")[0]
        try:
            ipaddress.ip_address(address)
        except ValueError:
            address = ""
        candidates = self._targets_for(address, request.user)
        form = forms.RediscoverForm(initial={"address": address, "scan_target": candidates[0] if candidates else None})
        form.fields["scan_target"].queryset = ScanTarget.objects.restrict(request.user, "run")
        return render(request, self.template_name, {
            "form": form, "address": address, "candidates": candidates,
            "return_url": _safe_return(request, reverse("plugins:netbox_nmap_discovery:discoveredhost_list")),
        })

    def post(self, request):
        from .jobs import enqueue_scan

        _require_login(request)
        form = forms.RediscoverForm(request.POST)
        form.fields["scan_target"].queryset = ScanTarget.objects.restrict(request.user, "run")
        if not form.is_valid():
            return render(request, self.template_name, {"form": form, "candidates": [], "return_url": ""})
        target = form.cleaned_data["scan_target"]
        address = form.cleaned_data["address"]
        if not target.covers(address) and not request.user.has_perm("netbox_nmap_discovery.change_scantarget",
                                                                      target):
            messages.error(request, _("{address} is outside scan target {target}. Rediscovering addresses outside a "
                                      "target requires permission to change it.").format(address=address,
                                                                                         target=target))
            return redirect(f"{reverse('plugins:netbox_nmap_discovery:rediscover')}?address={address}")
        job = enqueue_scan(target, user=request.user, address=address)
        messages.success(request, _("Rediscovery of {address} queued.").format(address=address))
        return redirect(job.get_absolute_url())
