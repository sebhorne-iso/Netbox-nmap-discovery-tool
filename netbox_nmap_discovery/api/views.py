from core.api.serializers import JobSerializer
from django.db.models import Count
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from netbox.api.authentication import TokenPermissions
from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import MethodNotAllowed, PermissionDenied
from rest_framework.response import Response
from rest_framework.routers import APIRootView

from .. import filtersets
from ..choices import ProposalStatusChoices
from ..models import CredentialProfile, DeviceTypeAlias, DiscoveredHost, ProposedChange, RoleRule, ScanTarget
from . import serializers


class DiscoveryRootView(APIRootView):
    def get_view_name(self):
        return "Network Discovery"


class RunScanPermission(TokenPermissions):
    """POST actions on scan targets require the custom ``run_scantarget`` permission."""

    perms_map = {**TokenPermissions.perms_map, "POST": ["%(app_label)s.run_%(model_name)s"]}


class DecidePermission(TokenPermissions):
    """Approving/rejecting proposals requires ``change_proposedchange``."""

    perms_map = {**TokenPermissions.perms_map, "POST": ["%(app_label)s.change_%(model_name)s"]}


class CredentialProfileViewSet(NetBoxModelViewSet):
    queryset = CredentialProfile.objects.all()
    serializer_class = serializers.CredentialProfileSerializer
    filterset_class = filtersets.CredentialProfileFilterSet
    # Requests carry secrets: never persist them in background job records
    background_enabled = False


class ScanTargetViewSet(NetBoxModelViewSet):
    queryset = ScanTarget.objects.prefetch_related("credentials", "tags").annotate(
        host_count=Count("discovered_hosts", distinct=True))
    serializer_class = serializers.ScanTargetSerializer
    filterset_class = filtersets.ScanTargetFilterSet

    def get_permissions(self):
        if self.action == "run":
            return [RunScanPermission()]
        return super().get_permissions()

    @extend_schema(request=serializers.RunScanSerializer, responses={202: JobSerializer})
    @action(detail=True, methods=["post"])
    def run(self, request, pk):
        """Queue a discovery scan of this target (or rediscovery of a single ``address``)."""
        from ..jobs import enqueue_scan

        target = get_object_or_404(ScanTarget.objects.restrict(request.user, "run"), pk=pk)
        params = serializers.RunScanSerializer(data=request.data)
        params.is_valid(raise_exception=True)
        address = params.validated_data.get("address")
        if address and not target.covers(address) and not request.user.has_perm(
                "netbox_nmap_discovery.change_scantarget", target):
            raise PermissionDenied("Rediscovering an address outside the scan target requires permission to change it.")
        job = enqueue_scan(target, user=request.user, address=address)
        return Response(JobSerializer(job, context={"request": request}).data, status=status.HTTP_202_ACCEPTED)


class RoleRuleViewSet(NetBoxModelViewSet):
    queryset = RoleRule.objects.select_related("role").prefetch_related("scan_targets", "tags")
    serializer_class = serializers.RoleRuleSerializer
    filterset_class = filtersets.RoleRuleFilterSet


class DeviceTypeAliasViewSet(NetBoxModelViewSet):
    queryset = DeviceTypeAlias.objects.select_related("manufacturer", "device_type")
    serializer_class = serializers.DeviceTypeAliasSerializer
    filterset_class = filtersets.DeviceTypeAliasFilterSet


class ProposedChangeViewSet(NetBoxModelViewSet):
    queryset = ProposedChange.objects.select_related("scan_target", "object_type", "decided_by")
    serializer_class = serializers.ProposedChangeSerializer
    filterset_class = filtersets.ProposedChangeFilterSet

    def get_permissions(self):
        if self.action in ("approve", "reject", "bulk_approve", "bulk_reject"):
            return [DecidePermission()]
        return super().get_permissions()

    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed("POST", detail="Proposals are created by discovery scans.")

    def _decide(self, request, proposals, approve):
        from ..sync.proposals import apply_proposal, reject_proposal, required_permissions

        results = []
        for proposal in proposals:
            if approve:
                if not request.user.has_perms(required_permissions(proposal)):
                    results.append({"id": proposal.pk, "success": False,
                                    "message": "Insufficient permissions to apply this proposal"})
                    continue
                ok, message = apply_proposal(proposal, request.user)
            else:
                ok = reject_proposal(proposal, request.user, reason=request.data.get("reason", ""))
                message = "Rejected" if ok else f"Proposal is {proposal.status}"
            results.append({"id": proposal.pk, "success": ok, "message": message})
        return results

    def _queryset(self, request):
        return ProposedChange.objects.restrict(request.user, "change")

    @extend_schema(request=serializers.DecisionSerializer, responses={200: serializers.ProposedChangeSerializer})
    @action(detail=True, methods=["post"])
    def approve(self, request, pk):
        """Apply a pending (or failed) proposal."""
        proposal = get_object_or_404(self._queryset(request), pk=pk)
        result = self._decide(request, [proposal], approve=True)[0]
        proposal.refresh_from_db()
        data = serializers.ProposedChangeSerializer(proposal, context={"request": request}).data
        return Response({**data, "result": result},
                        status=status.HTTP_200_OK if result["success"] else status.HTTP_409_CONFLICT)

    @extend_schema(request=serializers.DecisionSerializer, responses={200: serializers.ProposedChangeSerializer})
    @action(detail=True, methods=["post"])
    def reject(self, request, pk):
        proposal = get_object_or_404(self._queryset(request), pk=pk)
        result = self._decide(request, [proposal], approve=False)[0]
        proposal.refresh_from_db()
        return Response({**serializers.ProposedChangeSerializer(proposal, context={"request": request}).data,
                         "result": result})

    def _bulk(self, request, approve):
        params = serializers.DecisionSerializer(data=request.data)
        params.is_valid(raise_exception=True)
        ids = params.validated_data.get("ids")
        if not ids:
            raise PermissionDenied("Provide a list of proposal ids.")
        proposals = self._queryset(request).filter(
            pk__in=ids, status__in=(ProposalStatusChoices.PENDING, ProposalStatusChoices.FAILED)).order_by("created")
        return Response({"results": self._decide(request, proposals, approve)})

    @extend_schema(request=serializers.DecisionSerializer, responses={200: dict})
    @action(detail=False, methods=["post"], url_path="approve")
    def bulk_approve(self, request):
        """Apply several proposals: ``{"ids": [1, 2, 3]}``."""
        return self._bulk(request, approve=True)

    @extend_schema(request=serializers.DecisionSerializer, responses={200: dict})
    @action(detail=False, methods=["post"], url_path="reject")
    def bulk_reject(self, request):
        return self._bulk(request, approve=False)


class DiscoveredHostViewSet(NetBoxModelViewSet):
    queryset = DiscoveredHost.objects.select_related("vrf", "scan_target", "device", "ip_address")
    serializer_class = serializers.DiscoveredHostSerializer
    filterset_class = filtersets.DiscoveredHostFilterSet
    http_method_names = ["get", "delete", "head", "options"]
