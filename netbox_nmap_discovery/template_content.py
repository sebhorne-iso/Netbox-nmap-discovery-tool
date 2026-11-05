from django.contrib.contenttypes.models import ContentType
from netbox.plugins import PluginTemplateExtension

from .choices import ProposalStatusChoices
from .models import DiscoveredHost, ProposedChange


def _address_for(obj):
    if obj._meta.label_lower == "ipam.ipaddress":
        return str(obj.address.ip)
    for attr in ("primary_ip4", "primary_ip6", "oob_ip"):
        ip = getattr(obj, attr, None)
        if ip is not None:
            return str(ip.address.ip)
    # Fall back to the address discovery last reached the device on
    host = DiscoveredHost.objects.filter(device=obj).order_by("-last_seen").only("address").first()
    return host.address if host else None


class RediscoverButton(PluginTemplateExtension):
    models = ["dcim.device", "ipam.ipaddress"]

    def buttons(self):
        request = self.context["request"]
        if not request.user.has_perm("netbox_nmap_discovery.run_scantarget"):
            return ""
        address = _address_for(self.context["object"])
        if not address:
            return ""
        return self.render("netbox_nmap_discovery/inc/rediscover_button.html", extra_context={"address": address})


class DeviceDiscoveryPanel(PluginTemplateExtension):
    models = ["dcim.device"]

    def right_page(self):
        request = self.context["request"]
        if not request.user.has_perm("netbox_nmap_discovery.view_discoveredhost"):
            return ""
        device = self.context["object"]
        hosts = DiscoveredHost.objects.restrict(request.user, "view").filter(device=device).order_by("-last_seen")
        device_ct = ContentType.objects.get_for_model(device)
        pending = ProposedChange.objects.restrict(request.user, "view").filter(
            object_type=device_ct, object_id=device.pk, status=ProposalStatusChoices.PENDING)
        if not hosts.exists() and not pending.exists():
            return ""
        return self.render("netbox_nmap_discovery/inc/device_panel.html", extra_context={
            "discovered_hosts": hosts[:5],
            "pending_proposals": pending[:5],
        })


template_extensions = [RediscoverButton, DeviceDiscoveryPanel]
