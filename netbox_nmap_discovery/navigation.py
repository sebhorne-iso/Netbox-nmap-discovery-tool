from django.utils.translation import gettext_lazy as _
from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem


def _add_button(model):
    return PluginMenuButton(
        link=f"plugins:netbox_nmap_discovery:{model}_add",
        title=_("Add"),
        icon_class="mdi mdi-plus-thick",
        permissions=[f"netbox_nmap_discovery.add_{model}"],
    )


menu = PluginMenu(
    label=_("Discovery"),
    icon_class="mdi mdi-radar",
    groups=(
        (_("Scanning"), (
            PluginMenuItem(
                link="plugins:netbox_nmap_discovery:scantarget_list",
                link_text=_("Scan Targets"),
                permissions=["netbox_nmap_discovery.view_scantarget"],
                buttons=(_add_button("scantarget"),),
            ),
            PluginMenuItem(
                link="plugins:netbox_nmap_discovery:credentialprofile_list",
                link_text=_("Credentials"),
                permissions=["netbox_nmap_discovery.view_credentialprofile"],
                buttons=(_add_button("credentialprofile"),),
            ),
        )),
        (_("Results"), (
            PluginMenuItem(
                link="plugins:netbox_nmap_discovery:proposedchange_list",
                link_text=_("Review Queue"),
                permissions=["netbox_nmap_discovery.view_proposedchange"],
            ),
            PluginMenuItem(
                link="plugins:netbox_nmap_discovery:discoveredhost_list",
                link_text=_("Discovered Hosts"),
                permissions=["netbox_nmap_discovery.view_discoveredhost"],
            ),
        )),
        (_("Rules"), (
            PluginMenuItem(
                link="plugins:netbox_nmap_discovery:rolerule_list",
                link_text=_("Role Rules"),
                permissions=["netbox_nmap_discovery.view_rolerule"],
                buttons=(_add_button("rolerule"),),
            ),
            PluginMenuItem(
                link="plugins:netbox_nmap_discovery:devicetypealias_list",
                link_text=_("Device Type Aliases"),
                permissions=["netbox_nmap_discovery.view_devicetypealias"],
                buttons=(_add_button("devicetypealias"),),
            ),
        )),
    ),
)
