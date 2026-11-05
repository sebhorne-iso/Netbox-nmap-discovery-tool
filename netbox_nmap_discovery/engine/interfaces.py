"""Infer NetBox interface types from interface names, IANA ifType and speed."""
from __future__ import annotations

import re

__all__ = ("guess_interface_type", "is_management_interface")

# IANA ifType values (https://www.iana.org/assignments/ianaiftype-mib)
IFTYPE_ETHERNET = 6
IFTYPE_PPP = 23
IFTYPE_LOOPBACK = 24
IFTYPE_PROP_VIRTUAL = 53
IFTYPE_IEEE80211 = 71
IFTYPE_TUNNEL = 131
IFTYPE_L2VLAN = 135
IFTYPE_L3IPVLAN = 136
IFTYPE_BRIDGE = 209
IFTYPE_LAG = 161
IFTYPE_OTHER = 1

_VIRTUAL_IFTYPES = {IFTYPE_LOOPBACK, IFTYPE_PROP_VIRTUAL, IFTYPE_TUNNEL, IFTYPE_L2VLAN, IFTYPE_L3IPVLAN, IFTYPE_PPP,
                    150, 166, 131}  # 150 mplsTunnel, 166 mpls

_NAME_RULES = (
    # (regex, netbox type) - evaluated in order against the interface name
    (re.compile(r"^(port-?channel|po\d|bond|ae\d|lag|trk|bundle-ether|be\d|aggregate|agg|bridge-aggregation|"
                r"route-aggregation|eth-trunk)", re.I), "lag"),
    (re.compile(r"^[A-Za-z].*\.\d+$"), "virtual"),  # sub-interfaces / logical units (Gi0/0.100, ge-0/0/0.0)
    (re.compile(r"^(vlan|vl\d|irb|vlanif|bvi|bdi|svi|vif)", re.I), "virtual"),
    (re.compile(r"^(lo|loopback|dummy)", re.I), "virtual"),
    (re.compile(r"^(tunnel|tu\d|gre|ipip|wg|tun|tap|vti|st\d|gr-|ip-|lt-|ipsec|ssl\.)", re.I), "virtual"),
    (re.compile(r"^(br|bridge|virbr|vmbr|docker|cni|flannel)", re.I), "bridge"),
    (re.compile(r"^(null|nve|sit|vxlan|vtep|ens\d+\.\d+|eth\d+\.\d+)", re.I), "virtual"),
    (re.compile(r"^(wlan|wlp|wifi|radio|dot11)", re.I), "ieee802.11ac"),
    (re.compile(r"^(hundredgig|hu\d|et-|hge|100ge|hundred)", re.I), "100gbase-x-qsfp28"),
    (re.compile(r"^(fortygig|fo\d|40ge)", re.I), "40gbase-x-qsfpp"),
    (re.compile(r"^(twentyfivegig|twe\d|25ge)", re.I), "25gbase-x-sfp28"),
    (re.compile(r"^(tengig|te\d|xe-|10ge|tengige)", re.I), "10gbase-x-sfpp"),
    (re.compile(r"^(fivegig|fi\d)", re.I), "5gbase-t"),
    (re.compile(r"^(twogig|tw\d)", re.I), "2.5gbase-t"),
    (re.compile(r"^(gigabitethernet|gi\d|ge-|1ge)", re.I), "1000base-t"),
    (re.compile(r"^(fastethernet|fa\d)", re.I), "100base-tx"),
)

# speed (kbps) -> type for physical Ethernet when the name gives no hint
_SPEED_TYPES = (
    (400_000_000, "400gbase-x-qsfpdd"),
    (100_000_000, "100gbase-x-qsfp28"),
    (50_000_000, "50gbase-x-sfp56"),
    (40_000_000, "40gbase-x-qsfpp"),
    (25_000_000, "25gbase-x-sfp28"),
    (10_000_000, "10gbase-x-sfpp"),
    (5_000_000, "5gbase-t"),
    (2_500_000, "2.5gbase-t"),
    (1_000_000, "1000base-t"),
    (100_000, "100base-tx"),
    (10_000, "10base-t"),
)

_MGMT = re.compile(r"^(mgmt|management|ma\d|me\d|fxp0|em0$|oob|ipmi|bmc|idrac|ilo)", re.I)


def is_management_interface(name: str) -> bool:
    return bool(_MGMT.match(name or ""))


def guess_interface_type(name: str, if_type: int | None = None, speed_kbps: int | None = None) -> str:
    """Return a NetBox interface type slug (dcim.choices.InterfaceTypeChoices) for an interface."""
    name = name or ""
    # LAGs first: Cisco reports Port-channels with ifType 53 (propVirtual)
    if if_type == IFTYPE_LAG or _NAME_RULES[0][0].match(name):
        return "lag"
    if if_type == IFTYPE_BRIDGE:
        return "bridge"
    if if_type == IFTYPE_IEEE80211:
        return "ieee802.11ac"
    for regex, type_ in _NAME_RULES[1:]:
        if regex.match(name):
            return type_
    if if_type in _VIRTUAL_IFTYPES:
        return "virtual"
    if speed_kbps:
        for minimum, type_ in _SPEED_TYPES:
            if speed_kbps >= minimum:
                return type_
    if if_type == IFTYPE_ETHERNET:
        return "1000base-t"
    return "other"
