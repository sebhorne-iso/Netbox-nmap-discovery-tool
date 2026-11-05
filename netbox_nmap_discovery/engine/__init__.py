"""
Framework-independent discovery engine.

Nothing in this package imports Django or NetBox: it turns scan parameters and credentials into a list of
``HostResult`` results, which the ``sync`` package then reconciles with NetBox.
"""
from .results import ArpEntry, DeviceFacts, DiscoveredInterface, HostResult, Neighbor, NmapHost, OpenPort
from .runner import DiscoveryEngine, ScanRequest, ScanResult
from .snmp import SnmpCredential
from .ssh import SshCredential

__all__ = (
    "ArpEntry",
    "DeviceFacts",
    "HostResult",
    "DiscoveredInterface",
    "DiscoveryEngine",
    "Neighbor",
    "NmapHost",
    "OpenPort",
    "ScanRequest",
    "ScanResult",
    "SnmpCredential",
    "SshCredential",
)
