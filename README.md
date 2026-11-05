# NetBox Network Discovery

A NetBox 4.x plugin that scans your network with **nmap**, enriches what it finds over **SNMP** and **SSH**
(NAPALM / Netmiko), and synchronises the results into **NetBox DCIM and IPAM**. That covers devices, interfaces,
MAC addresses, IP addresses and **cables built from LLDP/CDP neighbours**. New devices and cables go through a
**review queue** before they reach NetBox.

```
 nmap sweep ──► SNMP (v2c/v3) ──► SSH (NAPALM / Netmiko) ──► merge ──► match ──► sync ──► NetBox DCIM + IPAM
  ports, OS,     facts, ifTable,    facts, serial, CDP,        │         │          │
  MAC/vendor     IPs, LLDP/CDP,     LLDP, ARP                  │         │          ├─ auto-apply updates to known objects
                 ENTITY-MIB, ARP                               │         │          └─ review queue: new devices & cables
                                                               │         └─ serial ▸ MAC ▸ hostname ▸ IP
                         LLDP neighbours / ARP entries ◄───────┘  (follow-up polling, ARP-only hosts)
```

## Features

- **Discovery**: nmap ping/port/OS scans with safe built-in profiles. SNMP v2c/v3 collects facts, interfaces,
  IPv4/IPv6 addresses, LAG membership, ENTITY-MIB serial and model, LLDP, CDP and ARP. SSH collection covers
  Cisco IOS/IOS-XE/NX-OS, Junos and EOS through NAPALM, and FortiOS, PAN-OS, AOS-CX, ArubaOS-Switch (ProCurve)
  and Linux through Netmiko.
- **Neighbour harvesting**: LLDP/CDP neighbours inside a scan target are polled even when nmap misses them. ARP
  tables reveal hosts behind firewalls, and supply MAC addresses for routed hosts.
- **Data written to NetBox**:
  - Devices: device type, role, site, location, tenant, platform, serial and primary IP.
  - Interfaces: type, speed, MTU, description, enabled state and LAG parent.
  - MAC addresses, using the NetBox 4.2+ MACAddress model.
  - IP addresses, assigned to interfaces and with DNS names.
  - Cables.
  - Discovery custom fields: last seen, MAC, vendor, OS and open ports.
- **Hybrid write mode**, chosen per scan target:
  - *Hybrid* (default): changes to objects already in NetBox are applied automatically. New devices, new cables
    and risky changes (a changed serial, an IP that is assigned elsewhere) wait in the review queue.
  - *Review everything*: every change waits for review.
  - *Fully automatic*: everything is applied directly.
- **Review queue**: see the exact diff, override the name, site, role, device type or platform before approving,
  and approve or reject in bulk from the UI or the API. Rejected proposals are not re-proposed by later scans.
- **Matching**: an existing device is matched by serial number, then interface MAC address, then hostname/FQDN,
  then IP address. HSRP, VRRP and other virtual MACs are ignored. Ambiguous matches are never guessed.
- **Resolution rules**:
  - Site comes from the scan target, unless a site-scoped NetBox prefix contains the IP; that prefix wins.
  - Device role comes from ordered **role rules** (hostname, sysDescr, sysObjectID, platform, vendor, model, MAC
    vendor or open-port conditions), falling back to the target's default role.
  - Device type comes from **device type aliases**, then an exact model or part-number match. If nothing matches,
    a minimal device type is created and tagged for review.
- **Stale detection**: an object is counted as missed only when the scan could have seen it. After N consecutive
  misses it is tagged `discovery-stale` and, optionally, IPs are set to *Deprecated*. Both are reversed when the
  object reappears. Nothing is ever deleted.
- **Hosts that only nmap can see** (printers, workstations, IoT) are recorded in IPAM only, with metadata. You can
  promote any of them to a device from the *Discovered Hosts* list.
- **Scan triggers**: on demand from the UI, recurring schedules (NetBox's job scheduler), the REST API, a
  **Rediscover** button on every device and IP page, and a management command.
- **Security**:
  - Credentials are encrypted at rest (Fernet) and never displayed or returned by the API.
  - They are excluded from the change log and from background API job records.
  - nmap runs without a shell, and custom arguments are checked against an allow-list, so file output, NSE
    scripts and `-iL` are refused.
  - All changes go through NetBox's change log, attributed to the user who ran or approved the scan.

## Compatibility

| Component | Supported |
|-----------|-----------|
| NetBox | 4.5 – 4.7 (developed and tested against **4.7.4**) |
| Python | 3.12+ |
| nmap | 7.80+ on the host or container that runs the NetBox RQ worker |
| Deployment | [netbox-docker](https://github.com/netbox-community/netbox-docker) (files in [`docker/`](docker/)) or bare metal |

## Installation

### netbox-docker

1. Copy the files from [`docker/`](docker/) into your `netbox-docker` checkout:

   ```
   netbox-docker/
   ├── Dockerfile-Plugins
   ├── docker-compose.override.yml
   ├── plugin_requirements.txt
   └── configuration/plugins.py
   ```

2. Generate an encryption key for stored credentials and add it to `netbox-docker/.env`:

   ```bash
   echo "NETBOX_DISCOVERY_ENCRYPTION_KEY=$(openssl rand -base64 32)" >> .env
   ```

3. Build and start:

   ```bash
   docker compose build --no-cache
   ```

   ```bash
   docker compose up -d
   ```

   Migrations run automatically when the `netbox` container starts.

The override grants the **`netbox-worker`** container `NET_RAW` and `NET_ADMIN` and sets `NMAP_PRIVILEGED=1`, so
nmap can run SYN scans and OS detection as the non-root `netbox` user. The image installs nmap with file
capabilities. Without these capabilities nmap fails to start in that container. Without them you can still set
`nmap_privileged: False` to use unprivileged TCP-connect scans without OS detection.

> **MAC addresses and Docker networking.** nmap learns MAC addresses only for hosts on a directly attached L2
> segment. Behind Docker's bridge network it will not see them, although SNMP/SSH ARP harvesting still supplies MACs
> for most hosts. To scan local segments natively, uncomment `network_mode: host` for the worker, as described in
> the override file.

### Bare metal / VM

```bash
sudo apt-get install -y nmap libcap2-bin
```

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
```

```bash
source /opt/netbox/venv/bin/activate && pip install "netbox-nmap-discovery @ https://github.com/sebhorne-iso/Netbox-nmap-discovery-tool/archive/refs/heads/main.tar.gz"
```

Add the plugin to `configuration.py`, see [Configuration](#configuration), and set `NMAP_PRIVILEGED=1` in the
environment of the `netbox-rq` service (or `nmap_privileged: True`). Then:

```bash
cd /opt/netbox/netbox && python manage.py migrate && sudo systemctl restart netbox netbox-rq
```

Also add the package to `/opt/netbox/local_requirements.txt` so NetBox upgrades keep it installed.

## Configuration

```python
PLUGINS = ["netbox_nmap_discovery"]
PLUGINS_CONFIG = {
    "netbox_nmap_discovery": {
        "encryption_key": "<random string>",   # or env NETBOX_DISCOVERY_ENCRYPTION_KEY
    },
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `encryption_key` | `None` | Key for stored credentials. A string, or a list `[new, old, …]` for rotation. Falls back to `NETBOX_DISCOVERY_ENCRYPTION_KEY`, then to a key derived from `SECRET_KEY` (a warning is logged, and changing `SECRET_KEY` would then make stored credentials unreadable). |
| `nmap_path` | `"nmap"` | nmap executable. |
| `nmap_privileged` | `None` | `None` auto-detects (running as root, or `NMAP_PRIVILEGED=1`). `True` assumes raw-socket rights and passes `--privileged`. `False` uses `-sT` with no OS detection. |
| `nmap_timeout` | `3600` | Seconds before an nmap run is aborted. |
| `snmp_timeout` / `snmp_retries` | `2` / `1` | Per-request SNMP timeout (seconds) and retries. |
| `ssh_timeout` | `30` | SSH connect/command timeout (seconds). |
| `ssh_autodetect` | `True` | Use Netmiko SSHDetect when the platform is unknown but SSH is open. |
| `max_workers` | `16` | Hosts polled in parallel over SNMP/SSH. |
| `poll_lldp_neighbors` | `True` | Poll LLDP/CDP neighbours whose management address is inside the scan target but was not found by nmap. |
| `interface_exclude_regex` | *(pseudo interfaces)* | Interfaces never synchronised, such as `lo`, `Null0`, `docker0`, `veth…` and stack ports. |
| `overwrite_interface_descriptions` | `True` | Copy interface descriptions (ifAlias) from devices into NetBox. Empty descriptions never overwrite. |
| `last_seen_update_hours` | `24` | Minimum interval between `discovery_last_seen` updates, which limits change-log noise. |
| `manufacturer_aliases` | `{}` | Map vendor strings to your NetBox manufacturer names, e.g. `{"Cisco Systems, Inc.": "Cisco"}`. |
| `device_type_u_height` | `1` | U height for automatically created device types. |
| `scheduled_job_user` | `None` | Username used for change-log attribution when a scheduled job has no user. |
| `promoted_interface_name` | `"eth0"` | Interface created when promoting an nmap-only host to a device. |

## Using it

### 1. Credentials (*Discovery → Credentials*)

Create SNMP v2c, SNMPv3 or SSH credential profiles. Secrets are encrypted when saved. Leave a secret field blank
when editing to keep the stored value. Profiles are tried in ascending **priority**. After the first scan, the
credential that worked for each host is tried first. *Connection options* passes extra NAPALM `optional_args` or
Netmiko arguments, for example `{"transport": "ssh"}` for Arista EOS without eAPI.

### 2. Scan targets (*Discovery → Scan Targets*)

A scan target defines what to scan and how to treat the results:

- **Targets / exclusions**: one entry per line, as an IP, a CIDR (/16 or smaller), an `a.b.c.x-y` range or a
  hostname. Put fragile OT/PLC ranges in exclusions.
- **Scan profile**:

  | Profile | nmap | Use |
  |---------|------|-----|
  | Discovery only | `-sn -T3` | Lightest. Finds live hosts, then relies on SNMP/SSH. |
  | **Conservative** (default) | top 100 TCP ports, `-T3`, OS detection, max 2 retries | General use. |
  | Thorough | top 1000 TCP ports, `-sV --version-light`, OS detection, `-T4` | Richer data, noisier. |
  | Custom | your arguments (allow-listed) | e.g. `-sS -p 22,161,443 -T2`. |

- **Defaults**: the site, location, tenant, VRF, default role and status given to new devices.
- **Sync mode**: hybrid, review or automatic. **Stale threshold**: how many missed scans before an object is
  flagged. **Deprecate stale IPs**: also set stale IPs to Deprecated.
- **Schedule interval**: minutes between automatic runs. Leave blank for manual-only.

### 3. Rules (optional)

- **Role rules**: ordered by weight, and every condition set on a rule must match. Examples:
  - hostname `^core-` → *Core Switch*
  - open ports `9100,631` → *Printer*
  - platform *Fortinet FortiOS* → *Firewall*
  - sysObjectID prefix `1.3.6.1.4.1.9.1.` → *Cisco device*

  Rules can be limited to specific scan targets.
- **Device type aliases**: map a reported model (exact or regex) to an existing device type, e.g.
  `WS-C3850-48P-L` → *Catalyst 3850-48P*. Combine with the
  [device-type library](https://github.com/netbox-community/devicetype-library) for full interface templates.

### 4. Run scans

- **UI**: *Run scan now* on a scan target. Progress and logs appear in the job, under the target's *Jobs* tab.
- **Schedule**: set *Schedule interval*. The next run is created automatically and shown on the target page.
- **Rediscover**: the button on any device or IP address page re-polls only that address.
- **API**: `POST /api/plugins/discovery/scan-targets/{id}/run/`, with optional body `{"address": "10.0.0.1"}`.
- **CLI**: `manage.py discovery_scan [target …] [--address IP] [--user USER] [--background]`.

### 5. Review queue (*Discovery → Review Queue*)

Each proposal lists the changes it will make, with risky changes highlighted. For new devices, **Edit values**
lets you override the name, site, location, role, device type, platform, tenant or status. You can approve or
reject single proposals, or select several and **Approve selected** / **Reject selected**. Approving needs the
NetBox permissions for the objects being created (e.g. `dcim.add_device`). Approved device proposals immediately
propose cables to their known neighbours.

## Synchronisation rules

| | Hybrid | Review | Automatic |
|---|:---:|:---:|:---:|
| New device (with interfaces, MACs, IPs, primary IP) | review | review | auto |
| New interface / MAC / IP on a known device, interface updates | auto | review | auto |
| Serial change, IP currently assigned to another device, *Unknown* device type replaced | review | review | auto |
| New cable from LLDP/CDP | review | review | auto |
| Scanned address in IPAM (create / fill empty DNS name) | auto | review | auto |
| Discovery custom fields, stale tags, Discovered Hosts | auto | auto | auto |

- **Never overwritten**: device names, existing platforms, device types (other than auto-created *Unknown* ones),
  manually set DNS names and non-empty descriptions with an empty value.
- **Cables** are created only between two interfaces that are both free. Conflicts with existing cables are
  logged, never changed. Virtual, LAG and wireless interfaces are skipped.
- **IP addresses** take their mask from the device interface, or else from the most specific non-container NetBox
  prefix, or else /32 (/128). They use the scan target's VRF.
- **Stale detection**: IPs inside the target's networks, interfaces and cables of devices that were polled
  successfully, and previously matched devices are counted per scan target. Single-host rediscovery never counts
  misses.

## Supported platforms

| Platform | Detection | SSH collector | Collected over SSH |
|----------|-----------|---------------|--------------------|
| Cisco IOS / IOS-XE | sysObjectID, sysDescr, SSH banner | NAPALM `ios` | facts, interfaces, IPs, LLDP, **CDP**, ARP |
| Cisco NX-OS | sysObjectID, sysDescr | NAPALM `nxos_ssh` | facts, interfaces, IPs, LLDP, **CDP**, ARP |
| Juniper Junos | sysObjectID | NAPALM `junos` (NETCONF) | facts, interfaces, IPs, LLDP, ARP |
| Arista EOS | sysObjectID | NAPALM `eos` (eAPI) | facts, interfaces, IPs, LLDP, ARP |
| Fortinet FortiOS | sysObjectID | Netmiko `fortinet` | system status, physical interfaces, ARP |
| Palo Alto PAN-OS | sysObjectID | Netmiko `paloalto_panos` | system info, interfaces, ARP |
| Aruba AOS-CX | sysObjectID | Netmiko `aruba_aoscx` | system, interface brief, LLDP |
| HPE ArubaOS-Switch (ProCurve) | sysObjectID | Netmiko `hp_procurve` | system, LLDP |
| Linux | sysObjectID / sysDescr, banner | Netmiko `linux` | hostname, DMI vendor/model/serial, `ip -j` interfaces, lldpd, neighbours |
| Windows | sysObjectID | — (SNMP only) | — |
| Anything with SNMP | — | — | standard MIBs (IF, IP, ENTITY, LLDP, CDP, LAG, ARP) |

SNMP is the primary data source. SSH fills in and overrides facts such as the serial and model. NAPALM drivers
are well established. The Netmiko CLI parsers for FortiOS, PAN-OS, AOS-CX and ProCurve are best-effort: CLI
output differs between releases. Each parser has fixtures in `tests/unit/fixtures`, and adding a sample of your
devices' output there is the quickest way to adapt one.

## REST API

All objects are available under `/api/plugins/discovery/`:

- `credentials/`, `scan-targets/`, `role-rules/` and `device-type-aliases/`: full CRUD.
- `proposed-changes/`: list, `PATCH` (overrides) and delete.
- `discovered-hosts/`: read and delete.

Actions:

| Endpoint | Body | Permission |
|----------|------|------------|
| `POST scan-targets/{id}/run/` | `{}` or `{"address": "10.0.0.1"}` → returns the job (202) | `netbox_nmap_discovery.run_scantarget` |
| `POST proposed-changes/{id}/approve/` | – | `change_proposedchange` + target-object permissions |
| `POST proposed-changes/{id}/reject/` | `{"reason": "…"}` | `change_proposedchange` |
| `POST proposed-changes/approve/` / `reject/` | `{"ids": [1, 2, 3]}` | as above |

Credential secrets (`secret`, `enable_secret`, `auth_key`, `priv_key`, `private_key`) are **write-only**. Responses
contain `has_secret` / `has_private_key` instead.

## Permissions

The standard view/add/change/delete permissions apply to every model. Additionally:

- **`run`** on *scan target* (`netbox_nmap_discovery.run_scantarget`) is required to run scans or rediscover. In
  NetBox, add `run` under *Additional actions* of an object permission. Rediscovering an address *outside* the
  chosen scan target's networks also requires `change` on that target, so `run` alone cannot scan arbitrary hosts.
- **Approving a proposal** requires `change` on *proposed change* plus the permissions for the objects it creates
  (e.g. `dcim.add_device`, `dcim.add_cable`).

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `nmap executable not found` | Install nmap where the RQ worker runs, or set `nmap_path`. |
| `Operation not permitted` / nmap exits immediately in Docker | The worker container lacks `NET_RAW`/`NET_ADMIN` (see the override file), or set `nmap_privileged: False`. |
| No MAC addresses for hosts | nmap only sees MACs on the local L2 segment. Enable ARP harvesting with SNMP/SSH credentials for the gateways, or run the worker with host networking. |
| Hosts found but never polled | No SNMP/SSH credential on the scan target, or an ACL blocks SNMP (UDP 161). Each SNMP credential costs up to `snmp_timeout × (retries+1)` per host that does not answer. |
| `Unable to decrypt stored credential` | The encryption key changed. Restore it, or re-enter the secrets. To rotate safely, configure `[new, old]` and run `manage.py discovery_rotate_key`. |
| Device proposed although it exists in NetBox | Matching uses serial, then interface MACs, hostname and IP. Add the serial or a MAC to the existing device, or check for ambiguous duplicate names (logged as a warning). |
| Changes not in the change log for scheduled runs | Set `scheduled_job_user` to a service account. |

Every scan writes a detailed log to its NetBox job. Problems collecting from a host appear on its
*Discovered Host* page.

## Development

```
netbox_nmap_discovery/
├── engine/          # framework-independent discovery (no Django imports)
│   ├── nmap.py      # command building, allow-list validation, XML parsing
│   ├── snmp.py      # pysnmp client + MIB parsing
│   ├── ssh/         # NAPALM / Netmiko collectors and CLI parsers
│   ├── platforms.py # platform detection, manufacturer normalisation
│   └── runner.py    # orchestration: nmap → SNMP → SSH → merge → neighbours/ARP
├── sync/            # reconciliation with NetBox (matching, planning/applying, cables, IPAM, stale, review queue)
├── jobs.py          # NetBox JobRunner, scheduling
└── models.py, views.py, api/, templates/ …
```

Engine unit tests need no NetBox:

```bash
pip install pytest defusedxml && pytest tests/unit
```

Integration tests run inside a NetBox checkout with PostgreSQL and Redis available:

```bash
cd /path/to/netbox/netbox && python manage.py test netbox_nmap_discovery
```

The [CI workflow](.github/workflows/ci.yml) runs both against NetBox v4.7.4.

## Limitations

- Virtual chassis and stacks are created as one device, using the first chassis serial.
- VMs and virtualization clusters are not created. Hypervisors appear as devices.
- IPv6 neighbour discovery tables are not harvested. IPv6 interface addresses are.
- Only one VRF per scan target. Addresses in other VRFs on the same device are recorded in the target's VRF.

## License

Apache 2.0, see [LICENSE](LICENSE).
