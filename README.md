# lanscan

A graphical overview of the devices on your local network, for the GNOME
desktop. Discovery and port scanning are done by `nmap`; names and service
hints come from mDNS (`avahi-browse`) when available.

- **List and map views** of all devices, switchable in the header bar.
  In the map this computer sits in the middle and the distance to each
  device shows its ping time (logarithmic, rings at 1, 10 and 100 ms); the Topology mode puts the
  gateway in the middle instead, with the devices spread evenly
- **History** in a local SQLite database: first/last seen, online/offline,
  new devices are flagged until you mark them as known
- **Port scan** per device (open ports, service versions, OS guess);
  click a device in the list to show its services underneath, with a
  clickable link on web (http/https) services. The menu
  can scan the ports of all online devices at once, either the 1000
  most common ports or all 65535 (slow)
- **Details pane** (name, type, addresses, port scan) by clicking a
  device in the list or the map; a header button hides the pane
- **Identification** from every source available: MAC vendor, mDNS and
  UPnP announcements (name, model), hostnames, open ports and nmap's OS
  detection
- **Operating system**: nmap's fingerprint from a root port scan, or
  else a best guess (shown as "likely") from service banners, SMB,
  SNMP, mDNS/UPnP announcements, host names and the TTL of ping replies
- **Custom names and device types**

## Several networks

The button next to Scan lists every network this machine is connected
to (LAN, WireGuard, Docker, virtual machines, ...), taken from the
routing table. Tick the ones to scan, or type other networks in the
field below the list. The list groups the devices under a collapsible
heading per network, and the map shows one cluster per network.

Networks without link-layer addresses, such as WireGuard, have no MAC
addresses: devices there are tracked by IP address. Hosts there are
found with nmap (TCP ports 80 and 443) and a ping of every address,
which covers networks of up to 1024 addresses; for larger ones use
"Scan as Root".

Each network's gateway is taken from the routing table. For a network
without one there (WireGuard, typically) a ping limited to one hop is
sent towards a few of its hosts: the hub in between, if any, answers.

## Requirements

Python 3.10+, PyGObject, GTK 4, libadwaita 1.6+, `nmap`, and optionally
`avahi-tools`. On Fedora:

    sudo dnf install python3-gobject gtk4 libadwaita nmap avahi-tools

## Running

    python3 -m lanscan

On startup the app quietly checks which of the already known devices
are online (no root, only their addresses are probed); press Scan to
look for new ones.

Scans run without root by default: nmap finds the hosts and MAC addresses
come from the kernel neighbour table. When a root scan would reveal more
(new devices that could not be identified, or devices without a MAC
address), a banner offers one; it runs nmap through `pkexec` for ARP
discovery and OS detection. "Scan as Root" is also always available in
the menu, and in the menu next to "Scan ports" for a single device.

To avoid a password prompt for every root scan, you can install the
optional polkit policy (read the note inside the file first):

    sudo cp data/io.github.lanscan.policy \
      /usr/share/polkit-1/actions/

The MAC vendor list is downloaded from wireshark.org on first start and
refreshed monthly (cached in `~/.cache/lanscan/manuf`). Only the public
list is fetched; no information about your devices is sent anywhere. If
the download fails, the older list shipped with nmap is used.

The database lives in `~/.local/share/lanscan/lanscan.db` (override with
the `LANSCAN_DB` environment variable).

## Tests

    python3 -m unittest discover -s tests

Only scan networks you own or are allowed to scan.
