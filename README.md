# LAN Scan

A graphical overview of the devices on your local network, for the GNOME
desktop. Discovery and port scanning are done by `nmap`; names and service
hints come from mDNS (`avahi-browse`) when available.

- **List and map views** of all devices, switchable in the header bar,
  for the scanned networks (LAN) and for Wi-Fi.
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
  device in the list or the map; a header button or the bar along the
  right edge hides the pane
- **Identification** from every source available: MAC vendor, mDNS and
  UPnP announcements (name, model), hostnames, open ports and nmap's OS
  detection
- **Operating system**: nmap's fingerprint from a root port scan, or
  else a best guess (shown as "likely") from service banners, SMB,
  SNMP, mDNS/UPnP announcements, host names and the TTL of ping replies
- **Wi-Fi**: the access points in range, in the list and on a map of
  their own where distance shows signal strength; a deep scan in
  monitor mode adds the client devices of every network
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

## Wi-Fi

The LAN | Wi-Fi switch in the header picks what the list and the map
show, and what Scan scans. On the Wi-Fi side, pick an adapter in the
menu next to Scan (it shows what each adapter is); Scan then asks
NetworkManager for the access points in range: name, band, channel,
security and signal. The Wi-Fi list has one row per network, with its access points
and client devices folded underneath; access points with the same
name count as one network, on the map too.

"Deep Scan", next to Scan on the Wi-Fi side, needs root and `iw`. It switches
the adapter to monitor mode for 30 seconds, hops through the 2.4, 5
and 6 GHz channels and reads the headers of the frames in the air.
That shows which devices talk to which access point, their signal
strength, hidden networks, and the network names devices are looking
for. A client whose address is also known from a network scan gets
that device's name (green on the map), and the device's details show
its Wi-Fi network and signal. Nothing is transmitted and no traffic
is decrypted.

If the adapter cannot scan (Wi-Fi switched off, not managed by
NetworkManager, or left in monitor mode), Scan says why and offers to
fix it. A Wi-Fi scan gives up after about half a minute.

Wi-Fi devices that are also on a network you scanned are marked
"YOURS" (green on the map): a client with the same address as a
device there, and an access point that such a client uses, whose
address is right next to one seen there, or that shares its name with
one of those. The access point part is a good guess, not proof. "Show
Only My Wi-Fi Networks" in the main menu hides everything else, and
network devices seen on Wi-Fi get a small Wi-Fi icon in the list.

While the deep scan runs the adapter is offline; afterwards it is
handed back to NetworkManager. If the adapter is your connection, the
app asks first. Only the 20 MHz primary channels are listened on, so
a quiet device can be missed; clients are a snapshot of the last deep
scan, while access points are remembered for a month.

## Install

Each release on GitHub has an RPM and a deb (Debian 13, Ubuntu 24.10
or newer). They pull in nmap and everything else needed:

    sudo dnf install ./lanscan-*.noarch.rpm
    sudo apt install ./lanscan_*_all.deb

The RPM is made for Fedora and its relatives and for openSUSE
Tumbleweed (`sudo zypper install ./lanscan-*.noarch.rpm`); it is only
tested on Fedora. Any system needs GTK 4 with libadwaita 1.6 or newer,
which rules out older releases such as RHEL 9 and openSUSE Leap 15.

The packages do not depend on a particular Python version. On other
distributions, install the requirements below and run it from a
checkout with `python3 -m lanscan`.

Build the packages yourself with `tools/build-packages.sh rpm` or
`tools/build-packages.sh deb`; they end up in `dist/`.

To make a release, run `tools/release.sh 0.2.0`. It runs the tests,
sets the version, commits and tags; pushing the tag makes the GitHub
workflow in `.github/workflows/release.yml` build both packages and
publish the release.

## Requirements

Python 3.10+, PyGObject, GTK 4, libadwaita 1.6+, `nmap`, and optionally
`avahi-tools`. Wi-Fi scanning uses NetworkManager (`nmcli`) and, for
the deep scan, `iw`. On Fedora:

    sudo dnf install python3-gobject gtk4 libadwaita nmap \
      avahi-tools iw

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

The packages install a polkit policy that lets polkit remember the
password for a few minutes, so each root scan does not prompt again.
It applies to every `pkexec nmap` run from your session. Running from
a checkout, you can install it yourself:

    sudo cp data/io.github.subsite.Lanscan.policy \
      /usr/share/polkit-1/actions/

Opening About asks GitHub for the latest release, to say whether a
newer version exists; nothing else is sent.

The MAC vendor list is downloaded from wireshark.org on first start and
refreshed monthly (cached in `~/.cache/lanscan/manuf`). Only the public
list is fetched; no information about your devices is sent anywhere. If
the download fails, the older list shipped with nmap is used.

The database lives in `~/.local/share/lanscan/lanscan.db` (override with
the `LANSCAN_DB` environment variable).

## Tests

    python3 -m unittest discover -s tests

Only scan networks you own or are allowed to scan.

## Licence

By SubSite - Fredrik Welander, <https://github.com/subsite/lanscan>.
LAN Scan is free software under the GNU General Public License,
version 3 or later; see `LICENSE`.
