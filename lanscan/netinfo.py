"""Information about this machine's own network setup (via iproute2),
and the MAC address vendor database."""

import ipaddress
import json
import os
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass

from gi.repository import GLib

NMAP_MAC_PREFIXES = "/usr/share/nmap/nmap-mac-prefixes"
# Wireshark's vendor list, built from the IEEE registries. Downloading
# the whole list means no device address ever leaves this machine.
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
MANUF_MAX_AGE = 30 * 86400


@dataclass
class Iface:
    name: str
    ip: str
    network: ipaddress.IPv4Network
    mac: str


def _ip_json(*args):
    try:
        out = subprocess.run(
            ["ip", "-j", *args], capture_output=True, text=True, timeout=5,
        ).stdout
        return json.loads(out or "[]")
    except (OSError, subprocess.SubprocessError, ValueError):
        return []


def parse_interfaces(data):
    ifaces = []
    for link in data:
        if "LOOPBACK" in link.get("flags", []):
            continue
        if link.get("operstate") == "DOWN":
            continue
        for addr in link.get("addr_info", []):
            if addr.get("family") != "inet" or addr.get("scope") != "global":
                continue
            try:
                net = ipaddress.ip_network(
                    f"{addr['local']}/{addr['prefixlen']}", strict=False)
            except (KeyError, ValueError):
                continue
            ifaces.append(Iface(
                link.get("ifname", ""), addr["local"], net,
                normalize_mac(link.get("address", ""))))
    return ifaces


def interfaces():
    return parse_interfaces(_ip_json("addr", "show"))


@dataclass
class Net:
    name: str  # interface it is reached through
    network: ipaddress.IPv4Network


def parse_networks(routes, ifaces=()):
    """Networks this machine can reach directly, from the routing table.

    This covers the LAN, but also VPN (WireGuard), Docker and virtual
    machine networks. Host routes and the default route are left out.
    """
    nets, seen = [], set()

    def add(name, network):
        if (network.version == 4 and network.prefixlen < 32
                and not network.is_link_local and not network.is_loopback
                and network not in seen):
            seen.add(network)
            nets.append(Net(name, network))

    for route in routes:
        dst, dev = route.get("dst"), route.get("dev")
        if not dst or dst == "default" or not dev or dev == "lo":
            continue
        if route.get("type", "unicast") != "unicast":
            continue
        try:
            add(dev, ipaddress.ip_network(dst, strict=False))
        except ValueError:
            continue
    for iface in ifaces:
        add(iface.name, iface.network)
    return nets


def networks():
    return parse_networks(_ip_json("-4", "route", "show"), interfaces())


def default_gateway():
    """Return (gateway_ip, interface_name) or (None, None)."""
    for route in _ip_json("-4", "route", "show", "default"):
        if route.get("gateway"):
            return route["gateway"], route.get("dev")
    return None, None


def parse_route_gateways(routes):
    """Every address the routing table sends traffic through."""
    return {r["gateway"] for r in routes if r.get("gateway")}


def route_gateways():
    return parse_route_gateways(_ip_json("-4", "route", "show"))


_FRESH = {"REACHABLE", "DELAY", "PROBE"}


def parse_neighbours(data, fresh_only=False):
    table = {}
    for entry in data:
        mac = entry.get("lladdr")
        state = set(entry.get("state") or [])
        if not mac or not entry.get("dst") or "FAILED" in state:
            continue
        if fresh_only and not state & _FRESH:
            continue
        table[entry["dst"]] = normalize_mac(mac)
    return table


def neighbours(fresh_only=False):
    """IP -> MAC from the kernel neighbour (ARP) table.

    With fresh_only, only entries the kernel confirmed moments ago.
    """
    return parse_neighbours(_ip_json("-4", "neigh", "show"), fresh_only)


def default_target():
    """CIDR of the network behind the default route, or ''."""
    ifaces = interfaces()
    if not ifaces:
        return ""
    _gw, dev = default_gateway()
    for iface in ifaces:
        if iface.name == dev:
            return str(iface.network)
    return str(ifaces[0].network)


def normalize_mac(mac):
    return (mac or "").strip().upper().replace("-", ":")


def parse_nmap_prefixes(text):
    table = {}
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        prefix, _, vendor = line.strip().partition(" ")
        if prefix and vendor:
            table[prefix.upper()] = vendor
    return table


def parse_manuf(text):
    """Parse Wireshark's manuf file: 'PREFIX[/BITS]<tab>Short<tab>Long'.

    Keys are the significant hex digits of the prefix (6, 7 or 9).
    """
    table = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        cols = [c.strip() for c in line.split("\t")]
        if len(cols) < 2:
            continue
        prefix, _, bits = cols[0].partition("/")
        digits = prefix.replace(":", "").replace("-", "").upper()
        try:
            int(digits, 16)
            length = int(bits) // 4 if bits else len(digits)
        except ValueError:
            continue
        if length not in (6, 7, 9) or len(digits) < length:
            continue
        name = cols[2] if len(cols) > 2 and cols[2] else cols[1]
        if name:
            table[digits[:length]] = name
    return table


def default_manuf_path():
    return os.path.join(GLib.get_user_cache_dir(), "lanscan", "manuf")


class VendorDb:
    """MAC prefix -> vendor.

    Uses the downloaded vendor list when there is one, on top of the
    (often years old) table shipped with nmap.
    """

    def __init__(self, manuf_path=None, nmap_path=NMAP_MAC_PREFIXES):
        self._manuf_path = manuf_path or default_manuf_path()
        self._nmap_path = nmap_path
        self._table = None
        self._lock = threading.Lock()

    @staticmethod
    def _read(path):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def _load(self):
        table = parse_nmap_prefixes(self._read(self._nmap_path))
        table.update(parse_manuf(self._read(self._manuf_path)))
        return table

    def lookup(self, mac):
        with self._lock:
            if self._table is None:
                self._table = self._load()
            table = self._table
        digits = normalize_mac(mac).replace(":", "")
        for length in (9, 7, 6):
            vendor = table.get(digits[:length])
            if vendor:
                return vendor
        return ""

    def is_stale(self):
        try:
            age = time.time() - os.path.getmtime(self._manuf_path)
        except OSError:
            return True
        return age > MANUF_MAX_AGE

    def update(self, force=False):
        """Download the vendor list if missing or old.

        Returns True if a new list was installed. Raises OSError (which
        includes network errors) or ValueError on failure.
        """
        if not force and not self.is_stale():
            return False
        request = urllib.request.Request(
            MANUF_URL, headers={"User-Agent": "lanscan"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(32 * 1024 * 1024)
        text = data.decode("utf-8", errors="replace")
        if len(parse_manuf(text)) < 10000:
            raise ValueError("downloaded vendor list looks incomplete")
        os.makedirs(os.path.dirname(self._manuf_path), exist_ok=True)
        tmp = self._manuf_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, self._manuf_path)
        with self._lock:
            self._table = None
        return True
