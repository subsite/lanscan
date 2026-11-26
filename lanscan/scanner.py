"""Running nmap / avahi-browse and turning their output into Host records."""

import ipaddress
import os
import re
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from . import netinfo, osguess, upnp

MAX_ADDRESSES = 65536
MAX_SWEEP = 1024  # most addresses a non-root scan pings one by one
SMB_SCRIPT = "/usr/share/nmap/scripts/smb-os-discovery.nse"

# How hard to probe. Gentle uses nmap's normal timing instead of -T4,
# pings fewer addresses at a time and keeps port scans to the 100 most
# common ports, without service probes, scripts, SNMP or OS detection.
# Discovery only scans like gentle and does no port scans at all.
NORMAL, GENTLE, DISCOVERY = "normal", "gentle", "discovery"
MODES = (NORMAL, GENTLE, DISCOVERY)
GENTLE_PORTS = 100


class ScanError(Exception):
    pass


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    mdns_name: str = ""
    os: str = ""
    services: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    is_gateway: bool = False
    is_self: bool = False
    friendly_name: str = ""
    model: str = ""
    upnp_type: str = ""
    nmap_type: str = ""
    rtt: float = 0.0  # round trip time in ms, 0 = unknown
    ttl: int = 0  # hops left on its replies, 0 = unknown
    service_os: str = ""  # OS according to its services, SMB or SNMP
    upnp_server: str = ""


def parse_target(text):
    """Validate user input as an IPv4 network. Raises ScanError.

    The result is passed to nmap (possibly running as root), so nothing
    but a well-formed network may get through.
    """
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        raise ScanError(
            "Enter a network like 192.168.1.0/24 or a single IP") from None
    if net.version != 4:
        raise ScanError("Only IPv4 networks are supported")
    if net.num_addresses > MAX_ADDRESSES:
        raise ScanError("Network too large (maximum is a /16)")
    return net


def parse_targets(text):
    """Several networks separated by commas or spaces. Raises ScanError."""
    return [parse_target(part)
            for part in text.replace(",", " ").split()]


def as_networks(networks):
    """Accept a single network or a list of them."""
    if networks is None:
        return []
    if isinstance(networks, (list, tuple, set)):
        return list(networks)
    return [networks]


def _base(privileged):
    nmap = shutil.which("nmap")
    if not nmap:
        raise ScanError("nmap is not installed")
    if privileged:
        pkexec = shutil.which("pkexec")
        if not pkexec:
            raise ScanError("pkexec is not installed")
        return [pkexec, nmap]
    return [nmap]


def discovery_cmd(networks, privileged, ips=None, mode=NORMAL):
    """Ping scan of the networks, or of just the given addresses."""
    targets = [str(n) for n in as_networks(networks)]
    if ips:
        targets = [str(ipaddress.IPv4Address(ip)) for ip in ips]
    timing = ["-T4"] if mode == NORMAL else []
    return _base(privileged) + ["-sn", *timing, "-oX", "-", *targets]


def portscan_cmd(ips, privileged, full=False, mode=NORMAL):
    """Port scan command. `full` scans all 65535 TCP ports instead of
    nmap's 1000 most common ones. Raises ScanError in discovery mode."""
    ips = [str(ipaddress.IPv4Address(ip)) for ip in ips]
    if mode == DISCOVERY:
        raise ScanError("Port scans are off in Discovery Only mode")
    if mode == GENTLE:
        # Root, a full scan and service probes are all left out.
        return _base(False) + [
            "-sT", "--top-ports", str(GENTLE_PORTS), "-Pn", "-oX", "-",
            *ips]
    if privileged:
        scan = ["-sS", "-O", "--osscan-guess"]
    else:
        scan = ["-sT"]
    if full:
        scan.append("-p-")
    if os.path.exists(SMB_SCRIPT):  # Windows / Samba report their OS
        scan += ["--script", "smb-os-discovery"]
    return _base(privileged) + scan + [
        "-sV", "--version-light", "-Pn", "-T4", "-oX", "-", *ips]


def run(cmd, timeout=900):
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError("The scan timed out") from None
    except OSError as e:
        raise ScanError(f"Could not run {cmd[0]}: {e}") from None
    if cmd[0].endswith("pkexec") and proc.returncode in (126, 127):
        raise ScanError("Authentication was cancelled or denied")
    if proc.returncode != 0:
        lines = [l for l in proc.stderr.strip().splitlines() if l.strip()]
        detail = lines[-1] if lines else f"exit code {proc.returncode}"
        raise ScanError(f"nmap failed: {detail}")
    return proc.stdout


def parse_nmap_xml(text):
    """Return the hosts nmap reported as up."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ScanError(f"Could not read nmap output: {e}") from None
    hosts = []
    for node in root.iter("host"):
        status = node.find("status")
        if status is None or status.get("state") != "up":
            continue
        host = Host(ip="")
        try:  # only known when nmap ran as root
            host.ttl = int(status.get("reason_ttl") or 0)
        except ValueError:
            pass
        details = []
        for addr in node.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host.ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                host.mac = netinfo.normalize_mac(addr.get("addr"))
                host.vendor = addr.get("vendor", "")
        if not host.ip:
            continue
        times = node.find("times")
        if times is not None:
            try:  # smoothed round trip time, in microseconds
                host.rtt = max(0.0, int(times.get("srtt")) / 1000)
            except (TypeError, ValueError):
                pass
        name = node.find("hostnames/hostname")
        if name is not None:
            host.hostname = name.get("name", "")
        for port in node.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            get = (lambda k: svc.get(k, "")) if svc is not None else (
                lambda k: "")
            try:
                number = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            host.ports.append({
                "port": number,
                "proto": port.get("protocol", "tcp"),
                "service": get("name"),
                "tunnel": get("tunnel"),
                "product": " ".join(
                    p for p in (get("product"), get("version")) if p),
            })
            host.nmap_type = host.nmap_type or get("devicetype")
            if svc is not None:
                details.append({
                    "ostype": get("ostype"),
                    "cpes": [c.text or "" for c in svc.findall("cpe")],
                    "banner": " ".join(
                        (get("product"), get("version"), get("extrainfo"))),
                })
        smb = node.find("hostscript/script[@id='smb-os-discovery']/"
                        "elem[@key='os']")
        host.service_os = (
            (smb.text or "").strip() if smb is not None else ""
        ) or osguess.os_from_services(details)
        match = node.find("os/osmatch")
        if match is not None:
            host.os = match.get("name", "")
            osclass = match.find("osclass")
            if osclass is not None:
                host.nmap_type = host.nmap_type or osclass.get("type", "")
        hosts.append(host)
    return hosts


def start_mdns():
    """Start an mDNS browse in the background; None if unavailable."""
    exe = shutil.which("avahi-browse")
    if not exe:
        return None
    try:
        return subprocess.Popen(
            [exe, "-a", "-r", "-p", "-t"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True)
    except OSError:
        return None


def finish_mdns(proc, timeout=8):
    if proc is None:
        return {}
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    return parse_avahi(out or "")


_TXT = re.compile(r'"((?:[^"\\]|\\.)*)"')
# TXT keys that carry a model name, most specific first.
_MODEL_KEYS = ("ty", "md", "usb_MDL", "product", "model", "am")
# Services whose instance name is the name the owner gave the device.
_NAMED_SERVICES = (
    "_companion-link.", "_airplay.", "_raop.", "_ipp.", "_ipps.", "_smb.",
    "_hap.", "_sonos.", "_spotify-connect.")


def avahi_unescape(text):
    r"""Undo avahi's escaping: '\032' is a byte value, '\.' a literal."""
    raw = text.encode("utf-8", errors="replace")
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == 0x5C and raw[i + 1:i + 4].isdigit() and (
                len(raw[i + 1:i + 4]) == 3):
            out.append(int(raw[i + 1:i + 4]) & 0xFF)
            i += 4
        elif raw[i] == 0x5C and i + 1 < len(raw):
            out.append(raw[i + 1])
            i += 2
        else:
            out.append(raw[i])
            i += 1
    return out.decode("utf-8", errors="replace")


def parse_avahi(text):
    """IP -> {'name', 'services', 'friendly', 'model'} from avahi-browse."""
    found = {}
    for line in text.splitlines():
        parts = line.split(";")
        # =;iface;proto;name;type;domain;hostname;address;port;txt
        if len(parts) < 9 or parts[0] != "=" or parts[2] != "IPv4":
            continue
        service = parts[4]
        entry = found.setdefault(parts[7], {
            "name": "", "services": [], "friendly": "", "model": "",
            "_fn": False})
        entry["name"] = entry["name"] or parts[6]
        if service not in entry["services"]:
            entry["services"].append(service)
        txt = {}
        for item in _TXT.findall(";".join(parts[9:])):
            key, sep, value = item.partition("=")
            if sep:
                txt[key] = value.strip()
        if not entry["model"]:
            for key in _MODEL_KEYS:
                if txt.get(key):
                    entry["model"] = txt[key].strip("()")
                    break
        if txt.get("fn") and not entry["_fn"]:
            entry["friendly"], entry["_fn"] = txt["fn"], True
        elif not entry["friendly"] and service.startswith(_NAMED_SERVICES):
            # _raop instances look like 'A1B2C3D4E5F6@Living Room'.
            name = avahi_unescape(parts[3]).rpartition("@")[2].strip()
            entry["friendly"] = name
    for entry in found.values():
        del entry["_fn"]
    return found


def add_neighbour_hosts(hosts, neigh, network):
    """Add hosts that answered ARP but that nmap reported as down.

    Without root nmap can only try TCP connections, which firewalled
    devices ignore. The kernel still had to resolve their MAC address,
    so a fresh neighbour entry proves they are there.
    """
    found = {h.ip for h in hosts}
    for ip, mac in neigh.items():
        if _inside(ip, network) and ip not in found:
            hosts.append(Host(ip=ip, mac=mac))
    return hosts


def add_upnp_hosts(hosts, upnp_info, network):
    """Add devices that answered the UPnP search but nothing else."""
    found = {h.ip for h in hosts}
    for ip in upnp_info:
        if _inside(ip, network) and ip not in found:
            hosts.append(Host(ip=ip))
    return hosts


def _inside(ip, networks):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in n for n in as_networks(networks))


inside = _inside


_HOP = re.compile(r"From ([\d.]+)[^\n]*Time to live exceeded", re.I)


def parse_hop(text):
    """Who answered a ping that was only allowed one hop ('' if the
    target was reached directly or nothing came back)."""
    match = _HOP.search(text)
    return match.group(1) if match else ""


def first_hop(ip):
    """The router between us and `ip`, or '' if there is none."""
    exe = shutil.which("ping")
    if not exe:
        return ""
    try:
        proc = subprocess.run(
            [exe, "-n", "-c", "1", "-W", "1", "-t", "1",
             str(ipaddress.IPv4Address(ip))],
            capture_output=True, text=True, timeout=4)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return parse_hop(proc.stdout + proc.stderr)


def find_gateways(hosts, ifaces, networks, routed=(), probe=first_hop):
    """Addresses of the gateways of the scanned networks.

    `routed` are the gateways the routing table names. A network we are
    part of that has none there (WireGuard, typically) is probed: a
    ping limited to one hop towards another host is answered by the
    hub in between, if there is one.
    """
    found = {ip for ip in routed if _inside(ip, networks)}
    own = {i.ip for i in ifaces}
    probes = {}  # target ip -> network
    for network in as_networks(networks):
        if any(_inside(ip, network) for ip in found):
            continue
        if not any(_inside(ip, network) for ip in own):
            continue
        targets = sorted(
            (h for h in hosts
             if _inside(h.ip, network) and h.ip not in own),
            key=lambda h: (not h.rtt, h.ip))
        for host in targets[:3]:
            probes[host.ip] = network
    if probes:
        with ThreadPoolExecutor(max_workers=16) as pool:
            for target, hop in zip(probes, pool.map(probe, probes)):
                if (hop and hop != target and hop not in own
                        and _inside(hop, probes[target])):
                    found.add(hop)
    return found


def enrich(hosts, ifaces=(), gateway=None, neigh=None, mdns=None,
           vendors=None, upnp_info=None):
    """Fill in what nmap alone could not tell us about each host."""
    neigh = neigh or {}
    mdns = mdns or {}
    upnp_info = upnp_info or {}
    gateways = {gateway} if isinstance(gateway, str) else set(gateway or ())
    own = {i.ip: i for i in ifaces}
    for host in hosts:
        if host.ip in own:
            host.is_self = True
            host.mac = host.mac or own[host.ip].mac
        host.mac = host.mac or neigh.get(host.ip, "")
        host.is_gateway = host.ip in gateways
        if host.mac and vendors:
            # Our list is usually newer than the one nmap ships.
            host.vendor = vendors.lookup(host.mac) or host.vendor
        info = mdns.get(host.ip)
        if info:
            host.mdns_name = info["name"]
            host.services = sorted(info["services"])
            host.friendly_name = info.get("friendly", "")
            host.model = info.get("model", "")
        info = upnp_info.get(host.ip)
        if info:
            host.friendly_name = host.friendly_name or info.get("name", "")
            host.model = info.get("model", "") or host.model
            host.upnp_type = info.get("type", "")
            host.upnp_server = info.get("server", "")
    return hosts


_PING_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms")
_PING_TTL = re.compile(r"ttl=(\d+)", re.I)


def parse_ping(text):
    """(round trip time in ms, ttl) from ping's output; zeros if the
    host did not answer."""
    time = _PING_TIME.search(text)
    ttl = _PING_TTL.search(text)
    return (float(time.group(1)) if time else 0.0,
            int(ttl.group(1)) if ttl else 0)


def ping_host(ip):
    exe = shutil.which("ping")
    if not exe:
        return 0.0, 0
    try:
        out = subprocess.run(
            [exe, "-n", "-c", "1", "-W", "1", str(ipaddress.IPv4Address(ip))],
            capture_output=True, text=True, timeout=4).stdout
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0.0, 0
    return parse_ping(out)


def sweep_targets(networks, ips=None):
    """Addresses a ping sweep should try: the given ones, or every
    address of the networks unless that is too many."""
    if ips:
        return [str(ipaddress.IPv4Address(ip)) for ip in ips]
    networks = as_networks(networks)
    if sum(n.num_addresses for n in networks) > MAX_SWEEP:
        return []
    return [str(ip) for n in networks for ip in n.hosts()]


def add_ping_hosts(hosts, targets, ping=ping_host, workers=64):
    """Add the hosts that answer a ping but that nmap missed.

    Without root nmap only tries TCP ports 80 and 443, which a
    firewalled host ignores; on a network without ARP (WireGuard)
    nothing else would reveal it.
    """
    found = {h.ip for h in hosts}
    targets = [ip for ip in dict.fromkeys(targets) if ip not in found]
    if targets:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for ip, (rtt, ttl) in zip(targets, pool.map(ping, targets)):
                if rtt or ttl:
                    hosts.append(Host(ip=ip, rtt=rtt, ttl=ttl))
    return hosts


def add_ping_times(hosts, ping=ping_host):
    """Ping the hosts nmap could not tell the round trip time or the
    TTL of (the TTL hints at the operating system)."""
    missing = [h for h in hosts
               if not (h.rtt and h.ttl) and not h.is_self]
    if missing:
        with ThreadPoolExecutor(max_workers=32) as pool:
            for host, (rtt, ttl) in zip(missing, pool.map(
                    lambda h: ping(h.ip), missing)):
                host.rtt = host.rtt or rtt
                host.ttl = host.ttl or ttl
    return hosts


vendors = netinfo.VendorDb()


def discover(networks, privileged, ips=None, mode=NORMAL):
    """Full discovery scan: nmap ping scan plus everything else we can
    learn without root (ARP table, mDNS, UPnP, vendor database).

    With `ips`, nmap only probes those addresses, which is much faster.
    """
    ifaces = netinfo.interfaces()
    mdns_proc = start_mdns()
    upnp_result = {}
    upnp_thread = threading.Thread(
        target=lambda: upnp_result.update(
            upnp.discover(
                [i.ip for i in ifaces if _inside(i.ip, networks)])),
        daemon=True)
    upnp_thread.start()
    try:
        xml = run(discovery_cmd(networks, privileged, ips, mode))
    except ScanError:
        if mdns_proc:
            mdns_proc.kill()
        raise
    hosts = parse_nmap_xml(xml)
    upnp_thread.join(timeout=15)
    upnp_info = dict(upnp_result)
    if not privileged:
        add_ping_hosts(hosts, sweep_targets(networks, ips),
                       workers=64 if mode == NORMAL else 8)
        add_neighbour_hosts(
            hosts, netinfo.neighbours(fresh_only=True), networks)
    add_upnp_hosts(hosts, upnp_info, networks)
    gateways = find_gateways(
        hosts, ifaces, networks, netinfo.route_gateways())
    return add_ping_times(enrich(
        hosts, ifaces, gateways, netinfo.neighbours(),
        finish_mdns(mdns_proc), vendors, upnp_info))


def scan_ports(ips, privileged, full=False, mode=NORMAL):
    """Port scan one or more hosts; returns Hosts with ports/os set."""
    timeout = 4 * 3600 if full and mode == NORMAL else 900
    hosts = parse_nmap_xml(
        run(portscan_cmd(ips, privileged, full, mode), timeout))
    for host in hosts:
        if host.mac:
            host.vendor = vendors.lookup(host.mac) or host.vendor
    if hosts and mode == NORMAL:
        # Devices with SNMP switched on describe themselves.
        with ThreadPoolExecutor(max_workers=16) as pool:
            for host, text in zip(hosts, pool.map(
                    lambda h: osguess.snmp_sysdescr(h.ip), hosts)):
                host.service_os = text or host.service_os
    return hosts
