"""UPnP/SSDP discovery: many TVs, routers, speakers and NAS boxes
announce their name, manufacturer and model this way."""

import select
import socket
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

SSDP_ADDR = ("239.255.255.250", 1900)
MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()
MAX_DESCRIPTION = 512 * 1024


def parse_response(data):
    """Header dict (lower-case keys) of an SSDP response."""
    headers = {}
    for line in data.decode("utf-8", errors="replace").splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers


def search(bind_ips, wait=3.0):
    """Send M-SEARCH on each local address.

    Returns ip -> {'locations': [...], 'types': [...], 'server': str}.
    """
    socks = []
    for ip in bind_ips:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.bind((ip, 0))
            sock.setblocking(False)
            sock.sendto(MSEARCH, SSDP_ADDR)
            sock.sendto(MSEARCH, SSDP_ADDR)
            socks.append(sock)
        except OSError:
            continue
    found = {}
    deadline = time.monotonic() + wait
    while socks:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select(socks, [], [], remaining)
        for sock in ready:
            try:
                data, (ip, _port) = sock.recvfrom(8192)
            except OSError:
                continue
            headers = parse_response(data)
            entry = found.setdefault(
                ip, {"locations": [], "types": [], "server": ""})
            location = headers.get("location", "")
            if location and location not in entry["locations"]:
                entry["locations"].append(location)
            st = headers.get("st", "")
            if st and st not in entry["types"]:
                entry["types"].append(st)
            entry["server"] = entry["server"] or headers.get("server", "")
    for sock in socks:
        sock.close()
    return found


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# Talk to the device directly: no proxies, no redirects elsewhere.
_opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), _NoRedirect)


def parse_description(xml_text):
    """Fields of the root <device> in a UPnP device description."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    device = root.find("{*}device")
    if device is None:
        return {}

    def text(tag):
        return (device.findtext("{*}" + tag) or "").strip()

    manufacturer, model = text("manufacturer"), text("modelName")
    if model.lower().startswith(manufacturer.lower()):
        manufacturer = ""
    return {
        "name": text("friendlyName"),
        "model": " ".join(p for p in (manufacturer, model) if p),
        "type": text("deviceType"),
    }


def fetch_description(url, ip):
    """Fetch a description, but only from the device that announced it."""
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or parts.hostname != ip:
            return {}
        with _opener.open(url, timeout=3) as response:
            return parse_description(response.read(MAX_DESCRIPTION))
    except (OSError, ValueError):
        return {}


def _describe(item):
    ip, entry = item
    info = {"name": "", "model": "", "type": "", "server": entry["server"]}
    for location in entry["locations"][:3]:
        found = fetch_description(location, ip)
        for key in ("name", "model", "type"):
            info[key] = info[key] or found.get(key, "")
        if info["name"] and info["type"]:
            break
    # Without a description the announced types are still a clue.
    hint = " ".join([info["type"], *entry["types"], entry["server"]])
    info["type"] = hint.strip()[:300]
    return ip, info


def discover(bind_ips, wait=3.0):
    """ip -> {'name', 'model', 'type'} for every UPnP device that answers."""
    try:
        found = search(bind_ips, wait)
        if not found:
            return {}
        with ThreadPoolExecutor(max_workers=16) as pool:
            return dict(pool.map(_describe, found.items()))
    except Exception:  # discovery is a bonus, never fail a scan over it
        return {}
