"""Best guess at a device's operating system from everything short of
nmap's fingerprinting: service banners, SNMP, mDNS and UPnP
announcements, host names and the TTL of ping replies."""

import re
import socket

# ---- nmap service details ---------------------------------------------

_CPE_NAMES = {
    "linux_kernel": "Linux", "windows": "Windows", "mac_os_x": "macOS",
    "macos": "macOS", "iphone_os": "iOS", "ios": "Cisco IOS",
    "android": "Android", "freebsd": "FreeBSD", "openbsd": "OpenBSD",
    "netbsd": "NetBSD", "routeros": "RouterOS", "openwrt": "OpenWrt",
    "embedded": "", "unix": "Unix",
}
# Distributions and systems that show up in service banners.
_BANNER = [
    (r"ubuntu", "Linux (Ubuntu)"), (r"raspbian", "Linux (Raspberry Pi OS)"),
    (r"debian", "Linux (Debian)"), (r"fedora", "Linux (Fedora)"),
    (r"centos", "Linux (CentOS)"), (r"red hat|rhel", "Linux (Red Hat)"),
    (r"openwrt", "Linux (OpenWrt)"), (r"synology|\bdsm\b", "Synology DSM"),
    (r"qnap|\bqts\b", "QNAP QTS"), (r"mikrotik|routeros", "RouterOS"),
    (r"freebsd", "FreeBSD"), (r"openbsd", "OpenBSD"),
    (r"microsoft|windows", "Windows"), (r"dropbear", "Linux (embedded)"),
]


def os_from_cpe(cpe):
    """'cpe:/o:microsoft:windows_10' -> 'Windows'; '' for non-OS CPEs."""
    parts = (cpe or "").split(":")
    if len(parts) < 4 or parts[1] != "/o":
        return ""
    product = parts[3].lower()
    for key, name in _CPE_NAMES.items():
        if product == key or product.startswith(key + "_"):
            return name
    return product.replace("_", " ").title()


def os_from_services(services):
    """`services` is a list of dicts with ostype, cpes (list) and banner
    (product, version and extra info of one nmap service)."""
    banner = " ".join(s.get("banner", "") for s in services).lower()
    for pattern, name in _BANNER:
        if name != "Windows" and re.search(pattern, banner):
            return name
    for service in services:
        for cpe in service.get("cpes", ()):
            name = os_from_cpe(cpe)
            if name:
                return name
    for service in services:
        if service.get("ostype"):
            return service["ostype"]
    return "Windows" if re.search(_BANNER[-2][0], banner) else ""


# ---- SNMP ---------------------------------------------------------------

_SYSDESCR = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])  # 1.3.6.1.2.1.1.1.0
SNMP_GET = (
    b"\x30\x29\x02\x01\x00\x04\x06public"
    b"\xa0\x1c\x02\x04\x4c\x61\x6e\x53\x02\x01\x00\x02\x01\x00"
    b"\x30\x0e\x30\x0c\x06\x08" + _SYSDESCR + b"\x05\x00")


def _ber(data, pos):
    """Read one BER element: (tag, value bytes, position after it)."""
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("truncated")
    return tag, data[pos:pos + length], pos + length


def parse_snmp(data):
    """The system description in an SNMP response, '' if there is none."""
    try:
        _tag, message, _ = _ber(data, 0)
        pos = 0
        for _field in range(2):  # version, community
            _tag, _value, pos = _ber(message, pos)
        tag, pdu, _ = _ber(message, pos)
        if tag != 0xA2:
            return ""
        pos = 0
        for _field in range(3):  # request id, error, error index
            _tag, _value, pos = _ber(pdu, pos)
        _tag, bindings, _ = _ber(pdu, pos)
        _tag, binding, _ = _ber(bindings, 0)
        tag, oid, pos = _ber(binding, 0)
        tag, value, _ = _ber(binding, pos)
        if oid != _SYSDESCR or tag != 0x04:
            return ""
    except (IndexError, ValueError):
        return ""
    text = value.decode("utf-8", errors="replace")
    text = " ".join("".join(
        c if c.isprintable() else " " for c in text).split())
    return text[:90]


def snmp_sysdescr(ip, timeout=1.0):
    """Ask a device to describe itself over SNMP (v1, 'public')."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(SNMP_GET, (ip, 161))
            data, (sender, _port) = sock.recvfrom(4096)
    except OSError:
        return ""
    return parse_snmp(data) if sender == ip else ""


# ---- announcements, names, TTL ----------------------------------------

_APPLE_MODELS = [
    (r"^(macbook|imac|macmini|macpro|macstudio|mac\d)", "macOS"),
    (r"^iphone", "iOS"), (r"^ipad", "iPadOS"), (r"^ipod", "iOS"),
    (r"^appletv", "tvOS"), (r"^watch", "watchOS"),
    (r"^audioaccessory", "audioOS (HomePod)"),
]
_SERVER = [
    (r"windows", "Windows"), (r"linux", "Linux"), (r"darwin", "macOS"),
    (r"android", "Android"), (r"freebsd", "FreeBSD"),
    (r"webos", "webOS"), (r"tizen", "Tizen"), (r"vxworks", "VxWorks"),
]
_HOSTNAMES = [
    (r"^(desktop|laptop|win)-[a-z0-9]{5,}", "Windows"),
    (r"^android[-_]|galaxy|pixel|oneplus|redmi|xiaomi|huawei|oppo",
     "Android"),
    (r"iphone", "iOS"), (r"ipad", "iPadOS"),
    (r"macbook|imac|mac-?mini|\bmbp\b", "macOS"),
    (r"openwrt", "Linux (OpenWrt)"),
    (r"raspberry|ubuntu|debian|fedora|linux", "Linux"),
    (r"^esp[-_0-9]|esp32|esp8266|shelly|tasmota", "Embedded firmware"),
]
_VENDORS = [
    (r"espressif|shelly|tuya", "Embedded firmware"),
    (r"raspberry pi", "Linux"),
]


def _first(table, text):
    for pattern, name in table:
        if re.search(pattern, text):
            return name
    return ""


def os_from_server(server):
    """OS named in a UPnP 'Server:' header such as 'Linux/5.10 UPnP/1.0'."""
    return _first(_SERVER, (server or "").split("UPnP")[0].lower())


def os_from_ttl(ttl):
    """Systems start their packets at 64, 128 or 255 hops."""
    if not ttl or ttl <= 0:
        return ""
    if ttl <= 64:
        return "Linux / Unix-like"
    if ttl <= 128:
        return "Windows"
    return "Embedded / network OS"


def guess_os(device):
    """Best guess for a Device (or Host-like object), '' if no clue.
    Sources in order of how much they can be trusted."""
    def get(name):
        return getattr(device, name, "") or ""

    services = " ".join(get("services") or [])
    names = f"{get('hostname')} {get('mdns_name')}".lower()
    return (
        get("service_os")
        or _first(_APPLE_MODELS, get("model").lower())
        or ("Android TV" if "_androidtvremote" in services else "")
        or os_from_server(get("upnp_server"))
        or _first(_HOSTNAMES, names)
        or _first(_VENDORS, get("vendor").lower())
        or os_from_ttl(getattr(device, "ttl", 0)))
