"""The Device model object, device types and type guessing."""

import time

from gi.repository import Gio, GObject

from .osguess import guess_os

# key, label, icon
TYPES = [
    ("unknown", "Unknown", "network-wired-symbolic"),
    ("router", "Router / access point", "network-wireless-symbolic"),
    ("computer", "Computer", "computer-symbolic"),
    ("phone", "Phone", "phone-symbolic"),
    ("tablet", "Tablet", "tablet-symbolic"),
    ("tv", "TV / media player", "tv-symbolic"),
    ("printer", "Printer", "printer-network-symbolic"),
    ("server", "Server / NAS", "network-server-symbolic"),
    ("speaker", "Speaker", "audio-speakers-symbolic"),
    ("camera", "Camera", "camera-video-symbolic"),
    ("console", "Game console", "input-gaming-symbolic"),
    ("iot", "Smart device", "modem-symbolic"),
]
TYPE_KEYS = [t[0] for t in TYPES]
TYPE_LABELS = {t[0]: t[1] for t in TYPES}
TYPE_ICONS = {t[0]: t[2] for t in TYPES}
GATEWAY_ICON = "lanscan-globe-symbolic"  # shipped in lanscan/icons

# Persisted fields and their defaults. Order defines the database columns;
# append new fields at the end.
FIELDS = {
    "mac": "",
    "ip": "",
    "hostname": "",
    "mdns_name": "",
    "vendor": "",
    "custom_name": "",
    "device_type": "",  # chosen by the user, "" = automatic
    "guessed_type": "",
    "os": "",
    "ports": None,  # list of dicts
    "services": None,  # list of mDNS service types
    "ports_scanned_at": 0.0,
    "first_seen": 0.0,
    "last_seen": 0.0,
    "online": False,
    "known": True,
    "is_gateway": False,
    "is_self": False,
    "friendly_name": "",  # name the device announces (UPnP / mDNS)
    "model": "",  # manufacturer and model it announces
    "upnp_type": "",
    "nmap_type": "",  # device type according to nmap
    "rtt": 0.0,  # round trip (ping) time in ms, 0 = never measured
    "ttl": 0,  # hops left on its ping replies
    "service_os": "",  # OS according to its services, SMB or SNMP
    "upnp_server": "",
}
JSON_FIELDS = ("ports", "services")
NOT_SCANNED = "Ports not scanned yet"
BOOL_FIELDS = ("online", "known", "is_gateway", "is_self")


# Well-known ports in order of how interesting they are in a summary,
# with the name people know the service by.
COMMON_PORTS = {
    22: "ssh", 80: "http", 443: "https", 445: "samba", 139: "samba",
    3389: "rdp", 5900: "vnc", 21: "ftp", 23: "telnet", 53: "dns",
    631: "ipp", 9100: "printing", 515: "printing", 548: "afp", 2049: "nfs",
    1883: "mqtt", 8883: "mqtt", 554: "rtsp", 25: "smtp", 587: "smtp",
    143: "imap", 993: "imap", 3306: "mysql", 5432: "postgres",
    8080: "http", 8443: "https", 8000: "http", 8008: "http",
    8009: "cast", 5000: "upnp", 32400: "plex", 8123: "home-assistant",
    62078: "iphone-sync", 111: "rpc", 135: "msrpc", 5353: "mdns",
}
_PORT_RANK = {port: rank for rank, port in enumerate(COMMON_PORTS)}
_NO_NAME = ("", "unknown", "tcpwrapped")


def is_random_mac(mac):
    """True for locally administered ("private", randomized) addresses."""
    return len(mac) >= 2 and mac[1].upper() in "26AE"


class ServiceRow(GObject.Object):
    """One line shown underneath a device in the list view."""

    __gtype_name__ = "LanscanServiceRow"

    def __init__(self, text, url=""):
        super().__init__()
        self.text = text
        self.url = url  # set when the service can be opened in a browser


class NetworkGroup(GObject.Object):
    """Collapsible heading row in the list view: one per network."""

    __gtype_name__ = "LanscanNetworkGroup"
    __gsignals__ = {"changed": (GObject.SignalFlags.RUN_FIRST, None, ())}

    def __init__(self, key):
        super().__init__()
        self.key = key  # label from the grouping, "" without networks
        self.devices = Gio.ListStore(item_type=Device)

    @property
    def title(self):
        devices = list(self.devices)
        online = sum(d.online for d in devices)
        return (f"{self.key or 'Devices'}   —   "
                f"{online} of {len(devices)} online")

    def sync(self, devices):
        """Make the group hold exactly `devices`, touching as little as
        possible so expanded rows stay expanded."""
        wanted = set(devices)
        for i in reversed(range(self.devices.get_n_items())):
            if self.devices.get_item(i) not in wanted:
                self.devices.remove(i)
        have = set(self.devices)
        for dev in devices:
            if dev not in have:
                self.devices.append(dev)
        self.emit("changed")


class Device(GObject.Object):
    __gtype_name__ = "LanscanDevice"
    __gsignals__ = {"changed": (GObject.SignalFlags.RUN_FIRST, None, ())}

    def __init__(self, **values):
        super().__init__()
        self.id = None
        self.scanning = False  # a port scan is running (not persisted)
        for name, default in FIELDS.items():
            setattr(self, name, [] if name in JSON_FIELDS else default)
        for name, value in values.items():
            setattr(self, name, value)

    @property
    def display_name(self):
        if self.custom_name:
            return self.custom_name
        if self.friendly_name:
            return self.friendly_name
        for name in (self.mdns_name, self.hostname):
            if name:
                return name.removesuffix(".local").removesuffix(".lan")
        if self.is_self:
            return "This computer"
        if self.model:
            return self.model
        if self.vendor:
            return f"{self.vendor} device"
        return self.ip or self.mac or "Unknown device"

    @property
    def type(self):
        key = self.device_type or self.guessed_type
        return key if key in TYPE_ICONS else "unknown"

    @property
    def icon_name(self):
        if self.is_gateway and self.type == "router":
            return GATEWAY_ICON  # the way out to the internet
        return TYPE_ICONS[self.type]

    @property
    def status_text(self):
        return "Online" if self.online else "Offline"

    @property
    def vendor_text(self):
        if self.vendor:
            return self.vendor
        return "Private address" if is_random_mac(self.mac) else ""

    def ip_sort_key(self):
        try:
            return tuple(int(p) for p in self.ip.split("."))
        except ValueError:
            return (999,)

    @property
    def os_text(self):
        """nmap's fingerprint, or else our best guess marked as one."""
        if self.os:
            return self.os
        guess = guess_os(self)
        return f"{guess} (likely)" if guess else ""

    def matches(self, text):
        text = text.lower()
        haystack = (
            self.display_name, self.ip, self.mac, self.vendor, self.hostname,
            self.mdns_name, TYPE_LABELS[self.type], self.os_text, self.model,
            self.friendly_name,
        )
        return any(text in (h or "").lower() for h in haystack)

    def top_services(self, count=3):
        """The most common open services, e.g. 'ssh, http, samba'."""
        ports = sorted(
            self.ports or [],
            key=lambda p: (_PORT_RANK.get(p.get("port"), len(_PORT_RANK)),
                           p.get("port") or 0))
        names = []
        for port in ports:
            number = port.get("port")
            name = COMMON_PORTS.get(number)
            if not name:
                name = (port.get("service") or "").rstrip("?")
                if name in _NO_NAME:
                    name = str(number)
            if name not in names:
                names.append(name)
        return ", ".join(names[:count])

    def service_rows(self):
        """(text, url) for the expandable rows in the list view; url is
        '' unless the service is a web server."""
        rows = []
        for port in self.ports or []:
            line = f"{port['port']}/{port.get('proto', 'tcp')}"
            detail = " — ".join(
                p for p in (port.get("service"), port.get("product")) if p)
            rows.append((f"{line}   {detail}" if detail else line,
                         web_url(self.ip, port)))
        for service in self.services or []:
            rows.append((f"mDNS   {short_service(service)}", ""))
        if self.scanning:
            rows.append(("Scanning ports…", ""))
        elif not self.ports_scanned_at:
            rows.append((NOT_SCANNED, ""))
        elif not self.ports:
            rows.append(("No open ports found", ""))
        return rows

    def service_lines(self):
        return [text for text, _url in self.service_rows()]

    def notify_changed(self):
        self.emit("changed")


def web_url(ip, port):
    """Browser address for an open port, or '' if it is not a web server."""
    name = (port.get("service") or "").lower()
    number = port.get("port")
    if not ip or "http" not in name or port.get("proto", "tcp") != "tcp":
        return ""
    secure = (port.get("tunnel") == "ssl" or name.startswith(("https", "ssl"))
              or number in (443, 8443))
    scheme, default = ("https", 443) if secure else ("http", 80)
    suffix = "" if number == default else f":{number}"
    return f"{scheme}://{ip}{suffix}/"


def format_rtt(ms):
    if not ms:
        return ""
    return f"{ms:.1f} ms" if ms < 10 else f"{ms:.0f} ms"


def short_service(service):
    """'_ipp._tcp' -> 'ipp'."""
    return service.strip("_").split("._")[0]


# Each hint list is (needles, type); the first list entry that matches wins.
_SERVICE_HINTS = [
    (("_ipp.", "_ipps.", "_printer.", "_pdl-datastream.", "_scanner.",
      "_uscan."), "printer"),
    (("_googlecast.", "_androidtvremote", "_roku", "_nvstream.",
      "_amzn-wplay.", "_mediaremotetv."), "tv"),
    (("_sonos.", "_spotify-connect."), "speaker"),
    (("_hap.", "_hue.", "_matter.", "_esphomelib.", "_shelly.",
      "_homekit."), "iot"),
]
_COMPUTER_SERVICES = [
    (("_smb.", "_afpovertcp.", "_nfs.", "_workstation.", "_ssh.",
      "_sftp-ssh.", "_rfb.", "_companion-link."), "computer"),
    (("_airplay.", "_raop."), "speaker"),
]

_NAME_HINTS = [
    (("iphone", "android", "pixel", "galaxy", "oneplus", "huawei-p",
      "redmi", "smartphone"), "phone"),
    (("ipad", "tablet", "galaxy-tab", "kindle"), "tablet"),
    (("chromecast", "appletv", "apple-tv", "apple tv", "roku", "bravia",
      "shield", "firetv", "fire tv", "-tv", "tv-", " tv", "webos", "tizen",
      "kodi", "smarttv"), "tv"),
    (("printer", "laserjet", "officejet", "deskjet", "envy", "epson",
      "brother", "canon", "pixma", "ecotank"), "printer"),
    (("playstation", "ps4", "ps5", "xbox", "nintendo", "steamdeck"),
     "console"),
    (("sonos", "homepod", "audioaccessory", "echo-", "echo dot",
      "nest-audio", "nest-mini", "soundbar", "denon", "heos"), "speaker"),
    (("camera", "ipcam", "doorbell"), "camera"),
    (("nas", "synology", "diskstation", "qnap", "truenas", "proxmox",
      "server", "readynas", "mycloud"), "server"),
    (("esp-", "esp32", "esp8266", "shelly", "tasmota", "hue", "tuya",
      "wled", "sonoff", "tradfri", "smartthings", "homeassistant"), "iot"),
    (("macbook", "imac", "macmini", "macpro", "macstudio", "laptop",
      "desktop", "thinkpad", "fedora", "ubuntu", "debian", "windows",
      "-pc", "pc-"), "computer"),
    (("router", "gateway", "openwrt", "fritz", "unifi", "accesspoint",
      "access point", "archer", "nighthawk", "orbi", "deco", "eero"),
     "router"),
]

_UPNP_HINTS = [
    (("mediarenderer", "dial-multiscreen", "tvdevice", "roku"), "tv"),
    (("internetgatewaydevice", "wandevice", "wfadevice",
      "wlanaccesspoint"), "router"),
    (("printer", "scanner"), "printer"),
    (("zoneplayer",), "speaker"),
    (("camera",), "camera"),
    (("lighting", "binarylight", "dimmablelight", "hvac"), "iot"),
    (("mediaserver",), "server"),
]

_NMAP_HINTS = [
    (("phone",), "phone"),
    (("print",), "printer"),
    (("router", "wap", "switch", "firewall", "bridge", "hub",
      "load balancer"), "router"),
    (("media device",), "tv"),
    (("webcam", "camera"), "camera"),
    (("storage",), "server"),
    (("game console",), "console"),
    (("specialized", "power-device", "remote management"), "iot"),
    (("general purpose", "terminal"), "computer"),
]

_VENDOR_HINTS = [
    (("espressif", "tuya", "shelly", "philips lighting", "signify",
      "itead", "allterco", "nest labs", "ikea of sweden", "belkin"), "iot"),
    (("synology", "qnap"), "server"),
    (("sonos", "bose", "harman"), "speaker"),
    (("nintendo", "sony interactive"), "console"),
    (("hikvision", "dahua", "axis comm", "reolink", "arlo"), "camera"),
    (("raspberry",), "computer"),
    (("roku", "vizio", "tcl ", "hisense"), "tv"),
    (("ubiquiti", "mikrotik", "netgear", "tp-link", "zyxel", "avm ",
      "eero", "aruba", "ruckus", "sagemcom", "arcadyan", "technicolor"),
     "router"),
    (("hewlett packard", "hp inc", "seiko epson", "brother industries",
      "canon", "lexmark", "kyocera", "xerox"), "printer"),
]


def _lookup(hints, text):
    for needles, kind in hints:
        if any(n in text for n in needles):
            return kind
    return ""


def guess_type(device):
    """Best-effort device type, from the most to the least reliable clue."""
    if device.is_gateway:
        return "router"
    services = " ".join(device.services or []).lower()
    names = " ".join((
        device.friendly_name or "", device.model or "",
        device.hostname or "", device.mdns_name or "")).lower()
    open_ports = {p.get("port") for p in device.ports or []}
    os_name = (device.os or "").lower()
    kind = (
        _lookup(_SERVICE_HINTS, services)
        or _lookup(_NAME_HINTS, names)
        or _lookup(_UPNP_HINTS, (device.upnp_type or "").lower())
        or ("printer" if open_ports & {631, 9100, 515} else "")
        or _lookup(_NMAP_HINTS, (device.nmap_type or "").lower())
        or _lookup(_VENDOR_HINTS, (device.vendor or "").lower())
        or _lookup(_COMPUTER_SERVICES, services)
    )
    if kind:
        return kind
    if device.is_self:
        return "computer"
    if any(w in os_name for w in ("android", "ios", "iphone")):
        return "phone"
    if any(w in os_name for w in ("windows", "linux", "mac os", "macos")):
        return "computer"
    if is_random_mac(device.mac):
        # Randomized addresses are mostly used by phones and tablets.
        return "phone"
    return ""


def format_time(timestamp, now=None):
    if not timestamp:
        return "Never"
    now = now or time.time()
    age = now - timestamp
    if age < 60:
        return "Just now"
    if age < 3600:
        return f"{int(age // 60)} min ago"
    if age < 86400:
        hours = int(age // 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))
