"""Wi-Fi map: the networks in range around this computer, the stronger
the signal the closer, with the client devices of each network as dots
around it."""

import math

import cairo
from gi.repository import Gdk, Graphene

from .mapview import (
    CENTER_RADIUS, INNER, LIMIT, _GATEWAY, _NEW, _OFFLINE, _ONLINE, _SELF, MapView,
    _unit, organic_layout)
from .wifi import band_of, signal_fraction

AP_RADIUS = 15
DOT_RADIUS = 4.5
WIFI_BOX = (98, 80)  # room a network, its label and its dots need
RINGS = (-50, -70, -90)  # dBm
ORBITS = ((AP_RADIUS + 10, 6), (AP_RADIUS + 21, 9))  # radius, most dots
_BANDS = {"2.4 GHz": (0.11, 0.60, 0.60), "5 GHz": _ONLINE,
          "6 GHz": _GATEWAY}
_CLIENT = (0.47, 0.56, 0.70)
EMPTY = ("No Wi-Fi networks in range yet.\nChoose a Wi-Fi adapter in the "
         "adapter menu next to Scan, then press Scan.")


def _strength(dev):
    return dev.signal or -999


def wifi_networks(devices):
    """Group what is in range into networks. Returns (networks, loose):
    networks are dicts with the strongest access point as 'ap', all of
    them as 'aps' and their 'clients'; loose are clients that are not
    connected to any of them. Access points with the same name are one
    network; hidden ones are each their own."""
    devices = [d for d in devices if d.wifi and d.online]
    by_key = {}
    for ap in (d for d in devices if d.wifi == "ap"):
        by_key.setdefault(ap.ssid or ap.mac, []).append(ap)
    networks, owner = [], {}
    for key in sorted(by_key):
        aps = sorted(by_key[key], key=lambda d: (-_strength(d), d.mac))
        if any(ap.mine for ap in aps) and not aps[0].mine:
            aps.sort(key=lambda d: not d.mine)  # show it as yours
        network = {"key": key, "ap": aps[0], "aps": aps, "clients": []}
        networks.append(network)
        for ap in aps:
            owner[ap.mac] = network
    loose = []
    for client in sorted(
            (d for d in devices if d.wifi == "client"), key=lambda d: d.mac):
        network = owner.get(client.bssid)
        (network["clients"] if network else loose).append(client)
    return networks, loose


def orbit_positions(count):
    """Offsets of up to 15 client dots on arcs above a network node."""
    points = []
    for radius, room in ORBITS:
        dots = min(room, count - len(points))
        for i in range(dots):
            # Spread over the upper side, around straight up.
            angle = -math.pi / 2 + (i - (dots - 1) / 2) * (
                math.radians(150) / room)
            points.append((radius * math.cos(angle), radius * math.sin(angle)))
    return points


def wifi_layout(devices, rx, ry):
    """Positions around (0, 0). Returns (networks, loose): the networks
    of wifi_networks() with 'x' and 'y' added, and [(x, y, client)]."""
    networks, loose = wifi_networks(devices)
    items = [(n["key"], round(signal_fraction(n["ap"].signal), 3))
             for n in networks]
    for network, (x, y) in zip(
            networks, organic_layout(items, rx, ry, WIFI_BOX)):
        network["x"], network["y"] = x, y
    placed = []
    for client in loose:
        angle = 2 * math.pi * _unit(client.mac, "loose")
        r = INNER + (1 - INNER) * signal_fraction(client.signal)
        placed.append(
            (math.cos(angle) * r * rx, math.sin(angle) * r * ry, client))
    return networks, placed


class WifiMapView(MapView):
    __gtype_name__ = "LanscanWifiMapView"

    def __init__(self, model, on_pick):
        super().__init__(model, on_pick)
        self.adapter = ""
        self._networks = {}  # access point shown -> its network
        self._cache = None

    def set_adapter(self, name):
        self.adapter = name or ""
        self.queue_draw()

    def _devices(self):
        items = (self.model.get_item(i)
                 for i in range(self.model.get_n_items()))
        return [d for d in items if d.wifi and d.online]

    def _fill(self, dev):
        if dev.mine:
            return _SELF
        if dev.wifi == "client":
            return _CLIENT
        return _BANDS.get(band_of(dev.freq), _OFFLINE)

    def _node_at(self, x, y):
        for nx, ny, radius, dev in reversed(self._nodes):
            if dev.wifi == "client":
                if math.hypot(x - nx, y - ny) <= radius + 3:
                    return dev
            elif abs(x - nx) <= radius + 6 and (
                    -radius - 6 <= y - ny <= radius + 34):
                return dev
        return None

    def _on_tooltip(self, _widget, x, y, _keyboard, tooltip):
        dev = self._node_at(x, y)
        if dev is None:
            return False
        network = self._networks.get(dev)
        if network is None:
            lines = [dev.display_name, dev.mac, dev.vendor_text,
                     dev.wifi_text,
                     "Also on your network" if dev.mine else ""]
            if dev.probes:
                lines.append("Looked for " + ", ".join(dev.probes))
        else:
            lines = [dev.display_name]
            if any(ap.mine for ap in network["aps"]):
                lines.append("Your network")
            lines += [f"{ap.mac}   {ap.wifi_text}" for ap in network["aps"]]
            count = len(network["clients"])
            if count:
                lines.append(f"{count} client{'s' if count != 1 else ''}")
        tooltip.set_text("\n".join(l for l in lines if l))
        return True

    def _layout(self, width, height):
        # Crowding pushes nodes up to LIMIT beyond the radius.
        rx = max(90.0, (width / 2 - 62) / LIMIT)
        ry = max(90.0, ((height - 30) / 2 - 56) / LIMIT)
        devices = self._devices()
        key = (round(rx), round(ry), tuple(
            (d.mac, d.ssid, d.bssid, d.signal, d.mine) for d in devices))
        if self._cache is None or self._cache[0] != key:
            self._cache = (key, wifi_layout(devices, rx, ry))
        return rx, ry, self._cache[1]

    def do_snapshot(self, snapshot):
        width, height = self.get_width(), self.get_height()
        if width <= 0 or height <= 0:
            return
        fg = self.get_color()
        dim, faint = Gdk.RGBA(), Gdk.RGBA()
        for color, alpha in ((dim, 0.6), (faint, 0.38)):
            color.red, color.green, color.blue, color.alpha = (
                fg.red, fg.green, fg.blue, alpha)
        rx, ry, (networks, loose) = self._layout(width, height)
        cx, cy = width / 2, (height - 30) / 2
        self._nodes, self._networks = [], {}
        if not networks and not loose:
            self._text(snapshot, EMPTY, cx, cy - 20, dim, width=width - 32)
            return
        frame = {"cx": cx, "cy": cy, "even": False}

        cr = snapshot.append_cairo(Graphene.Rect().init(0, 0, width, height))
        glow = cairo.RadialGradient(cx, cy, 0, cx, cy, min(rx, ry) * 0.9)
        glow.add_color_stop_rgba(0, fg.red, fg.green, fg.blue, 0.07)
        glow.add_color_stop_rgba(1, fg.red, fg.green, fg.blue, 0.0)
        cr.set_source(glow)
        cr.arc(cx, cy, min(rx, ry) * 0.9, 0, 2 * math.pi)
        cr.fill()
        cr.set_line_width(1)
        cr.set_dash([2, 5])
        cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.13)
        for dbm in RINGS:
            r = INNER + (1 - INNER) * signal_fraction(dbm)
            cr.save()
            cr.translate(cx, cy)
            cr.scale(rx, ry)
            cr.arc(0, 0, r, 0, 2 * math.pi)
            cr.restore()
            cr.stroke()
        cr.set_dash([])

        for x, y, client in loose:
            self._nodes.append((cx + x, cy + y, DOT_RADIUS, client))
        extra = []  # (x, y, clients that did not fit)
        for network in networks:
            x, y = cx + network["x"], cy + network["y"]
            ap = network["ap"]
            self._networks[ap] = network
            self._draw_link(cr, frame, x, y, ap, fg)
            dots = orbit_positions(len(network["clients"]))
            for (dx, dy), client in zip(dots, network["clients"]):
                self._nodes.append((x + dx, y + dy, DOT_RADIUS, client))
            if len(network["clients"]) > len(dots):
                extra.append((x, y, len(network["clients"]) - len(dots)))
            self._nodes.append((x, y, AP_RADIUS, ap))

        for x, y, radius, dev in self._nodes:
            if dev.wifi == "client":
                cr.set_source_rgba(*self._fill(dev), 0.95 if dev.bssid
                                   else 0.5)
                cr.arc(x, y, radius, 0, 2 * math.pi)
                cr.fill()
                if dev is self.current:
                    cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.9)
                    cr.set_line_width(1.5)
                    cr.arc(x, y, radius + 3, 0, 2 * math.pi)
                    cr.stroke()
                continue
            self._draw_node(cr, x, y, radius, dev, fg)
            if dev.security == "Open":  # anyone can listen in
                cr.set_source_rgb(*_NEW)
                cr.set_line_width(2)
                cr.arc(x, y, radius + 1.5, 0, 2 * math.pi)
                cr.stroke()
        # This computer, where the signals are measured.
        body = cairo.RadialGradient(
            cx - CENTER_RADIUS * 0.4, cy - CENTER_RADIUS * 0.5,
            CENTER_RADIUS * 0.1, cx, cy, CENTER_RADIUS)
        body.add_color_stop_rgb(0, *(min(1.0, c + 0.22) for c in _SELF))
        body.add_color_stop_rgb(1, *_SELF)
        cr.set_source(body)
        cr.arc(cx, cy, CENTER_RADIUS, 0, 2 * math.pi)
        cr.fill()

        white = Gdk.RGBA()
        white.parse("white")
        for dbm in RINGS:
            r = INNER + (1 - INNER) * signal_fraction(dbm)
            self._text(snapshot, f"{dbm} dBm", cx, cy - r * ry - 15, faint,
                       small=True)
        self._text(
            snapshot, "Distance shows signal strength · green is yours, "
            "other colours show the band · dots are client devices "
            "(deep scan)",
            width / 2, height - 22, faint, small=True,
            width=max(60, width - 16))
        self._draw_icon(snapshot, "computer-symbolic", cx, cy, white)
        self._text(snapshot, "This computer", cx, cy + CENTER_RADIUS + 5, fg)
        if self.adapter:
            self._text(snapshot, self.adapter, cx, cy + CENTER_RADIUS + 21,
                       dim, small=True)
        for x, y, count in extra:
            self._text(snapshot, f"+{count}", x, y - ORBITS[-1][0] - 19,
                       dim, small=True)
        for x, y, radius, dev in self._nodes:
            if dev.wifi == "client":
                continue
            self._draw_icon(snapshot, dev.icon_name, x, y, white, 16)
            self._text(snapshot, dev.display_name, x, y + radius + 4, fg,
                       bold=dev is self.current, width=WIFI_BOX[0] + 6)
            self._text(snapshot, dev.signal_text, x, y + radius + 19, dim,
                       small=True)

    def _draw_icon(self, snapshot, name, x, y, color, size=24):
        icon = self._icon(name)
        if icon is None:
            return
        snapshot.save()
        snapshot.translate(Graphene.Point().init(x - size / 2, y - size / 2))
        icon.snapshot_symbolic(snapshot, size, size, [color])
        snapshot.restore()
