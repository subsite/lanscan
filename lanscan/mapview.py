"""Network map: one cluster per network around this computer. How far
out a device sits shows its ping time, on a logarithmic scale."""

import hashlib
import ipaddress
import math

import cairo
from gi.repository import Gdk, Graphene, Gtk, Pango

from .device import format_rtt

NODE_RADIUS = 20
CENTER_RADIUS = 27
LABEL_WIDTH = 116
BOX_W, BOX_H = 112, 80  # room a node and its label need
LIMIT = 1.1  # how far beyond the radius crowding may push a node
INNER = 0.3  # where the scale starts, as a fraction of the radius
RTT_MIN, RTT_MAX = 0.2, 500.0  # ms at the inner and the outer end
RINGS = (1, 10, 100)  # ms

_ONLINE = (0.208, 0.518, 0.894)
_SELF = (0.149, 0.635, 0.412)
_GATEWAY = (0.569, 0.255, 0.675)
_OFFLINE = (0.55, 0.55, 0.55)
_NEW = (0.902, 0.380, 0.0)


def rtt_fraction(rtt):
    """Ping time in ms -> distance from the centre, 0..1 (logarithmic).
    Devices that were never measured go on the outer edge (1.0)."""
    if not rtt or rtt <= 0:
        return 1.0
    t = math.log(rtt / RTT_MIN) / math.log(RTT_MAX / RTT_MIN)
    return min(0.9, max(0.0, t))


def _unit(key, salt=""):
    """A stable pseudo-random number in [0, 1) for `key`."""
    digest = hashlib.blake2s(
        f"{salt}/{key}".encode(), digest_size=4).digest()
    return int.from_bytes(digest, "big") / 2 ** 32


def even_layout(count, rx, ry):
    """Spread `count` nodes evenly around (0, 0): every node gets its
    own direction, so no line runs through another node, and they take
    turns between as many rings as it takes to fit. Returns [(x, y)]."""
    if count <= 0:
        return []
    size = min(rx, ry)
    for rings in (1, 2, 3, 4):
        if rings == 1:
            radii = [0.66]
        else:
            radii = [0.44 + 0.56 * j / (rings - 1) for j in range(rings)]
        # Neighbours on the innermost ring are `rings` directions apart.
        gap = 2 * radii[0] * size * math.sin(
            min(math.pi / 2, math.pi * rings / count))
        if count <= rings or gap >= BOX_W:
            break
    # Stepping through the rings in this order keeps direct neighbours
    # as far apart as possible.
    order = {1: [0], 2: [0, 1], 3: [0, 2, 1], 4: [0, 2, 1, 3]}[rings]
    angles = [2 * math.pi * i / count - math.pi / 2 for i in range(count)]
    return _relax(
        angles, [radii[order[i % rings]] for i in range(count)], rx, ry)


def organic_layout(items, rx, ry, box=None):
    """Scatter nodes around (0, 0). `items` is [(key, fraction)]; the
    fraction is the distance (scaled to the radii rx, ry). The keys put
    the nodes in a stable pseudo-random order around the circle, each
    in its own direction, so no line runs through another node.
    Overlapping nodes are nudged apart, so distances are approximate
    where it is crowded. `box` is the room (width, height) one node
    needs. Returns [(x, y)]."""
    count = len(items)
    around = sorted(range(count), key=lambda i: (_unit(items[i][0]), i))
    start = 2 * math.pi * _unit(items[around[0]][0]) if count else 0
    angles = [0.0] * count
    for slot, i in enumerate(around):
        angles[i] = start + 2 * math.pi * slot / count
    return _relax(
        angles, [INNER + (1 - INNER) * t for _key, t in items], rx, ry,
        box)


def _relax(angles, want, rx, ry, box=None):
    """Place nodes at the given directions and distances (fractions of
    rx, ry), then move overlapping ones apart. Nodes are moved outwards
    along their own direction, which keeps them off each other's
    lines; only if that is not enough they are nudged sideways."""
    box_w, box_h = box or (BOX_W, BOX_H)
    pts = []
    for angle, r in zip(angles, want):
        pts.append([math.cos(angle) * r * rx, math.sin(angle) * r * ry])

    def reach(point):
        return math.hypot(point[0] / rx, point[1] / ry)

    def overlaps():
        """(i, j, x overlap, y overlap); j is None for the middle node."""
        found = []
        for i, point in enumerate(pts):
            ox, oy = box_w - abs(point[0]), box_h - abs(point[1])
            if ox > 0 and oy > 0:
                found.append((i, None, ox, oy))
            for j in range(i + 1, len(pts)):
                ox = box_w - abs(pts[j][0] - point[0])
                oy = box_h - abs(pts[j][1] - point[1])
                if ox > 0 and oy > 0:
                    found.append((i, j, ox, oy))
        return found

    for _step in range(120):
        found = overlaps()
        if not found:
            return [(x, y) for x, y in pts]
        stuck = True
        for i, j, ox, oy in found:
            if j is not None and reach(pts[j]) > reach(pts[i]):
                i = j  # the outer one of the two gives way
            point = pts[i]
            length = math.hypot(*point) or 1e-6
            grow = 1 + min(ox, oy, 12) / length
            if reach(point) * grow <= LIMIT:
                point[0] *= grow
                point[1] *= grow
                stuck = False
        if stuck:
            break
    for _step in range(8):  # no room left: legibility comes first
        found = overlaps()
        if not found:
            break
        for i, j, ox, oy in found:
            a = pts[i]
            b = pts[j] if j is not None else [0.0, 0.0]
            if ox / box_w < oy / box_h:
                axis, shift = 0, ox / 2 + 0.5
            else:
                axis, shift = 1, oy / 2 + 0.5
            shift = math.copysign(shift, (b[axis] - a[axis]) or 1)
            if j is None:
                a[axis] -= 2 * shift
            else:
                a[axis] -= shift
                b[axis] += shift
    return [(x, y) for x, y in pts]


def group_by_network(devices, networks):
    """Split devices into [(label, [devices])], one group per network
    that has any; devices outside every network end up in 'Other'."""
    groups, remaining = [], list(devices)
    for name, network in networks:
        members, rest = [], []
        for dev in remaining:
            try:
                inside = ipaddress.ip_address(dev.ip) in network
            except ValueError:
                inside = False
            (members if inside else rest).append(dev)
        remaining = rest
        if members:
            label = f"{name}  ·  {network}" if name else str(network)
            groups.append((label, members))
    if remaining:
        groups.append(("Other" if groups else "", remaining))
    return groups


class MapView(Gtk.Widget):
    __gtype_name__ = "LanscanMapView"

    def __init__(self, model, on_pick):
        """`model` lists the devices; `on_pick(device or None)` is called
        when a node (or empty space) is clicked."""
        super().__init__(hexpand=True, vexpand=True, has_tooltip=True)
        self.model = model
        self.current = None
        self.networks = []  # (name, IPv4Network)
        self.topology = False  # gateway in the middle, no ping distances
        self._on_pick = on_pick
        self.wifi_note = lambda dev: ""  # set by the window
        self._nodes = []  # (x, y, radius, device)
        self._icons = {}
        self._layouts = {}
        model.connect("items-changed", lambda *a: self.queue_draw())
        click = Gtk.GestureClick()
        click.connect("released", self._on_click)
        self.add_controller(click)
        self.connect("query-tooltip", self._on_tooltip)

    def refresh(self):
        self.queue_draw()

    def set_current(self, device):
        self.current = device
        self.queue_draw()

    def set_topology(self, topology):
        self.topology = bool(topology)
        self.queue_draw()

    def set_networks(self, networks):
        self.networks = list(networks)
        self.queue_draw()

    def _devices(self):
        """The devices this map shows: those on the networks."""
        items = (self.model.get_item(i)
                 for i in range(self.model.get_n_items()))
        return [d for d in items if not d.wifi]

    def _scatter(self, items, rx, ry):
        """Cached layout; `items` is a node count for an even spread."""
        even = isinstance(items, int)
        key = (round(rx), round(ry), items if even else tuple(items))
        if key not in self._layouts:
            if len(self._layouts) > 32:
                self._layouts.clear()
            self._layouts[key] = (even_layout if even else organic_layout)(
                items, rx, ry)
        return self._layouts[key]

    def _layout(self, width, height):
        """Clusters as dicts: label, x/y/w of the cell, cx/cy, rx/ry,
        center device (or None) and nodes [(x, y, device)]."""
        groups = group_by_network(self._devices(), self.networks)
        if not groups:
            return []
        cols = math.ceil(math.sqrt(len(groups)))
        rows = math.ceil(len(groups) / cols)
        cell_w, cell_h = width / cols, height / rows
        clusters = []
        for index, (label, devices) in enumerate(groups):
            x0 = (index % cols) * cell_w
            y0 = (index // cols) * cell_h
            top = 26 if label else 0
            me = next((d for d in devices if d.is_self), None)
            gateway = next((d for d in devices if d.is_gateway), None)
            even = self.topology
            # Ping times are measured from here, so this computer is
            # the natural middle for those.
            center = (gateway or me) if even else (me or gateway)
            others = sorted(
                (d for d in devices if d is not center),
                key=lambda d: d.ip_sort_key())
            rx = max(70.0, cell_w / 2 - 66)
            ry = max(70.0, (cell_h - top) / 2 - 58)
            rx, ry = min(rx, ry * 1.7), min(ry, rx * 1.2)
            cx, cy = x0 + cell_w / 2, y0 + top + (cell_h - top) / 2 - 12
            items = len(others) if even else [
                (d.mac or d.ip, round(rtt_fraction(d.rtt), 3))
                for d in others]
            nodes = [(cx + x, cy + y, d) for (x, y), d in zip(
                self._scatter(items, rx, ry), others)]
            clusters.append({
                "label": label, "x": x0, "y": y0, "w": cell_w,
                "cx": cx, "cy": cy, "rx": rx, "ry": ry, "even": even,
                "center": center, "nodes": nodes})
        return clusters

    def _node_at(self, x, y):
        for nx, ny, radius, dev in self._nodes:
            if abs(x - nx) <= radius + 6 and (
                    -radius - 6 <= y - ny <= radius + 34):
                return dev
        return None

    def _on_click(self, _gesture, _n, x, y):
        self._on_pick(self._node_at(x, y))

    def _on_tooltip(self, _widget, x, y, _keyboard, tooltip):
        dev = self._node_at(x, y)
        if dev is None:
            return False
        ping = format_rtt(dev.rtt)
        lines = [dev.display_name, dev.ip, dev.mac, dev.vendor_text,
                 dev.model, dev.os_text, dev.top_services(),
                 dev.status_text,
                 f"Ping {ping}" if ping and not dev.is_self else "",
                 self.wifi_note(dev)]
        tooltip.set_text("\n".join(l for l in lines if l))
        return True

    def _icon(self, name):
        key = (name, self.get_scale_factor())
        if key not in self._icons:
            theme = Gtk.IconTheme.get_for_display(self.get_display())
            self._icons[key] = theme.lookup_icon(
                name, None, 24, key[1], Gtk.TextDirection.NONE,
                Gtk.IconLookupFlags.PRELOAD)
        return self._icons[key]

    def _fill(self, dev):
        if not dev.online:
            return _OFFLINE
        if dev.is_gateway:
            return _GATEWAY
        if dev.is_self:
            return _SELF
        return _ONLINE

    def _draw_rings(self, cr, cluster, fg):
        cx, cy, rx, ry = (cluster[k] for k in ("cx", "cy", "rx", "ry"))
        cr.set_line_width(1)
        for ms in () if cluster["even"] else RINGS:
            r = INNER + (1 - INNER) * rtt_fraction(ms)
            cr.save()
            cr.translate(cx, cy)
            cr.scale(rx, ry)
            cr.arc(0, 0, r, 0, 2 * math.pi)
            cr.restore()
            cr.set_dash([2, 5])
            cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.13)
            cr.stroke()
        cr.set_dash([])
        # A soft light in the middle.
        glow = cairo.RadialGradient(cx, cy, 0, cx, cy, min(rx, ry) * 0.9)
        glow.add_color_stop_rgba(0, fg.red, fg.green, fg.blue, 0.07)
        glow.add_color_stop_rgba(1, fg.red, fg.green, fg.blue, 0.0)
        cr.set_source(glow)
        cr.arc(cx, cy, min(rx, ry) * 0.9, 0, 2 * math.pi)
        cr.fill()

    def _draw_link(self, cr, cluster, x, y, dev, fg):
        """A slightly bent line from the centre, fading on the way out."""
        cx, cy = cluster["cx"], cluster["cy"]
        bend = (_unit(dev.mac or dev.ip, "bend") - 0.5) * (
            0.12 if cluster["even"] else 0.24)
        mx = (cx + x) / 2 - (y - cy) * bend
        my = (cy + y) / 2 + (x - cx) * bend
        if dev.online:
            color = self._fill(dev)
            paint = cairo.LinearGradient(cx, cy, x, y)
            paint.add_color_stop_rgba(0, *color, 0.10)
            paint.add_color_stop_rgba(1, *color, 0.65)
            cr.set_source(paint)
            cr.set_line_width(1.6)
            cr.set_dash([])
        else:
            cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.13)
            cr.set_line_width(1)
            cr.set_dash([3, 4])
        cr.move_to(cx, cy)
        cr.curve_to(mx, my, mx, my, x, y)
        cr.stroke()
        cr.set_dash([])

    def _draw_node(self, cr, x, y, radius, dev, fg):
        color = self._fill(dev)
        if dev.online:
            halo = cairo.RadialGradient(x, y, radius * 0.8, x, y, radius * 2)
            halo.add_color_stop_rgba(0, *color, 0.38)
            halo.add_color_stop_rgba(1, *color, 0.0)
            cr.set_source(halo)
            cr.arc(x, y, radius * 2, 0, 2 * math.pi)
            cr.fill()
            light = tuple(min(1.0, c + 0.22) for c in color)
            body = cairo.RadialGradient(
                x - radius * 0.4, y - radius * 0.5, radius * 0.1,
                x, y, radius)
            body.add_color_stop_rgb(0, *light)
            body.add_color_stop_rgb(1, *color)
            cr.set_source(body)
        else:
            cr.set_source_rgba(*color, 0.45)
        cr.arc(x, y, radius, 0, 2 * math.pi)
        cr.fill()
        if not dev.known:
            cr.set_source_rgb(*_NEW)
            cr.set_line_width(2.5)
            cr.arc(x, y, radius + 1.5, 0, 2 * math.pi)
            cr.stroke()
        if dev is self.current:
            cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.9)
            cr.set_line_width(2)
            cr.arc(x, y, radius + 5.5, 0, 2 * math.pi)
            cr.stroke()

    def do_snapshot(self, snapshot):
        width, height = self.get_width(), self.get_height()
        if width <= 0 or height <= 0:
            return
        clusters = self._layout(width, height)
        self._nodes = []
        for cluster in clusters:
            self._nodes += [
                (x, y, NODE_RADIUS, d) for x, y, d in cluster["nodes"]]
            if cluster["center"] is not None:
                self._nodes.append((
                    cluster["cx"], cluster["cy"], CENTER_RADIUS,
                    cluster["center"]))
        selected = self.current
        fg = self.get_color()

        rect = Graphene.Rect().init(0, 0, width, height)
        cr = snapshot.append_cairo(rect)
        for cluster in clusters:
            self._draw_rings(cr, cluster, fg)
            for x, y, dev in cluster["nodes"]:
                self._draw_link(cr, cluster, x, y, dev, fg)
            if cluster["center"] is None:
                # Nothing known to sit in the middle: draw a plain hub.
                cr.set_source_rgba(fg.red, fg.green, fg.blue, 0.35)
                cr.arc(cluster["cx"], cluster["cy"], 7, 0, 2 * math.pi)
                cr.fill()
        for x, y, radius, dev in self._nodes:
            self._draw_node(cr, x, y, radius, dev, fg)

        white = Gdk.RGBA()
        white.parse("white")
        dim = Gdk.RGBA()
        dim.red, dim.green, dim.blue, dim.alpha = (
            fg.red, fg.green, fg.blue, 0.6)
        faint = Gdk.RGBA()
        faint.red, faint.green, faint.blue, faint.alpha = (
            fg.red, fg.green, fg.blue, 0.38)
        for cluster in clusters:
            if cluster["label"]:
                self._text(
                    snapshot, cluster["label"],
                    cluster["x"] + cluster["w"] / 2, cluster["y"] + 8, dim,
                    bold=True, width=max(60, cluster["w"] - 16))
            for ms in () if cluster["even"] else RINGS:
                r = INNER + (1 - INNER) * rtt_fraction(ms)
                self._text(
                    snapshot, f"{ms} ms", cluster["cx"],
                    cluster["cy"] - r * cluster["ry"] - 15, faint,
                    small=True)
        if not all(cluster["even"] for cluster in clusters):
            self._text(
                snapshot, "Distance shows ping time from this computer",
                width / 2, height - 22, faint, small=True,
                width=max(60, width - 16))
        for x, y, radius, dev in self._nodes:
            icon = self._icon(dev.icon_name)
            if icon is not None:
                snapshot.save()
                snapshot.translate(Graphene.Point().init(x - 12, y - 12))
                icon.snapshot_symbolic(snapshot, 24, 24, [white])
                snapshot.restore()
            self._text(snapshot, dev.display_name, x, y + radius + 5,
                       fg if dev.online else dim, bold=dev is selected)
            self._text(snapshot, dev.ip, x, y + radius + 21, dim,
                       small=True)

    def _text(self, snapshot, text, x, y, color, bold=False, small=False,
              width=LABEL_WIDTH):
        """Draw `text` centred on x, with its top at y."""
        layout = self.create_pango_layout(text)
        layout.set_width(int(width * Pango.SCALE))
        layout.set_alignment(Pango.Alignment.CENTER)
        layout.set_ellipsize(Pango.EllipsizeMode.END)
        attrs = Pango.AttrList()
        attrs.insert(Pango.attr_scale_new(0.78 if small else 0.88))
        if bold:
            attrs.insert(Pango.attr_weight_new(Pango.Weight.BOLD))
        layout.set_attributes(attrs)
        snapshot.save()
        snapshot.translate(Graphene.Point().init(x - width / 2, y))
        snapshot.append_layout(layout, color)
        snapshot.restore()
