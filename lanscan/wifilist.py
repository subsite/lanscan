"""The Wi-Fi list: one row per network, with its access points and
client devices folded underneath."""

from gi.repository import Gio, Gtk, Pango

from .device import Device, NetworkGroup, format_time
from .wifi import band_of

LOOSE = ""  # key of the group of clients that are not on any network


def _strength(dev):
    return dev.signal if dev.online and dev.signal else -999


def group_wifi(devices):
    """[(key, [devices])]: access points with the same name are one
    network (hidden ones each their own), followed by their clients.
    Clients without a network come last, under the key LOOSE."""
    groups, owner = {}, {}
    wifi = [d for d in devices if d.wifi]
    for ap in sorted((d for d in wifi if d.wifi == "ap"),
                     key=lambda d: (-_strength(d), d.mac)):
        key = ap.ssid or ap.mac
        groups.setdefault(key, []).append(ap)
        owner[ap.mac] = key
    loose = []
    for client in sorted((d for d in wifi if d.wifi == "client"),
                         key=lambda d: (-_strength(d), d.mac)):
        key = owner.get(client.bssid)
        (groups[key] if key is not None else loose).append(client)
    result = list(groups.items())
    if loose:
        result.append((LOOSE, loose))
    return result


class WifiGroup(NetworkGroup):
    """A Wi-Fi network: heading row of the list."""

    __gtype_name__ = "LanscanWifiGroup"

    @property
    def aps(self):
        return [d for d in self.devices if d.wifi == "ap"]

    @property
    def clients(self):
        return [d for d in self.devices if d.wifi == "client"]

    @property
    def title(self):
        if self.key == LOOSE:
            return "Not connected to a network"
        aps = self.aps
        return (aps[0].ssid if aps else "") or "Hidden network"

    @property
    def online(self):
        return any(d.online for d in self.devices)

    @property
    def mine(self):
        return any(d.mine for d in self.aps)

    @property
    def strength(self):
        return max((_strength(d) for d in self.devices), default=-999)

    @property
    def signal_text(self):
        if not self.online:
            return "Out of range"
        best = self.strength
        return f"{best} dBm" if best > -999 else ""

    @property
    def band_text(self):
        aps = self.aps
        if len(aps) == 1:
            return ap_band(aps[0])
        bands = sorted({band_of(d.freq).replace(" GHz", "") for d in aps}
                       - {""}, key=float)
        return " + ".join(bands) + " GHz" if bands else ""

    @property
    def security(self):
        return next((d.security for d in self.aps if d.security), "")

    @property
    def last_seen(self):
        return max((d.last_seen for d in self.devices), default=0)

    def clients_of(self, ap):
        return sum(d.bssid == ap.mac for d in self.clients)


def ap_band(dev):
    """'5 GHz ch 36'"""
    return dev.channel_text.replace(", channel", " ch")


def row_name(item):
    if isinstance(item, WifiGroup):
        return item.title
    if item.wifi == "ap":
        return item.custom_name or "Access point"
    return item.display_name


def row_signal(item):
    if isinstance(item, WifiGroup):
        return item.signal_text
    return item.signal_text if item.online else "Out of range"


def row_band(item):
    if isinstance(item, WifiGroup):
        return item.band_text
    return ap_band(item) if item.wifi == "ap" else ""


def row_security(item):
    return "" if getattr(item, "wifi", "") == "client" else item.security


def row_clients(item, group):
    if isinstance(item, WifiGroup):
        count = len(item.clients)
        return str(count) if count or item.key != LOOSE else ""
    if item.wifi == "ap" and group is not None:
        return str(group.clients_of(item) or "")
    return ""


def _single(item):
    """The device a row stands for: itself, or the only access point
    of a network."""
    if not isinstance(item, WifiGroup):
        return item
    aps = item.aps
    return aps[0] if len(aps) == 1 else None


def row_mac(item):
    dev = _single(item)
    return dev.mac if dev else ""


def row_vendor(item):
    dev = _single(item)
    return dev.vendor_text if dev else ""


def sort_rank(item):
    """Networks by signal with the unconnected clients last; inside a
    network the access points first."""
    if isinstance(item, WifiGroup):
        return (item.key == LOOSE, -item.strength)
    return (item.wifi != "ap", -_strength(item))


class WifiList(Gtk.ScrolledWindow):
    __gtype_name__ = "LanscanWifiList"

    def __init__(self, model, on_pick):
        """`model` lists all devices (the Wi-Fi ones are picked out);
        `on_pick(device)` is called when a device row is clicked."""
        super().__init__()
        self.model = model
        self._on_pick = on_pick
        self.groups = Gio.ListStore(item_type=WifiGroup)
        self.tree = Gtk.TreeListModel.new(
            self.groups, False, False,
            lambda item, *_: item.devices if isinstance(
                item, WifiGroup) else None)
        self.view = Gtk.ColumnView(
            show_row_separators=True, hexpand=True, vexpand=True,
            single_click_activate=True, css_classes=["compact"])
        sorted_model = Gtk.SortListModel(
            model=self.tree,
            sorter=Gtk.TreeListRowSorter.new(self.view.get_sorter()))
        self.view.set_model(Gtk.NoSelection(model=sorted_model))
        self.view.connect("activate", self._on_activate)
        self._build_columns()
        self.set_child(self.view)

    def refresh(self):
        """Regroup the devices, keeping the groups (and what is folded
        out) that are still there."""
        devices = [self.model.get_item(i)
                   for i in range(self.model.get_n_items())]
        wanted = group_wifi(devices)
        keys = [key for key, _members in wanted]
        for i in reversed(range(self.groups.get_n_items())):
            if self.groups.get_item(i).key not in keys:
                self.groups.remove(i)
        existing = {g.key: g for g in self.groups}
        for index, (key, members) in enumerate(wanted):
            group = existing.get(key)
            if group is not None:
                group.sync(members)
                continue
            group = WifiGroup(key)
            group.sync(members)
            position = min(index, self.groups.get_n_items())
            self.groups.insert(position, group)
            row = self.tree.get_child_row(position)
            if row is not None and group.mine:
                row.set_expanded(True)  # your own networks start open
        sorter = self.view.get_sorter()
        if sorter is not None:
            sorter.changed(Gtk.SorterChange.DIFFERENT)

    def expand_all(self, expand):
        for i in range(self.groups.get_n_items()):
            row = self.tree.get_child_row(i)
            if row is not None:
                row.set_expanded(expand)

    def _on_activate(self, view, position):
        row = view.get_model().get_item(position)
        if row is None:
            return
        item = row.get_item()
        if isinstance(item, Device):
            self._on_pick(item)
        elif row.is_expandable():
            row.set_expanded(not row.get_expanded())

    def _column(self, title, make, update, key, expand=False):
        """`update(widget, item, group)`: item is a WifiGroup or a
        Device, group the network a device row is under."""
        factory = Gtk.SignalListItemFactory()

        def setup(_f, cell):
            widget = make()
            widget.bound = []
            cell.set_child(widget)

        def bind(_f, cell):
            widget, row = cell.get_child(), cell.get_item()
            item = row.get_item()
            parent = row.get_parent()
            group = parent.get_item() if parent else None
            if isinstance(widget, Gtk.TreeExpander):
                widget.set_list_row(row)
            update(widget, item, group)
            # A device row also shows counts that its network knows.
            for source in (item, group):
                if source is not None:
                    widget.bound.append((source, source.connect(
                        "changed", lambda _s: update(widget, item, group))))

        def unbind(_f, cell):
            widget = cell.get_child()
            for source, handler in widget.bound:
                source.disconnect(handler)
            widget.bound = []
            if isinstance(widget, Gtk.TreeExpander):
                widget.set_list_row(None)

        factory.connect("setup", setup)
        factory.connect("bind", bind)
        factory.connect("unbind", unbind)
        column = Gtk.ColumnViewColumn(
            title=title, factory=factory, expand=expand, resizable=True)

        def compare(a, b, *_):
            ka, kb = key(a), key(b)
            return (ka > kb) - (ka < kb)

        column.set_sorter(Gtk.CustomSorter.new(compare))
        self.view.append_column(column)
        return column

    def _build_columns(self):
        def label():
            return Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)

        def text(getter):
            def update(widget, item, _group):
                widget.set_text(getter(item) or "")
                widget.set_opacity(1.0 if item.online else 0.55)
            return update

        def make_name():
            box = Gtk.Box(spacing=10)
            box.append(Gtk.Image())
            box.append(Gtk.Label(
                xalign=0, ellipsize=Pango.EllipsizeMode.END))
            box.append(Gtk.Label(
                label="YOURS", css_classes=["caption-heading", "success"]))
            return Gtk.TreeExpander(child=box)

        def update_name(expander, item, _group):
            box = expander.get_child()
            image = box.get_first_child()
            name = image.get_next_sibling()
            badge = name.get_next_sibling()
            is_group = isinstance(item, WifiGroup)
            name.set_text(row_name(item))
            name.set_css_classes(["heading"] if is_group else [])
            image.set_from_icon_name(
                ("network-wireless-symbolic" if item.key != LOOSE
                 else "network-wireless-offline-symbolic")
                if is_group else item.icon_name)
            # The heading speaks for its access points.
            badge.set_visible(item.mine and (
                is_group or item.wifi == "client"))
            badge.set_tooltip_text(
                "Looks like a network you scanned" if is_group
                else "Also on a network you scanned")
            box.set_opacity(1.0 if item.online else 0.55)

        def update_clients(widget, item, group):
            widget.set_text(row_clients(item, group))
            widget.set_opacity(1.0 if item.online else 0.55)

        self._column(
            "Name", make_name, update_name,
            key=lambda i: row_name(i).lower(), expand=True)
        signal = self._column("Signal", label, text(row_signal), sort_rank)
        self._column("Band / channel", label, text(row_band), row_band)
        self._column(
            "Security", label, text(row_security), row_security)
        self._column(
            "Clients", label, update_clients,
            key=lambda i: -len(i.clients) if isinstance(i, WifiGroup) else 0)
        self._column("MAC address", label, text(row_mac), row_mac)
        self._column(
            "Vendor", label, text(row_vendor),
            key=lambda i: row_vendor(i).lower(), expand=True)
        self._column(
            "Last seen", label, text(lambda i: format_time(i.last_seen)),
            key=lambda i: -i.last_seen)
        self.view.sort_by_column(signal, Gtk.SortType.ASCENDING)
