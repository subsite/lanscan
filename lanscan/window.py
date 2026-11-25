"""Main window: header, device list, map and detail pane."""

import os
import threading
import time

from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk, Pango

from . import APP_NAME, netinfo, scanner, wifi
from .detail import DetailPane
from .device import (
    NOT_SCANNED, TYPE_LABELS, Device, NetworkGroup, ServiceRow, format_time)
from .mapview import MapView, group_by_network
from .wifilist import WifiList
from .wifimap import WifiMapView

# Tighter rows than the Adwaita default, to fit more devices on screen.
CSS = """
columnview.compact > listview > row > cell {
  padding-top: 3px;
  padding-bottom: 3px;
}
columnview.compact > listview > row > cell button {
  min-height: 22px;
  padding-top: 0;
  padding-bottom: 0;
}
button.pane-handle {
  min-width: 16px;
  padding: 0;
  border-radius: 0;
  background-color: alpha(currentColor, 0.07);
}
button.pane-handle:hover {
  background-color: alpha(currentColor, 0.16);
}
"""


def load_css():
    display = Gdk.Display.get_default()
    if display is None:
        return
    Gtk.IconTheme.get_for_display(display).add_search_path(
        os.path.join(os.path.dirname(__file__), "icons"))
    provider = Gtk.CssProvider()
    provider.load_from_string(CSS)
    Gtk.StyleContext.add_provider_for_display(
        display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)


class Window(Adw.ApplicationWindow):
    def __init__(self, app, store):
        super().__init__(
            application=app, title=APP_NAME, default_width=1200,
            default_height=720)
        load_css()
        self.store = store
        self.scanning = False
        self.search_text = ""
        self.last_scan = 0.0
        self.current = None  # device shown in the detail pane
        self._local_networks = []
        self._unidentified = []
        self._show_empty_pane = False
        self.only_mine = store.get_setting("wifi_only_mine") == "1"

        # Devices -> filter -> groups per network -> tree (network,
        # device, service rows) -> sort.
        self._named_networks = []
        self.groups = Gio.ListStore(item_type=NetworkGroup)
        self.items = Gio.ListStore(item_type=Device)
        for dev in store.devices() + store.wifi_devices():
            self.items.append(dev)
        self.filter = Gtk.CustomFilter.new(self._matches)
        self.filtered = Gtk.FilterListModel(
            model=self.items, filter=self.filter)
        self.tree = Gtk.TreeListModel.new(
            self.groups, False, False, self._child_model)
        self.column_view = Gtk.ColumnView(
            show_row_separators=True, hexpand=True, vexpand=True,
            single_click_activate=True, css_classes=["compact"])
        self.sorted = Gtk.SortListModel(
            model=self.tree,
            sorter=Gtk.TreeListRowSorter.new(self.column_view.get_sorter()))
        self.column_view.set_model(Gtk.NoSelection(model=self.sorted))
        self.column_view.connect("activate", self._on_row_activated)
        self._build_columns()

        for name, callback in (
                ("scan-root", lambda *a: self.start_scan(privileged=True)),
                ("port-scan-root", lambda *a: self.start_port_scan(
                    [self.current], privileged=True)),
                ("wifi-deep", lambda *a: self.start_wifi_deep()),
                ("port-scan-all", lambda *a: self.scan_all_ports()),
                ("port-scan-all-full",
                 lambda *a: self.scan_all_ports(full=True))):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

        action = Gio.SimpleAction.new_stateful(
            "wifi-only-mine", None, GLib.Variant.new_boolean(self.only_mine))
        action.connect("change-state", self._on_only_mine)
        self.add_action(action)

        # Header
        header = Adw.HeaderBar()
        self.scan_btn = Gtk.Button(
            label="Scan", css_classes=["suggested-action"])
        self.scan_btn.connect("clicked", lambda _b: self.start_scan())
        header.pack_start(self.scan_btn)
        header.pack_start(self._build_network_chooser())
        # What to look at: the scanned networks or Wi-Fi.
        scope = Gtk.Box(css_classes=["linked"])
        lan_btn = Gtk.ToggleButton(
            label="LAN", active=True,
            tooltip_text="The devices on the scanned networks")
        self.wifi_btn = Gtk.ToggleButton(
            label="Wi-Fi", group=lan_btn,
            active=store.get_setting("scope") == "wifi",
            tooltip_text="The Wi-Fi networks in range")
        scope.append(lan_btn)
        scope.append(self.wifi_btn)
        header.pack_start(scope)
        self.spinner = Adw.Spinner(visible=False)
        header.pack_start(self.spinner)

        menu = Gio.Menu()
        section = Gio.Menu()
        section.append("Scan as Root", "win.scan-root")
        section.append(
            "Deep Wi-Fi Scan (Root, Shows Clients)", "win.wifi-deep")
        section.append("Show Only My Wi-Fi Networks", "win.wifi-only-mine")
        menu.append_section(None, section)
        section = Gio.Menu()
        section.append("Scan Ports on All Devices", "win.port-scan-all")
        section.append(
            "Scan All 65535 Ports on All Devices (Slow)",
            "win.port-scan-all-full")
        menu.append_section(None, section)
        section = Gio.Menu()
        section.append(f"About {APP_NAME}", "app.about")
        menu.append_section(None, section)
        header.pack_end(Gtk.MenuButton(
            icon_name="open-menu-symbolic", menu_model=menu, primary=True,
            tooltip_text="Main menu"))
        search_btn = Gtk.ToggleButton(
            icon_name="edit-find-symbolic", tooltip_text="Search")
        header.pack_end(search_btn)
        self.pane_btn = Gtk.ToggleButton(
            icon_name="sidebar-show-right-symbolic",
            tooltip_text="Show the details pane",
            active=store.get_setting("details_pane") != "0")
        self.pane_btn.connect("toggled", self._on_pane_toggled)
        header.pack_end(self.pane_btn)
        self.expand_btn = Gtk.ToggleButton(
            icon_name="view-list-bullet-symbolic",
            tooltip_text="Expand all devices")
        self.expand_btn.connect("toggled", self._on_expand_all)
        header.pack_end(self.expand_btn)
        self.map_mode = Gtk.Box(css_classes=["linked"])
        ping_btn = Gtk.ToggleButton(
            label="Ping", active=True,
            tooltip_text="This computer in the middle; "
                         "distance shows ping time")
        topo_btn = Gtk.ToggleButton(
            label="Topology", group=ping_btn,
            active=store.get_setting("map_mode") == "topology",
            tooltip_text="The gateway (or else this computer) in the "
                         "middle; devices spread evenly")
        topo_btn.connect("toggled", self._on_map_mode)
        self.map_mode.append(ping_btn)
        self.map_mode.append(topo_btn)
        self._topology = topo_btn.get_active()
        header.pack_end(self.map_mode)

        search_entry = Gtk.SearchEntry(
            placeholder_text="Search devices", hexpand=True)
        search_entry.connect("search-changed", self._on_search)
        search_bar = Gtk.SearchBar(child=Adw.Clamp(
            child=search_entry, maximum_size=420))
        search_bar.connect_entry(search_entry)
        search_bar.set_key_capture_widget(self)
        search_btn.bind_property(
            "active", search_bar, "search-mode-enabled",
            GObject.BindingFlags.BIDIRECTIONAL
            | GObject.BindingFlags.SYNC_CREATE)

        # Views
        self.view_stack = Gtk.Stack()
        self.view_stack.add_named(
            Gtk.ScrolledWindow(child=self.column_view), "list")
        self.map = MapView(self.filtered, self._on_map_pick)
        self.map.wifi_note = self._wifi_note
        self.map.set_topology(self._topology)
        self.view_stack.add_named(self.map, "map")
        self.wifi_list = WifiList(self.filtered, self.show_details)
        self.view_stack.add_named(self.wifi_list, "wifi-list")
        self.wifi_map = WifiMapView(self.filtered, self._on_map_pick)
        self.wifi_map.set_adapter(self.wifi_iface)
        self.view_stack.add_named(self.wifi_map, "wifi-map")
        # Shown instead of an empty Wi-Fi list or map: what to do.
        self.wifi_help = Adw.StatusPage(
            icon_name="network-wireless-symbolic")
        self.wifi_help_btn = Gtk.Button(
            halign=Gtk.Align.CENTER, css_classes=["pill", "suggested-action"])
        self.wifi_help_btn.connect("clicked", self._on_wifi_help)
        self.wifi_help.set_child(self.wifi_help_btn)
        self.view_stack.add_named(self.wifi_help, "wifi-help")
        # List or map, of whichever of the two is being looked at.
        views = Gtk.Box(css_classes=["linked"])
        list_btn = Gtk.ToggleButton(
            child=Adw.ButtonContent(
                icon_name="view-list-symbolic", label="List"), active=True)
        self.map_btn = Gtk.ToggleButton(
            child=Adw.ButtonContent(
                icon_name="network-workgroup-symbolic", label="Map"),
            group=list_btn, active=store.get_setting("view") == "map")
        views.append(list_btn)
        views.append(self.map_btn)
        header.set_title_widget(views)
        self.wifi_btn.connect("toggled", self._on_view)
        self.map_btn.connect("toggled", self._on_view)

        empty = Adw.StatusPage(
            icon_name="network-workgroup-symbolic", title="No Devices Yet",
            description="Press Scan to look for devices on your network.")
        self.content = Gtk.Stack()
        self.content.add_named(empty, "empty")
        self.content.add_named(self.view_stack, "views")
        self._on_view()

        self.detail = DetailPane(
            on_edit=self._device_edited,
            on_scan_ports=lambda dev: self.start_port_scan([dev]),
            on_forget=self._forget,
            on_close=lambda: self.pane_btn.set_active(False),
            wifi_for=lambda dev: store.wifi_for(dev.mac))
        # A bar along the edge that opens and closes the details pane.
        self.pane_handle = Gtk.Button(css_classes=["flat", "pane-handle"])
        self.pane_handle.set_cursor_from_name("pointer")
        self.pane_handle.connect("clicked", self._on_pane_handle)
        self.content.set_hexpand(True)
        main = Gtk.Box()
        main.append(self.content)
        main.append(self.pane_handle)
        self.split = Adw.OverlaySplitView(
            content=main, sidebar=self.detail,
            sidebar_position=Gtk.PackType.END, show_sidebar=False,
            min_sidebar_width=230, max_sidebar_width=280,
            sidebar_width_fraction=0.24)

        self.status = Gtk.Label(
            xalign=0, css_classes=["dim-label", "caption"], margin_start=12,
            margin_end=12, margin_top=6, margin_bottom=6)
        toolbar = Adw.ToolbarView(content=self.split)
        toolbar.add_top_bar(header)
        toolbar.add_top_bar(search_bar)
        self.banner = Adw.Banner()
        self.banner.connect("button-clicked", self._on_banner)
        toolbar.add_top_bar(self.banner)
        toolbar.add_bottom_bar(self.status)
        self.toasts = Adw.ToastOverlay(child=toolbar)
        self.set_content(self.toasts)

        self.column_view.sort_by_column(
            self._ip_column, Gtk.SortType.ASCENDING)
        self._update_map_networks()
        self._sync_pane()
        self._refresh()
        GLib.timeout_add_seconds(30, self._tick)
        GLib.idle_add(self._startup_scan)

    # ---- choosing networks --------------------------------------------

    def _build_network_chooser(self):
        """Button with a popover listing the networks that can be scanned."""
        saved = self.store.get_setting("targets")
        if saved is None:  # first run, or settings from an older version
            saved = (self.store.get_setting("target")
                     or netinfo.default_target())
        self.selected = {t for t in saved.split(",") if t}
        self.detected = []

        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=6,
            margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        box.append(Gtk.Label(
            label="Networks to scan", xalign=0, css_classes=["heading"]))
        self.net_list = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.append(self.net_list)
        box.append(Gtk.Label(
            label="Other networks", xalign=0, margin_top=6,
            css_classes=["caption", "dim-label"]))
        self.extra = Gtk.Entry(
            placeholder_text="10.0.0.0/24, 192.168.5.0/24", width_chars=28,
            text=self.store.get_setting("extra_targets") or "")
        box.append(self.extra)
        box.append(Gtk.Label(
            label="Wi-Fi adapter", xalign=0, margin_top=6,
            css_classes=["heading"]))
        self.wifi_iface = self.store.get_setting("wifi_iface") or ""
        if self.wifi_iface not in wifi.adapters():
            self.wifi_iface = ""
        self.wifi_list = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.append(self.wifi_list)
        box.append(Gtk.Label(
            xalign=0, wrap=True, max_width_chars=34,
            css_classes=["caption", "dim-label"],
            label="With an adapter chosen, Scan also lists the Wi-Fi "
                  "access points in range (see the Wi-Fi view). "
                  "It can be an adapter you are not connected with.\n"
                  "To also see the devices on each network, run "
                  "Deep Wi-Fi Scan from the main menu: it needs your "
                  "password and takes the adapter offline for "
                  f"{wifi.DEEP_SECONDS} seconds."))

        popover = Gtk.Popover(child=box)
        popover.connect("show", lambda _p: self._rebuild_network_list())
        popover.connect("closed", lambda _p: self._networks_changed())
        self.extra.connect("activate", lambda _e: (
            popover.popdown(), self.start_scan()))
        self.net_button = Gtk.MenuButton(
            popover=popover, tooltip_text="Networks to scan")
        self._rebuild_network_list()
        self._networks_changed()
        return self.net_button

    def _rebuild_network_list(self):
        """List the networks this machine is connected to right now."""
        while (child := self.net_list.get_first_child()) is not None:
            self.net_list.remove(child)
        self.detected = netinfo.networks()
        for net in self.detected:
            cidr = str(net.network)
            too_large = net.network.num_addresses > scanner.MAX_ADDRESSES
            check = Gtk.CheckButton(
                label=f"{net.name}  ·  {cidr}"
                + ("  (too large)" if too_large else ""),
                active=cidr in self.selected and not too_large,
                sensitive=not too_large)
            check.connect("toggled", self._on_network_toggled, cidr)
            self.net_list.append(check)
        if not self.detected:
            self.net_list.append(Gtk.Label(
                label="No networks found", xalign=0,
                css_classes=["dim-label"]))
        while (child := self.wifi_list.get_first_child()) is not None:
            self.wifi_list.remove(child)
        names = wifi.adapters()  # may have changed: USB adapters
        if self.wifi_iface not in names:
            self.wifi_iface = ""
        first = None
        for name in [""] + names:
            label = name or "Off"
            problem = wifi.quick_check(name) if name else None
            if problem:
                label += "  ·  " + {
                    "monitor": "in monitor mode",
                    "radio": "Wi-Fi is off"}.get(problem.fix, "switched off")
            check = Gtk.CheckButton(
                label=label, group=first, active=name == self.wifi_iface,
                tooltip_text=problem.text if problem else None)
            first = first or check
            check.connect("toggled", self._on_wifi_adapter, name)
            self.wifi_list.append(check)
        if not names:
            self.wifi_list.append(Gtk.Label(
                label="No Wi-Fi adapter found", xalign=0,
                css_classes=["dim-label"]))

    def _on_wifi_adapter(self, check, name):
        if not check.get_active():
            return
        self.wifi_iface = name
        self.store.set_setting("wifi_iface", self.wifi_iface)
        if hasattr(self, "wifi_map"):
            self.wifi_map.set_adapter(self.wifi_iface)
            self._show_view()
        self._networks_changed()

    def _on_network_toggled(self, check, cidr):
        if check.get_active():
            self.selected.add(cidr)
        else:
            self.selected.discard(cidr)
        self._networks_changed()

    def _networks_changed(self):
        self.store.set_setting("targets", ",".join(sorted(self.selected)))
        self.store.set_setting("extra_targets", self.extra.get_text())
        try:
            targets = self._targets()
        except scanner.ScanError:
            self.net_button.set_label("Invalid network")
            return
        if len(targets) == 1:
            label = str(targets[0])
        else:
            label = f"{len(targets)} networks" if targets else ""
        if self.wifi_iface:
            label = f"{label} + Wi-Fi" if label else "Wi-Fi"
        self.net_button.set_label(label or "No network")

    def _targets(self):
        """The networks to scan: the ticked ones that are connected, plus
        whatever was typed in. Raises ScanError for bad input."""
        targets = [
            n.network for n in self.detected
            if str(n.network) in self.selected
            and n.network.num_addresses <= scanner.MAX_ADDRESSES]
        for network in scanner.parse_targets(self.extra.get_text()):
            if network not in targets:
                targets.append(network)
        return targets

    def _update_map_networks(self):
        named = [(n.name, n.network) for n in self.detected]
        try:
            extra = scanner.parse_targets(self.extra.get_text())
        except scanner.ScanError:
            extra = []
        known = {network for _name, network in named}
        named += [("", n) for n in extra if n not in known]
        # Most specific first, so a device lands in its smallest network.
        named.sort(key=lambda item: -item[1].prefixlen)
        self._named_networks = named
        self.map.set_networks(named)

    # ---- expandable service rows --------------------------------------

    def _regroup(self):
        """Sort the visible devices into one collapsible group per
        network, keeping existing groups (and what is expanded)."""
        devices = [self.filtered.get_item(i)
                   for i in range(self.filtered.get_n_items())]
        wanted = group_by_network(
            [d for d in devices if not d.wifi], self._named_networks)
        keys = [key for key, _devices in wanted]
        for i in reversed(range(self.groups.get_n_items())):
            if self.groups.get_item(i).key not in keys:
                self.groups.remove(i)
        existing = {g.key: g for g in self.groups}
        for index, (key, members) in enumerate(wanted):
            group = existing.get(key)
            if group is None:
                group = NetworkGroup(key)
                position = min(index, self.groups.get_n_items())
                self.groups.insert(position, group)
                row = self.tree.get_child_row(position)
                if row is not None:
                    row.set_expanded(True)  # networks start out open
            group.sync(members)

    def _child_model(self, item, *_):
        """Children in the tree: a network's devices, a device's
        service lines."""
        if isinstance(item, NetworkGroup):
            return item.devices
        if not isinstance(item, Device):
            return None
        if getattr(item, "service_store", None) is None:
            item.service_store = Gio.ListStore(item_type=ServiceRow)
            item.service_lines_shown = None
            item.connect("changed", self._sync_services)
        self._sync_services(item)
        return item.service_store

    def _sync_services(self, dev):
        rows = dev.service_rows()
        if rows != dev.service_lines_shown:
            dev.service_lines_shown = rows
            dev.service_store.splice(
                0, dev.service_store.get_n_items(),
                [ServiceRow(text, url) for text, url in rows])

    def _on_row_activated(self, view, position):
        """A click on a row. (A click on the arrow itself is handled by
        the arrow and only folds the row out or in.)"""
        row = view.get_model().get_item(position)
        if row is None:
            return
        item = row.get_item()
        if isinstance(item, Device):
            self.show_details(item)
        if row.is_expandable():
            row.set_expanded(not row.get_expanded())

    def _on_expand_all(self, button):
        expand = button.get_active()
        button.set_tooltip_text(
            "Collapse all devices" if expand else "Expand all devices")
        self._expand_all(expand)
        self.wifi_list.expand_all(expand)

    def _expand_all(self, expand):
        for i in range(self.groups.get_n_items()):
            group_row = self.tree.get_child_row(i)
            if group_row is None:
                continue
            if expand:
                group_row.set_expanded(True)
            devices = self.groups.get_item(i).devices
            for j in range(devices.get_n_items()):
                row = group_row.get_child_row(j)  # None while collapsed
                if row is not None:
                    row.set_expanded(expand)

    # ---- list columns -------------------------------------------------

    def _column(self, title, make, update, key=None, expand=False):
        """Add a column. `update(widget, device, other)` fills a cell;
        `other` is None on device rows, a ServiceRow on the rows below
        a device and a NetworkGroup (device None) on network headings."""
        factory = Gtk.SignalListItemFactory()

        def setup(_f, item):
            widget = make()
            widget.bound = None
            widget.device = None
            item.set_child(widget)

        def bind(_f, item):
            widget, row = item.get_child(), item.get_item()
            obj = row.get_item()
            if isinstance(widget, Gtk.TreeExpander):
                widget.set_list_row(row)
            if isinstance(obj, Device):
                widget.device = obj
                update(widget, obj, None)
                widget.bound = (obj, obj.connect(
                    "changed", lambda d: update(widget, d, None)))
            elif isinstance(obj, NetworkGroup):
                widget.device = None
                update(widget, None, obj)
                widget.bound = (obj, obj.connect(
                    "changed", lambda g: update(widget, None, g)))
            else:
                parent = row.get_parent()
                dev = widget.device = parent.get_item() if parent else None
                if dev is None:
                    return
                update(widget, dev, obj)
                widget.bound = (dev, dev.connect(
                    "changed", lambda d: update(widget, d, obj)))

        def unbind(_f, item):
            widget = item.get_child()
            if widget.bound:
                dev, handler = widget.bound
                dev.disconnect(handler)
                widget.bound = None
            if isinstance(widget, Gtk.TreeExpander):
                widget.set_list_row(None)

        factory.connect("setup", setup)
        factory.connect("bind", bind)
        factory.connect("unbind", unbind)
        column = Gtk.ColumnViewColumn(
            title=title, factory=factory, expand=expand, resizable=True)
        if key:
            def compare(a, b, *_):
                # Service rows keep their order; only devices are sorted.
                if not (isinstance(a, Device) and isinstance(b, Device)):
                    return 0
                ka, kb = key(a), key(b)
                return (ka > kb) - (ka < kb)
            column.set_sorter(Gtk.CustomSorter.new(compare))
        self.column_view.append_column(column)
        return column

    def _build_columns(self):
        def label():
            return Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.END)

        def text(getter):
            def update(widget, dev, service):
                widget.set_text("" if service else (getter(dev) or ""))
            return update

        def make_name():
            box = Gtk.Box(spacing=10)
            box.append(Gtk.Image())
            box.append(Gtk.Label(
                xalign=0, ellipsize=Pango.EllipsizeMode.END, hexpand=True))
            box.append(Gtk.Image(
                icon_name="network-wireless-symbolic", pixel_size=14,
                css_classes=["dim-label"]))
            box.append(Gtk.Label(
                label="NEW", css_classes=["caption-heading", "warning"]))
            scan = Gtk.Button(
                label="Scan ports", valign=Gtk.Align.CENTER,
                tooltip_text="Look for open ports on this device")
            box.append(scan)
            browse = Gtk.Button(
                css_classes=["flat", "link", "caption"],
                tooltip_text="Open in browser",
                valign=Gtk.Align.CENTER)
            browse.set_cursor_from_name("pointer")
            box.append(browse)
            expander = Gtk.TreeExpander(child=box)
            expander.url = ""
            browse.connect(
                "clicked", lambda _b: expander.url and Gtk.UriLauncher(
                    uri=expander.url).launch(self, None, None))
            scan.connect(
                "clicked",
                lambda _b: self.start_port_scan([expander.device]))
            return expander

        def update_name(expander, dev, service):
            box = expander.get_child()
            image = box.get_first_child()
            name = image.get_next_sibling()
            on_wifi = name.get_next_sibling()
            badge = on_wifi.get_next_sibling()
            scan = badge.get_next_sibling()
            browse = scan.get_next_sibling()
            expander.url = getattr(service, "url", "")
            browse.set_visible(bool(expander.url))
            browse.set_label(expander.url)
            if isinstance(service, NetworkGroup):
                for hidden in (image, on_wifi, badge, scan):
                    hidden.set_visible(False)
                name.set_hexpand(True)
                name.set_text(service.title)
                name.set_css_classes(["heading"])
                box.set_opacity(1.0)
                return
            is_device = service is None
            image.set_visible(is_device)
            scan.set_visible(not is_device and service.text == NOT_SCANNED)
            scan.set_sensitive(dev.online)
            name.set_hexpand(is_device)
            badge.set_visible(is_device and not dev.known)
            note = self._wifi_note(dev) if is_device else ""
            on_wifi.set_visible(bool(note))
            on_wifi.set_tooltip_text(note or None)
            if is_device:
                image.set_from_icon_name(dev.icon_name)
                image.set_tooltip_text(TYPE_LABELS[dev.type])
                name.set_text(dev.display_name)
                name.set_css_classes([])
                box.set_opacity(1.0 if dev.online else 0.55)
            else:
                name.set_text(service.text)
                name.set_css_classes(["caption", "dim-label"])
                box.set_opacity(1.0)

        def update_status(widget, dev, service):
            if service:
                widget.set_text("")
                return
            widget.set_text(dev.status_text)
            widget.set_css_classes(
                ["success"] if dev.online else ["dim-label"])

        self._column(
            "Name", make_name, update_name,
            key=lambda d: d.display_name.lower(), expand=True)
        self._column(
            "Status", label, update_status, key=lambda d: not d.online)
        self._ip_column = self._column(
            "IP address", label, text(lambda d: d.ip),
            key=lambda d: d.ip_sort_key())
        self._column(
            "Services", label, text(lambda d: d.summary_text),
            key=lambda d: d.summary_text)
        self._column(
            "MAC address", label, text(lambda d: d.mac), key=lambda d: d.mac)
        self._column(
            "Vendor", label, text(lambda d: d.vendor_text),
            key=lambda d: d.vendor_text.lower(), expand=True)
        self._column(
            "Model", label, text(lambda d: d.model),
            key=lambda d: (d.model or "").lower(), expand=True)
        self._column(
            "OS", label, text(lambda d: d.os_text),
            key=lambda d: d.os_text.lower(), expand=True)
        self._column(
            "Last seen", label, text(lambda d: format_time(d.last_seen)),
            key=lambda d: -d.last_seen)

    # ---- helpers ------------------------------------------------------

    def _matches(self, dev, *_):
        if not self.store.wifi_shown(dev, self.only_mine):
            return False
        return not self.search_text or dev.matches(self.search_text)

    def _on_only_mine(self, action, value):
        action.set_state(value)
        self.only_mine = value.get_boolean()
        self.store.set_setting("wifi_only_mine", int(self.only_mine))
        self._refresh()

    def _wifi_note(self, dev):
        """'On Wi-Fi: ...' for a network device a Wi-Fi scan also saw."""
        seen = None if dev.wifi else self.store.wifi_for(dev.mac)
        if seen is None or seen.wifi != "client":
            return ""
        return f"On Wi-Fi: {seen.wifi_text.removeprefix('on ')}"

    def _on_search(self, entry):
        self.search_text = entry.get_text().strip()
        self._refresh()

    def _on_view(self, *_args):
        """Show the list or map of the LAN or of Wi-Fi."""
        wifi_scope, as_map = self.wifi_btn.get_active(), (
            self.map_btn.get_active())
        self.store.set_setting("scope", "wifi" if wifi_scope else "lan")
        self.store.set_setting("view", "map" if as_map else "list")
        self.expand_btn.set_visible(not as_map)
        self.map_mode.set_visible(as_map and not wifi_scope)
        self._show_view()

    def _show_view(self):
        """Put the chosen view on screen, or instructions in its place
        when there is nothing to show yet."""
        wifi_scope, as_map = self.wifi_btn.get_active(), (
            self.map_btn.get_active())
        name = ("wifi-" if wifi_scope else "") + (
            "map" if as_map else "list")
        if wifi_scope and self._update_wifi_help(as_map):
            name = "wifi-help"
        if name == "wifi-list" and (
                self.view_stack.get_visible_child_name() != name):
            self.wifi_list.refresh()  # lay the rows out afresh
        self.view_stack.set_visible_child_name(name)
        self.content.set_visible_child_name(
            "views" if wifi_scope or self.items.get_n_items() else "empty")

    def _update_wifi_help(self, as_map):
        """Fill in the Wi-Fi instructions. Returns False when the Wi-Fi
        list or map has something to show instead."""
        found = [d for d in self.items if d.wifi]
        shown = [d for d in self.filtered if d.wifi]
        if any(d.online for d in shown) if as_map else shown:
            return False
        deep = ("To also see the devices on each network, run Deep "
                "Wi-Fi Scan from the main menu afterwards.")
        button = "Scan"
        if self.scanning:
            title, text, button = "Scanning…", "", ""
        elif found and not shown:
            title = "None of These Networks Are Yours"
            text = (f"{len(found)} Wi-Fi networks and devices are hidden. "
                    "Switch off Show Only My Wi-Fi Networks in the main "
                    "menu to see them all.")
            button = "Show All"
        elif not self.wifi_iface:
            title = "Choose a Wi-Fi Adapter"
            text = ("Wi-Fi scanning is off. Choose an adapter under "
                    "Wi-Fi adapter in the network menu next to Scan, then "
                    "press Scan to list the access points in range.\n\n"
                    + deep)
            button = "Choose Adapter"
        elif found:
            title = "No Wi-Fi Networks in Range"
            text = (f"Press Scan to look again with {self.wifi_iface}. The "
                    "list shows the networks seen before.")
        else:
            title = "No Wi-Fi Scan Yet"
            text = ("Press Scan to list the access points in range of "
                    f"{self.wifi_iface}.\n\n" + deep)
        self.wifi_help.set_title(title)
        self.wifi_help.set_description(text)
        self.wifi_help_btn.set_label(button)
        self.wifi_help_btn.set_visible(bool(button))
        return True

    def _on_wifi_help(self, button):
        label = button.get_label()
        if label == "Choose Adapter":
            self.net_button.popup()
        elif label == "Show All":
            self.lookup_action("wifi-only-mine").change_state(
                GLib.Variant.new_boolean(False))
        else:
            self.start_scan()

    def _on_map_mode(self, button):
        self._topology = button.get_active()
        self.store.set_setting(
            "map_mode", "topology" if self._topology else "ping")
        self.map.set_topology(self._topology)

    def show_details(self, dev):
        if dev is None:
            return
        self.current = dev
        self.detail.set_device(dev)
        self._sync_pane()
        self.map.set_current(dev)
        self.wifi_map.set_current(dev)

    def close_details(self):
        self.current = None
        self.detail.set_device(None)
        self._sync_pane()
        self.map.set_current(None)
        self.wifi_map.set_current(None)

    def _sync_pane(self):
        """The pane shows the picked device, unless it is switched off.
        Opened from the bar on the edge it also shows without one."""
        shown = self.pane_btn.get_active() and (
            self.current is not None or self._show_empty_pane)
        self.split.set_show_sidebar(shown)
        self.pane_handle.set_icon_name(
            "pan-end-symbolic" if shown else "pan-start-symbolic")
        self.pane_handle.set_tooltip_text(
            "Hide the details pane" if shown else "Show the details pane")

    def _on_pane_handle(self, _button):
        shown = self.split.get_show_sidebar()
        self.pane_btn.set_active(not shown)
        self._show_empty_pane = not shown
        self._sync_pane()

    def _on_pane_toggled(self, button):
        self.store.set_setting(
            "details_pane", "1" if button.get_active() else "0")
        # Switched on by hand, it also opens without a device picked.
        self._show_empty_pane = button.get_active()
        self._sync_pane()

    def _on_map_pick(self, dev):
        if dev is None:
            self.close_details()
        else:
            self.show_details(dev)

    def _update_banner(self):
        """Suggest a root scan when it would reveal more."""
        unidentified, without_mac = self.store.root_scan_candidates(
            self._local_networks)
        self._unidentified = unidentified[:16]
        if self.scanning or not (unidentified or without_mac):
            self.banner.set_revealed(False)
            return
        if unidentified:
            n = len(unidentified)
            title = (f"{n} new devices could not be identified" if n > 1
                     else "A new device could not be identified")
            label = "Identify as Root"
        else:
            n = len(without_mac)
            title = (f"{n} devices have no MAC address" if n > 1
                     else "A device has no MAC address")
            label = "Scan as Root"
        self.banner.set_title(title)
        self.banner.set_button_label(label)
        self.banner.set_revealed(True)

    def _on_banner(self, _banner):
        if self._unidentified:
            self.start_port_scan(self._unidentified, privileged=True)
        else:
            self.start_scan(privileged=True)

    def _toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=text, timeout=4))

    def _tick(self):
        # Keep relative times ("5 min ago") current.
        for dev in list(self.items):
            dev.notify_changed()
        self._update_status()
        return True

    def _update_status(self):
        devices = self.store.devices()
        online = sum(d.online for d in devices)
        new = sum(not d.known for d in devices)
        parts = [f"{len(devices)} devices", f"{online} online"]
        if new:
            parts.append(f"{new} new")
        in_range = sum(d.online for d in self.store.wifi_devices())
        if in_range:
            parts.append(f"{in_range} on Wi-Fi")
        if self.scanning:
            parts.append("scanning…")
        elif self.last_scan:
            parts.append(f"last scan {format_time(self.last_scan).lower()}")
        self.status.set_text(" · ".join(parts))

    def _refresh(self):
        """Re-evaluate everything that depends on device data."""
        self.filter.changed(Gtk.FilterChange.DIFFERENT)
        self._regroup()
        sorter = self.column_view.get_sorter()
        if sorter is not None:
            sorter.changed(Gtk.SorterChange.DIFFERENT)
        if self.expand_btn.get_active():
            self._expand_all(True)  # also covers rows that just appeared
            self.wifi_list.expand_all(True)
        self._show_view()
        self.map.refresh()
        self.wifi_list.refresh()
        self.wifi_map.refresh()
        self._update_status()
        self._update_banner()

    def refresh(self):
        self._refresh()

    def _device_edited(self, dev):
        self.store.save(dev)
        dev.notify_changed()
        self._refresh()

    def _forget(self, dev):
        self.close_details()
        found, position = self.items.find(dev)
        if found:
            self.items.remove(position)
        self.store.delete(dev)
        self._refresh()
        self._toast(f"Forgot {dev.display_name}")

    # ---- scanning -----------------------------------------------------

    def _startup_scan(self):
        """Quietly check which of the known devices are up right now."""
        try:
            networks = self._targets()
        except scanner.ScanError:
            return False
        ips = [d.ip for d in self.store.devices()
               if scanner.inside(d.ip, networks)]
        if ips or self.wifi_iface:
            self.start_scan(ips=ips, quiet=True)
        return False

    def start_scan(self, privileged=False, ips=None, quiet=False):
        """Scan the chosen networks, and for Wi-Fi networks if an
        adapter is chosen. A quiet scan only probes the addresses in
        `ips` and does not announce the result."""
        if self.scanning:
            return
        self.detected = netinfo.networks()
        try:
            networks = self._targets()
        except scanner.ScanError as e:
            self._toast(str(e))
            return
        iface = self.wifi_iface
        lan = bool(networks) and (bool(ips) or not quiet)
        if not lan and not iface:
            if not quiet:
                self._toast("Choose a network to scan first")
            return
        self._networks_changed()
        self._set_scanning(True)

        def work():
            hosts, aps, errors = None, None, []
            if lan:
                try:
                    hosts = scanner.discover(networks, privileged, ips)
                except scanner.ScanError as e:
                    errors.append(str(e))
                except Exception as e:  # never leave the UI on a spinner
                    errors.append(f"Scan failed: {e}")
            problem = None
            if iface:
                try:
                    problem = wifi.diagnose(iface)
                    if problem is None:
                        aps = wifi.quick_scan(iface)
                except Exception as e:
                    errors.append(str(e) if isinstance(e, wifi.WifiError)
                                  else f"Wi-Fi scan failed: {e}")
            GLib.idle_add(
                self._scan_done, hosts, networks, aps, errors, quiet,
                problem)

        threading.Thread(target=work, daemon=True).start()

    def _set_scanning(self, scanning):
        self.scanning = scanning
        self.scan_btn.set_sensitive(not scanning)
        self.net_button.set_sensitive(not scanning)
        self.spinner.set_visible(scanning)
        for name in ("scan-root", "wifi-deep"):
            self.lookup_action(name).set_enabled(not scanning)
        self._update_status()
        self._update_banner()
        if hasattr(self, "wifi_help"):
            self._show_view()

    def _scan_failed(self, message):
        self._set_scanning(False)
        self._toast(message)

    def _scan_done(self, hosts, networks, aps, errors, quiet=False,
                   problem=None):
        new = []
        if hosts is not None:
            known = set(self.items)
            # Only networks with link-layer addresses: a root scan
            # cannot find MAC addresses on a VPN such as WireGuard.
            self._local_networks = [
                i.network for i in netinfo.interfaces() if i.mac]
            self._update_map_networks()
            new = self.store.merge_scan(hosts, networks)
            for dev in self.store.devices():
                if dev not in known:
                    self.items.append(dev)
        if aps is not None:
            self._merge_wifi(aps)
        self.last_scan = time.time()
        self._set_scanning(False)
        self._refresh()
        if quiet:
            return
        for error in errors:
            self._toast(error)
        if problem is not None:
            self._wifi_problem(self.wifi_iface, problem)
        parts = []
        if hosts is not None:
            parts.append(f"{len(hosts)} devices online")
            if new:
                parts.append(f"{len(new)} new")
        if aps is not None:
            parts.append(f"{len(aps)} Wi-Fi access points")
        if parts:
            self._toast(", ".join(parts))

    # ---- Wi-Fi ----------------------------------------------------------

    def _merge_wifi(self, aps, clients=None):
        gone = self.store.merge_wifi(aps, clients, scanner.vendors)
        for dev in gone:
            if dev is self.current:
                self.close_details()
            found, position = self.items.find(dev)
            if found:
                self.items.remove(position)
        shown = set(self.items)
        for dev in self.store.wifi_devices():
            if dev not in shown:
                self.items.append(dev)

    def _wifi_problem(self, iface, problem):
        """Explain why the adapter cannot scan, and offer to fix it."""
        body = problem.text
        if problem.fix:
            body += "\n\nLAN Scan can fix this: " + problem.remedy
        else:
            body += ("\n\nYou can pick another adapter, or Off, in the "
                     "network menu next to Scan.")
        dialog = Adw.AlertDialog(heading="Wi-Fi Scan Not Possible", body=body)
        dialog.add_response("close", "Close")
        if problem.fix:
            dialog.add_response("fix", "Fix and Scan")
            dialog.set_response_appearance(
                "fix", Adw.ResponseAppearance.SUGGESTED)
            dialog.connect("response", lambda _d, response: (
                response == "fix" and self._fix_wifi(iface, problem.fix)))
        dialog.present(self)

    def _fix_wifi(self, iface, kind):
        if self.scanning:
            return
        self._set_scanning(True)

        def work():
            try:
                wifi.fix(iface, kind)
                time.sleep(2)  # NetworkManager needs a moment
                problem = wifi.diagnose(iface)
            except Exception as e:
                GLib.idle_add(self._scan_failed, str(e))
                return
            GLib.idle_add(done, problem)

        def done(problem):
            self._set_scanning(False)
            if problem is None:
                self.start_scan()
            else:
                self._toast(f"That did not help: {problem.text}")

        threading.Thread(target=work, daemon=True).start()

    def start_wifi_deep(self):
        """Listen in monitor mode, after asking if that cuts a
        connection."""
        if self.scanning:
            return
        iface = self.wifi_iface
        if not iface:
            self._toast("Choose a Wi-Fi adapter in the network menu first")
            return
        if not any(i.name == iface for i in netinfo.interfaces()):
            self._run_wifi_deep(iface)
            return
        dialog = Adw.AlertDialog(
            heading=f"Disconnect {iface}?",
            body=f"{iface} is connected to a network. The deep scan takes "
                 f"it offline for about {wifi.DEEP_SECONDS} seconds.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("scan", "Scan")
        dialog.set_response_appearance(
            "scan", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", lambda _d, response: (
            response == "scan" and self._run_wifi_deep(iface)))
        dialog.present(self)

    def _run_wifi_deep(self, iface):
        if self.scanning:
            return
        self._set_scanning(True)
        self._toast(
            f"Listening on {iface} for {wifi.DEEP_SECONDS} seconds…")

        def work():
            try:
                aps, clients = wifi.deep_scan(iface)
            except Exception as e:
                GLib.idle_add(self._scan_failed, str(e) if isinstance(
                    e, wifi.WifiError) else f"Wi-Fi scan failed: {e}")
            else:
                GLib.idle_add(self._wifi_deep_done, aps, clients)

        threading.Thread(target=work, daemon=True).start()

    def _wifi_deep_done(self, aps, clients):
        self._merge_wifi(aps, clients)
        self.last_scan = time.time()
        self._set_scanning(False)
        self._refresh()
        self._toast(f"{len(aps)} Wi-Fi access points, "
                    f"{len(clients)} client devices")

    def scan_all_ports(self, full=False):
        """Port scan every online device (without root)."""
        devices = [d for d in self.store.devices()
                   if d.online and not d.scanning]
        if not devices:
            self._toast("No devices are online; run a scan first")
            return
        what = "all 65535 ports" if full else "ports"
        self._toast(f"Scanning {what} on {len(devices)} devices…")
        self.start_port_scan(
            sorted(devices, key=lambda d: d.ip_sort_key()), full=full)

    def start_port_scan(self, devices, privileged=False, full=False):
        devices = [d for d in devices if d is not None and d.online
                   and not d.scanning and not d.wifi]
        if not devices:
            return
        for dev in devices:
            dev.scanning = True
            dev.notify_changed()
        # Without root, scan a few devices at a time so results show up
        # as they come. As root that would mean a password prompt each.
        size = len(devices) if privileged else 8
        chunks = [devices[i:i + size] for i in range(0, len(devices), size)]

        def work():
            for index, chunk in enumerate(chunks):
                try:
                    hosts = scanner.scan_ports(
                        [d.ip for d in chunk], privileged, full)
                except Exception as e:
                    message = str(e) if isinstance(
                        e, scanner.ScanError) else f"Port scan failed: {e}"
                    rest = [d for c in chunks[index:] for d in c]
                    GLib.idle_add(self._port_scan_done, rest, [], message)
                    return
                GLib.idle_add(self._port_scan_done, chunk, hosts, None)
            if len(devices) > 1:
                GLib.idle_add(self._toast, "Port scan finished")

        threading.Thread(target=work, daemon=True).start()

    def _port_scan_done(self, devices, hosts, error):
        by_ip = {h.ip: h for h in hosts}
        for dev in devices:
            dev.scanning = False
            host = by_ip.get(dev.ip)
            if host is not None:
                self.store.apply_port_scan(dev, host)
            else:
                dev.notify_changed()
        if error:
            self._toast(error)
        elif not hosts:
            self._toast("No response to the port scan")
        self._refresh()
