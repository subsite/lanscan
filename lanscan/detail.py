"""Side pane showing and editing a single device."""

from gi.repository import Adw, Gio, Gtk

from .device import (
    TYPE_KEYS, TYPE_LABELS, format_time, short_service, web_url)


def _property_row(title):
    row = Adw.ActionRow(
        title=title, use_markup=False, subtitle_selectable=True,
        css_classes=["property"])
    return row


class DetailPane(Gtk.Box):
    """Callbacks: on_edit(dev), on_scan_ports(dev), on_forget(dev),
    on_close()."""

    def __init__(self, on_edit, on_scan_ports, on_forget, on_close):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.device = None
        self._handler = 0
        self._loading = False
        self._on_edit = on_edit
        self._on_scan_ports = on_scan_ports
        self._on_forget = on_forget
        self._port_rows = []

        header = Adw.HeaderBar(
            show_start_title_buttons=False, show_end_title_buttons=False)
        self._title = Adw.WindowTitle(title="")
        header.set_title_widget(self._title)
        close = Gtk.Button(
            icon_name="window-close-symbolic", tooltip_text="Close")
        close.connect("clicked", lambda _b: on_close())
        header.pack_end(close)
        self.append(header)

        page = Adw.PreferencesPage(vexpand=True)
        self.append(page)

        group = Adw.PreferencesGroup()
        page.add(group)
        self._name = Adw.EntryRow(title="Name", show_apply_button=True)
        self._name.connect("apply", self._name_applied)
        group.add(self._name)
        labels = ["Automatic"] + [TYPE_LABELS[k] for k in TYPE_KEYS[1:]]
        self._type = Adw.ComboRow(
            title="Type", model=Gtk.StringList.new(labels))
        self._type.connect("notify::selected", self._type_selected)
        group.add(self._type)

        group = Adw.PreferencesGroup(title="Network")
        page.add(group)
        self._rows = {}
        for key, title in (
                ("status", "Status"), ("ip", "IP address"),
                ("mac", "MAC address"), ("vendor", "Vendor"),
                ("model", "Model"),
                ("hostname", "Hostname"), ("mdns_name", "mDNS name"),
                ("services", "Announced services"),
                ("first_seen", "First seen"), ("last_seen", "Last seen")):
            self._rows[key] = _property_row(title)
            group.add(self._rows[key])

        self._ports_group = Adw.PreferencesGroup(title="Open ports")
        menu = Gio.Menu()
        menu.append("Scan as Root (Detects OS)", "win.port-scan-root")
        self._scan_btn = Adw.SplitButton(
            label="Scan ports", menu_model=menu, valign=Gtk.Align.CENTER)
        self._scan_btn.connect(
            "clicked", lambda _b: self._on_scan_ports(self.device))
        self._ports_group.set_header_suffix(self._scan_btn)
        page.add(self._ports_group)

        group = Adw.PreferencesGroup()
        page.add(group)
        box = Gtk.Box(spacing=12, homogeneous=True)
        self._known_btn = Gtk.Button(label="Mark as known")
        self._known_btn.connect("clicked", self._mark_known)
        box.append(self._known_btn)
        forget = Gtk.Button(
            label="Forget device", css_classes=["destructive-action"])
        forget.connect("clicked", lambda _b: self._on_forget(self.device))
        box.append(forget)
        group.add(box)

    def set_device(self, device):
        if self.device is not None and self._handler:
            self.device.disconnect(self._handler)
            self._handler = 0
        self.device = device
        if device is not None:
            self._handler = device.connect("changed", lambda _d: self.update())
            self._loading = True
            self._name.set_text(device.custom_name)
            self.update()

    def update(self):
        dev = self.device
        if dev is None:
            return
        self._loading = True
        self._title.set_title(dev.display_name)
        index = TYPE_KEYS.index(dev.device_type) if (
            dev.device_type in TYPE_KEYS) else 0
        self._type.set_selected(index)
        guessed = TYPE_LABELS.get(dev.guessed_type or "unknown", "Unknown")
        self._type.set_subtitle("" if index else f"Detected: {guessed}")

        status = dev.status_text
        if dev.is_self:
            status += " · this computer"
        if dev.is_gateway:
            status += " · gateway"
        if not dev.known:
            status += " · new"
        values = {
            "status": status, "ip": dev.ip, "mac": dev.mac,
            "vendor": dev.vendor_text, "model": dev.model,
            "hostname": dev.hostname,
            "mdns_name": dev.mdns_name,
            "services": ", ".join(
                short_service(s) for s in dev.services or []),
            "first_seen": format_time(dev.first_seen),
            "last_seen": format_time(dev.last_seen),
        }
        for key, row in self._rows.items():
            row.set_subtitle(values[key] or "")
            row.set_visible(bool(values[key]))

        for row in self._port_rows:
            self._ports_group.remove(row)
        self._port_rows = []
        if dev.scanning:
            self._ports_group.set_description("Scanning…")
        elif not dev.ports_scanned_at:
            self._ports_group.set_description("Not scanned yet")
        else:
            when = format_time(dev.ports_scanned_at).lower()
            found = f"{len(dev.ports)} open" if dev.ports else "None found"
            self._ports_group.set_description(f"{found} · scanned {when}")
        if dev.os_text:
            row = _property_row("Operating system")
            row.set_subtitle(dev.os_text)
            self._add_port_row(row)
        for port in dev.ports or []:
            row = Adw.ActionRow(
                title=f"{port['port']}/{port.get('proto', 'tcp')}",
                subtitle=" — ".join(
                    p for p in (port.get("service"), port.get("product"))
                    if p),
                use_markup=False, subtitle_selectable=True)
            url = web_url(dev.ip, port)
            if url:
                link = Gtk.LinkButton(
                    uri=url, label=url, valign=Gtk.Align.CENTER,
                    tooltip_text="Open in browser")
                link.add_css_class("caption")
                row.add_suffix(link)
            self._add_port_row(row)
        self._scan_btn.set_sensitive(dev.online and not dev.scanning)
        self._known_btn.set_visible(not dev.known)
        self._loading = False

    def _add_port_row(self, row):
        self._ports_group.add(row)
        self._port_rows.append(row)

    def _name_applied(self, row):
        if self._loading or self.device is None:
            return
        self.device.custom_name = row.get_text().strip()
        self._on_edit(self.device)

    def _type_selected(self, row, _pspec):
        if self._loading or self.device is None:
            return
        index = row.get_selected()
        self.device.device_type = TYPE_KEYS[index] if index else ""
        self._on_edit(self.device)

    def _mark_known(self, _button):
        self.device.known = True
        self._on_edit(self.device)
