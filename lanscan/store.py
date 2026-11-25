"""SQLite-backed device history."""

import ipaddress
import json
import os
import sqlite3
import time

from gi.repository import GLib

from .device import BOOL_FIELDS, FIELDS, JSON_FIELDS, Device, guess_type

_COLUMNS = list(FIELDS)
_TABLES = ("devices", "wifi")
WIFI_KEEP = 30 * 86400  # how long an access point out of range is kept


def _number(mac):
    try:
        # Without the "locally administered" bit, which access points
        # often set on the Wi-Fi side of an address.
        return int(mac.replace(":", ""), 16) & ~(0x02 << 40)
    except ValueError:
        return None


def near_mac(mac, others):
    """True if `mac` is (nearly) one of `others`: the radios of an
    access point are numbered right next to its network port."""
    number = _number(mac)
    for other in others:
        value = _number(other)
        if (number is not None and value is not None
                and number >> 24 == value >> 24
                and abs(number - value) <= 16):
            return True
    return False


def default_path():
    override = os.environ.get("LANSCAN_DB")
    if override:
        return override
    folder = os.path.join(GLib.get_user_data_dir(), "lanscan")
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, "lanscan.db")


class Store:
    def __init__(self, path=None):
        self.db = sqlite3.connect(path or default_path())
        self.db.row_factory = sqlite3.Row
        cols = ", ".join(
            f"{c} TEXT UNIQUE" if c == "mac" else c for c in _COLUMNS)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS settings ("
            "key TEXT PRIMARY KEY, value TEXT)")
        # Devices on the networks, and what Wi-Fi scans found.
        self._devices, self._wifi = {}, {}
        for table, loaded in zip(_TABLES, (self._devices, self._wifi)):
            self.db.execute(
                f"CREATE TABLE IF NOT EXISTS {table} ("
                f"id INTEGER PRIMARY KEY, {cols})")
            have = {r["name"] for r in self.db.execute(
                f"PRAGMA table_info({table})")}
            for col in _COLUMNS:
                if col not in have:  # column added in a newer version
                    self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col}")
            for row in self.db.execute(f"SELECT * FROM {table}"):
                dev = Device()
                dev.id = row["id"]
                for col in _COLUMNS:
                    value = row[col]
                    if col in JSON_FIELDS:
                        value = json.loads(value) if value else []
                    elif col in BOOL_FIELDS:
                        value = bool(value)
                    elif value is None:
                        value = FIELDS[col]
                    setattr(dev, col, value)
                loaded[dev.id] = dev
        self.db.commit()

    def devices(self):
        """Devices on the scanned networks."""
        return list(self._devices.values())

    def wifi_devices(self):
        """Access points and clients found by Wi-Fi scans."""
        return list(self._wifi.values())

    def _loaded(self, dev):
        return self._wifi if dev.wifi else self._devices

    def save(self, dev):
        values = []
        for col in _COLUMNS:
            value = getattr(dev, col)
            if col in JSON_FIELDS:
                value = json.dumps(value or [])
            elif col in BOOL_FIELDS:
                value = int(bool(value))
            elif col == "mac":
                value = value or None
            values.append(value)
        with self.db:
            if dev.id is None:
                marks = ", ".join("?" for _ in _COLUMNS)
                cur = self.db.execute(
                    f"INSERT INTO {dev.table} ({', '.join(_COLUMNS)}) "
                    f"VALUES ({marks})", values)
                dev.id = cur.lastrowid
                self._loaded(dev)[dev.id] = dev
            else:
                sets = ", ".join(f"{c} = ?" for c in _COLUMNS)
                self.db.execute(
                    f"UPDATE {dev.table} SET {sets} WHERE id = ?",
                    values + [dev.id])

    def delete(self, dev):
        with self.db:
            self.db.execute(
                f"DELETE FROM {dev.table} WHERE id = ?", (dev.id,))
        self._loaded(dev).pop(dev.id, None)

    def get_setting(self, key, default=None):
        row = self.db.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key, value):
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO settings VALUES (?, ?)",
                (key, str(value)))

    def _find(self, host):
        devices = self._devices.values()
        if host.mac:
            for dev in devices:
                if dev.mac == host.mac:
                    return dev
            # A device first seen without a MAC can be adopted.
            candidates = [
                d for d in devices if d.ip == host.ip and not d.mac]
        else:
            candidates = [d for d in devices if d.ip == host.ip]
        return max(candidates, key=lambda d: d.last_seen, default=None)

    def merge_scan(self, hosts, network=None, now=None):
        """Apply a discovery scan. Returns the devices that are new.

        Devices inside `network` (one network or a list) that were
        not found are marked offline.
        """
        now = now or time.time()
        first_scan = not self._devices
        seen, new = set(), []
        for host in hosts:
            dev = self._find(host)
            if dev is None:
                dev = Device(first_seen=now, known=first_scan)
                new.append(dev)
            dev.mac = host.mac or dev.mac
            dev.ip = host.ip
            dev.hostname = host.hostname or dev.hostname
            dev.mdns_name = host.mdns_name or dev.mdns_name
            dev.vendor = host.vendor or dev.vendor
            dev.services = host.services or dev.services
            dev.friendly_name = host.friendly_name or dev.friendly_name
            dev.model = host.model or dev.model
            dev.upnp_type = host.upnp_type or dev.upnp_type
            dev.upnp_server = host.upnp_server or dev.upnp_server
            dev.ttl = host.ttl or dev.ttl
            dev.is_gateway = host.is_gateway
            dev.is_self = host.is_self
            if host.rtt:  # averaged, a single ping is noisy
                dev.rtt = round(
                    (dev.rtt + host.rtt) / 2 if dev.rtt else host.rtt, 3)
            dev.online = True
            dev.last_seen = now
            dev.guessed_type = guess_type(dev)
            self.save(dev)
            seen.add(dev.id)
        for dev in self._devices.values():
            if dev.id in seen or not dev.online:
                continue
            if network is None or _in_network(dev.ip, network):
                dev.online = False
                self.save(dev)
        self.mark_mine()
        for dev in self._devices.values():
            dev.notify_changed()
        return [] if first_scan else new

    def apply_port_scan(self, dev, host, now=None):
        dev.ports = host.ports
        dev.os = host.os or dev.os
        dev.service_os = host.service_os or dev.service_os
        dev.ttl = host.ttl or dev.ttl
        if host.mac and not any(
                d.mac == host.mac for d in self._devices.values()):
            dev.mac = host.mac
        dev.vendor = host.vendor or dev.vendor
        dev.nmap_type = host.nmap_type or dev.nmap_type
        dev.ports_scanned_at = now or time.time()
        dev.guessed_type = guess_type(dev)
        self.save(dev)
        dev.notify_changed()

    def merge_wifi(self, aps, clients=None, vendors=None, now=None):
        """Apply a Wi-Fi scan. `clients` is None for a scan that cannot
        see clients; otherwise the clients found replace the earlier
        ones. Returns the Wi-Fi devices that are gone for good."""
        now = now or time.time()
        by_mac = {d.mac: d for d in self._wifi.values()}
        seen, gone = set(), []

        def record(kind, mac):
            dev = by_mac.get(mac)
            if dev is None:
                dev = by_mac[mac] = Device(mac=mac, first_seen=now)
            dev.wifi = kind
            if vendors and not dev.vendor:
                dev.vendor = vendors.lookup(mac)
            dev.online = True
            dev.last_seen = now
            seen.add(mac)
            return dev

        for ap in aps:
            dev = record("ap", ap.bssid)
            dev.ssid = ap.ssid or dev.ssid
            dev.freq = ap.freq or dev.freq
            dev.signal = ap.signal or dev.signal
            dev.security = ap.security or dev.security
            dev.bssid, dev.probes = "", []
        for client in clients or []:
            if client.mac in seen:
                continue
            dev = record("client", client.mac)
            dev.bssid = client.bssid
            ap = by_mac.get(client.bssid)
            dev.ssid = ap.ssid if ap else ""
            dev.signal = client.signal
            dev.probes = list(client.probes)
            dev.freq, dev.security = 0, ""
        for dev in list(by_mac.values()):
            if dev.mac in seen:
                dev.guessed_type = guess_type(dev)
                self.save(dev)
            elif dev.id is None:
                continue
            elif not dev.custom_name and (
                    clients is not None if dev.wifi == "client"
                    else now - dev.last_seen > WIFI_KEEP):
                self.delete(dev)
                gone.append(dev)
            elif dev.online and (clients is not None or dev.wifi == "ap"):
                dev.online = False
                self.save(dev)
            dev.notify_changed()
        self.mark_mine()
        return gone

    def mark_mine(self):
        """Work out which Wi-Fi devices belong to the scanned networks.
        A client does if its address is also seen there. An access
        point does if such a client talks to it, if its address is
        next to one seen there, or if it shares its network name with
        one that does. Once found out, an access point stays marked."""
        lan = {d.mac: d for d in self._devices.values() if d.mac}
        wifi = list(self._wifi.values())
        aps = [d for d in wifi if d.wifi == "ap"]
        mine = {d: d.mine for d in aps}
        for dev in wifi:
            if dev.wifi == "client":
                known = lan.get(dev.mac)
                # The same address on a network: borrow its name.
                name = known.display_name if known else ""
                if (dev.mine, dev.friendly_name) != (bool(known), name):
                    dev.mine, dev.friendly_name = bool(known), name
                    self.save(dev)
                    dev.notify_changed()
        served = {d.bssid for d in wifi if d.wifi == "client" and d.mine}
        for ap in aps:
            if ap.mac in served or near_mac(ap.mac, lan):
                mine[ap] = True
        names = {ap.ssid for ap in aps if mine[ap] and ap.ssid}
        for ap in aps:
            if mine[ap] or ap.ssid in names:
                if not ap.mine:
                    ap.mine = True
                    self.save(ap)
                    ap.notify_changed()

    def wifi_shown(self, dev, only_mine):
        """Whether a Wi-Fi device passes the 'only my networks' filter:
        yours, or a client of one of your access points."""
        if not only_mine or not dev.wifi or dev.mine:
            return True
        ap = self.wifi_for(dev.bssid) if dev.wifi == "client" else None
        return bool(ap and ap.mine)

    def wifi_for(self, mac):
        """What the last Wi-Fi scans know about an address, or None."""
        if not mac:
            return None
        return next(
            (d for d in self._wifi.values() if d.mac == mac), None)

    def root_scan_candidates(self, local_networks):
        """Online devices a root scan could tell us more about.

        Returns (unidentified, without_mac): new devices of unknown type
        that were never port scanned, and devices on a directly attached
        network whose MAC address is missing.
        """
        online = [d for d in self._devices.values()
                  if d.online and not d.is_self]
        unidentified = [
            d for d in online
            if not d.known and d.type == "unknown" and not d.ports_scanned_at]
        without_mac = [
            d for d in online
            if not d.mac and any(_in_network(d.ip, n) for n in local_networks)]
        return unidentified, without_mac

    def reidentify(self, vendors=None):
        """Re-run identification on stored devices, e.g. after the
        vendor list was updated. Returns the number of devices changed."""
        changed = 0
        for dev in self.devices() + self.wifi_devices():
            vendor = (vendors.lookup(dev.mac) if vendors and dev.mac
                      else "") or dev.vendor
            before = (dev.vendor, dev.guessed_type)
            dev.vendor = vendor
            dev.guessed_type = guess_type(dev)
            if (dev.vendor, dev.guessed_type) != before:
                self.save(dev)
                dev.notify_changed()
                changed += 1
        return changed

    def mark_all_offline(self):
        for dev in self.devices() + self.wifi_devices():
            if dev.online:
                dev.online = False
                self.save(dev)


def _in_network(ip, networks):
    """`networks` is one network or a list of them."""
    if not isinstance(networks, (list, tuple, set)):
        networks = [networks]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in n for n in networks)
