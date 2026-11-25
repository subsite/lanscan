"""SQLite-backed device history."""

import ipaddress
import json
import os
import sqlite3
import time

from gi.repository import GLib

from .device import BOOL_FIELDS, FIELDS, JSON_FIELDS, Device, guess_type

_COLUMNS = list(FIELDS)


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
        self.db.executescript(f"""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY, {cols});
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, value TEXT);
        """)
        have = {r["name"] for r in self.db.execute(
            "PRAGMA table_info(devices)")}
        for col in _COLUMNS:
            if col not in have:  # column added in a newer version
                self.db.execute(f"ALTER TABLE devices ADD COLUMN {col}")
        self._devices = {}
        for row in self.db.execute("SELECT * FROM devices"):
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
            self._devices[dev.id] = dev

    def devices(self):
        return list(self._devices.values())

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
                    f"INSERT INTO devices ({', '.join(_COLUMNS)}) "
                    f"VALUES ({marks})", values)
                dev.id = cur.lastrowid
                self._devices[dev.id] = dev
            else:
                sets = ", ".join(f"{c} = ?" for c in _COLUMNS)
                self.db.execute(
                    f"UPDATE devices SET {sets} WHERE id = ?",
                    values + [dev.id])

    def delete(self, dev):
        with self.db:
            self.db.execute("DELETE FROM devices WHERE id = ?", (dev.id,))
        self._devices.pop(dev.id, None)

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
        for dev in self._devices.values():
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
        for dev in self._devices.values():
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
