import ipaddress
import math
import unittest

import lanscan  # noqa: F401  (sets gi versions)
import struct

from lanscan import netinfo, scanner, wifi, wifimon
from lanscan.wifilist import (
    LOOSE, WifiGroup, group_wifi, row_clients, row_name, sort_rank)
from lanscan.wifimap import orbit_positions, wifi_layout, wifi_networks
from lanscan.device import Device, guess_type
from lanscan.mapview import even_layout, organic_layout, rtt_fraction
from lanscan.scanner import Host
from lanscan.store import Store

DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up" reason="arp-response"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<address addr="aa:bb:cc:00:00:01" addrtype="mac" vendor="Netgear"/>
<hostnames><hostname name="router.lan" type="PTR"/></hostnames></host>
<host><status state="down"/><address addr="192.168.1.2" addrtype="ipv4"/>
</host>
<host><status state="up" reason="localhost-response"/>
<address addr="192.168.1.10" addrtype="ipv4"/><hostnames/></host>
</nmaprun>"""

PORTS_XML = """<nmaprun><host><status state="up"/>
<address addr="192.168.1.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="9.6"/></port>
<port protocol="tcp" portid="23"><state state="closed"/></port>
<port protocol="tcp" portid="631"><state state="open"/></port>
</ports>
<os><osmatch name="Linux 5.X" accuracy="96"/></os>
</host></nmaprun>"""

NET = ipaddress.ip_network("192.168.1.0/24")


class ScannerTest(unittest.TestCase):
    def test_parse_discovery(self):
        hosts = scanner.parse_nmap_xml(DISCOVERY_XML)
        self.assertEqual([h.ip for h in hosts], ["192.168.1.1", "192.168.1.10"])
        self.assertEqual(hosts[0].mac, "AA:BB:CC:00:00:01")
        self.assertEqual(hosts[0].vendor, "Netgear")
        self.assertEqual(hosts[0].hostname, "router.lan")
        self.assertEqual(hosts[1].mac, "")

    def test_parse_ports(self):
        host = scanner.parse_nmap_xml(PORTS_XML)[0]
        self.assertEqual([p["port"] for p in host.ports], [22, 631])
        self.assertEqual(host.ports[0]["product"], "OpenSSH 9.6")
        self.assertEqual(host.os, "Linux 5.X")

    def test_bad_xml(self):
        with self.assertRaises(scanner.ScanError):
            scanner.parse_nmap_xml("not xml")

    def test_parse_target(self):
        self.assertEqual(str(scanner.parse_target(" 192.168.1.7/24 ")),
                         "192.168.1.0/24")
        for bad in ("", "-iL /etc/shadow", "192.168.1.0/24 --script x",
                    "10.0.0.0/8", "fe80::/64", "example.com"):
            with self.assertRaises(scanner.ScanError, msg=bad):
                scanner.parse_target(bad)

    def test_parse_avahi(self):
        text = (
            "+;wlan0;IPv4;Printer;_ipp._tcp;local\n"
            "=;wlan0;IPv4;Printer;_ipp._tcp;local;hp.local;192.168.1.20;"
            "631;\"txt\"\n"
            "=;wlan0;IPv6;Printer;_ipp._tcp;local;hp.local;fe80::1;631;\n"
            "=;wlan0;IPv4;Printer;_scanner._tcp;local;hp.local;"
            "192.168.1.20;80;\n")
        self.assertEqual(scanner.parse_avahi(text), {"192.168.1.20": {
            "name": "hp.local", "services": ["_ipp._tcp", "_scanner._tcp"],
            "friendly": "Printer", "model": ""}})

    def test_parse_avahi_txt(self):
        text = (
            '=;wlan0;IPv4;HP\\032LaserJet\\032\\091Office\\093;_ipp._tcp;'
            'local;hp.local;192.168.1.20;631;"txtvers=1" '
            '"ty=HP LaserJet M110w" "note=a;b"\n'
            '=;wlan0;IPv4;Chromecast-abc;_googlecast._tcp;local;x.local;'
            '192.168.1.21;8009;"md=Chromecast Ultra" "fn=Living Room TV"\n'
            '=;wlan0;IPv4;AABBCC@K\\195\\182k;_raop._tcp;local;y.local;'
            '192.168.1.22;7000;"am=AudioAccessory5,1"\n')
        found = scanner.parse_avahi(text)
        self.assertEqual(found["192.168.1.20"]["friendly"],
                         "HP LaserJet [Office]")
        self.assertEqual(found["192.168.1.20"]["model"], "HP LaserJet M110w")
        self.assertEqual(found["192.168.1.21"]["friendly"], "Living Room TV")
        self.assertEqual(found["192.168.1.21"]["model"], "Chromecast Ultra")
        self.assertEqual(found["192.168.1.22"]["friendly"], "K\u00f6k")

    def test_manuf(self):
        table = netinfo.parse_manuf(
            "# comment\n"
            "00:00:0C\tCisco\tCisco Systems, Inc\n"
            "00:1B:C5:00:00:00/36\tConverge\tConverged Systems\n"
            "00:55:DA:00:00:00/28\tShinko\n"
            "garbage line\n")
        self.assertEqual(table, {
            "00000C": "Cisco Systems, Inc", "001BC5000": "Converged Systems",
            "0055DA0": "Shinko"})

    def test_vendor_db(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            manuf = os.path.join(tmp, "manuf")
            nmap = os.path.join(tmp, "nmap")
            with open(manuf, "w") as f:
                f.write("AA:BB:CC\tNew\tNew Name Inc\n"
                        "AA:BB:CC:D0:00:00/28\tSub\tSub Block\n")
            with open(nmap, "w") as f:
                f.write("AABBCC Old Name\n112233 Only Nmap\n")
            db = netinfo.VendorDb(manuf, nmap)
            self.assertEqual(db.lookup("aa:bb:cc:00:00:01"), "New Name Inc")
            self.assertEqual(db.lookup("AA:BB:CC:D1:00:01"), "Sub Block")
            self.assertEqual(db.lookup("11:22:33:00:00:01"), "Only Nmap")
            self.assertEqual(db.lookup("99:99:99:00:00:01"), "")
            self.assertFalse(db.is_stale())

    def test_upnp(self):
        from lanscan import upnp
        headers = upnp.parse_response(
            b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.9:80/d.xml\r\n"
            b"ST: upnp:rootdevice\r\nServer: Linux UPnP/1.0\r\n\r\n")
        self.assertEqual(headers["location"], "http://192.168.1.9:80/d.xml")
        self.assertEqual(headers["st"], "upnp:rootdevice")
        info = upnp.parse_description(
            '<root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
            "<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1"
            "</deviceType><friendlyName>Living Room</friendlyName>"
            "<manufacturer>Samsung</manufacturer>"
            "<modelName>UE55</modelName></device></root>")
        self.assertEqual(info["name"], "Living Room")
        self.assertEqual(info["model"], "Samsung UE55")
        self.assertEqual(upnp.parse_description("<broken"), {})
        # Never fetch from anywhere but the announcing device.
        self.assertEqual(
            upnp.fetch_description("http://10.0.0.1/d.xml", "192.168.1.9"),
            {})
        self.assertEqual(
            upnp.fetch_description("file:///etc/passwd", "192.168.1.9"), {})

    def test_enrich_identification(self):
        hosts = [Host("192.168.1.9", mac="AA:BB:CC:00:00:09")]
        scanner.add_upnp_hosts(hosts, {"192.168.1.8": {}, "10.0.0.1": {}}, NET)
        self.assertEqual([h.ip for h in hosts], ["192.168.1.9", "192.168.1.8"])
        scanner.enrich(hosts, upnp_info={"192.168.1.9": {
            "name": "Living Room", "model": "Samsung UE55",
            "type": "urn:schemas-upnp-org:device:MediaRenderer:1"}})
        self.assertEqual(hosts[0].friendly_name, "Living Room")
        store = Store(":memory:")
        self.addCleanup(store.db.close)
        store.merge_scan(hosts, NET, now=1)
        dev = next(d for d in store.devices() if d.ip == "192.168.1.9")
        self.assertEqual(dev.display_name, "Living Room")
        self.assertEqual(dev.type, "tv")

    def test_nmap_device_type(self):
        xml = PORTS_XML.replace(
            '<osmatch name="Linux 5.X" accuracy="96"/>',
            '<osmatch name="Linux 5.X" accuracy="96">'
            '<osclass type="storage-misc" vendor="Synology"/></osmatch>')
        self.assertEqual(scanner.parse_nmap_xml(xml)[0].nmap_type,
                         "storage-misc")

    def test_find_gateways(self):
        wg = ipaddress.ip_network("10.8.0.0/24")
        ifaces = [netinfo.Iface("wlan0", "192.168.1.5", NET, ""),
                  netinfo.Iface("wg0", "10.8.0.3", wg, "")]
        hosts = [Host(ip=ip) for ip in (
            "192.168.1.1", "192.168.1.9", "10.8.0.1", "10.8.0.3",
            "10.8.0.5")]
        asked = []

        def probe(ip):
            asked.append(ip)
            return "10.8.0.1" if ip == "10.8.0.5" else ""

        routed = netinfo.parse_route_gateways([
            {"dst": "default", "gateway": "192.168.1.1", "dev": "wlan0"},
            {"dst": "10.8.0.0/24", "dev": "wg0"}])
        self.assertEqual(
            scanner.find_gateways(hosts, ifaces, [NET, wg], routed, probe),
            {"192.168.1.1", "10.8.0.1"})
        self.assertEqual(sorted(asked), ["10.8.0.1", "10.8.0.5"])
        self.assertEqual(scanner.parse_hop(
            "PING 10.8.0.5 (10.8.0.5) 56(84) bytes of data.\n"
            "From 10.8.0.1 icmp_seq=1 Time to live exceeded\n"), "10.8.0.1")
        self.assertEqual(scanner.parse_hop(
            "64 bytes from 10.8.0.5: icmp_seq=1 ttl=64 time=20 ms"), "")
        scanner.enrich(hosts, ifaces, {"192.168.1.1", "10.8.0.1"})
        self.assertEqual([h.ip for h in hosts if h.is_gateway],
                         ["192.168.1.1", "10.8.0.1"])

    def test_enrich(self):
        hosts = scanner.parse_nmap_xml(DISCOVERY_XML)
        iface = netinfo.Iface("eth0", "192.168.1.10", NET,
                              "11:22:33:44:55:66")
        scanner.enrich(hosts, [iface], "192.168.1.1")
        self.assertTrue(hosts[0].is_gateway)
        self.assertTrue(hosts[1].is_self)
        self.assertEqual(hosts[1].mac, "11:22:33:44:55:66")

    def test_neighbour_hosts(self):
        data = [
            {"dst": "192.168.1.30", "lladdr": "aa:aa:aa:aa:aa:30",
             "state": ["REACHABLE"]},
            {"dst": "192.168.1.31", "lladdr": "aa:aa:aa:aa:aa:31",
             "state": ["STALE"]},
            {"dst": "192.168.1.1", "lladdr": "aa:bb:cc:00:00:01",
             "state": ["REACHABLE"]},
            {"dst": "10.9.9.9", "lladdr": "aa:aa:aa:aa:aa:99",
             "state": ["REACHABLE"]},
            {"dst": "192.168.1.32", "state": ["FAILED"]},
        ]
        self.assertEqual(len(netinfo.parse_neighbours(data)), 4)
        fresh = netinfo.parse_neighbours(data, fresh_only=True)
        hosts = scanner.add_neighbour_hosts(
            scanner.parse_nmap_xml(DISCOVERY_XML), fresh, NET)
        self.assertEqual([h.ip for h in hosts],
                         ["192.168.1.1", "192.168.1.10", "192.168.1.30"])
        self.assertEqual(hosts[2].mac, "AA:AA:AA:AA:AA:30")

    def test_discovery_cmd(self):
        self.assertEqual(
            scanner.discovery_cmd(NET, False)[-1], "192.168.1.0/24")
        cmd = scanner.discovery_cmd(NET, False, ["192.168.1.5", "192.168.1.6"])
        self.assertEqual(cmd[-3:], ["-", "192.168.1.5", "192.168.1.6"])
        with self.assertRaises(ValueError):
            scanner.discovery_cmd(NET, False, ["-iL"])

    def test_portscan_cmd(self):
        cmd = scanner.portscan_cmd(["192.168.1.5", "192.168.1.6"], False)
        self.assertEqual(cmd[-2:], ["192.168.1.5", "192.168.1.6"])
        self.assertIn("-sT", cmd)
        self.assertNotIn("-O", cmd)
        self.assertNotIn("-p-", cmd)
        self.assertIn("-p-", scanner.portscan_cmd(["192.168.1.5"], False, True))
        with self.assertRaises(ValueError):
            scanner.portscan_cmd(["--script=x"], False)

    def test_networks(self):
        routes = [
            {"dst": "default", "gateway": "192.168.1.1", "dev": "wlp2s0"},
            {"dst": "192.168.1.0/24", "dev": "wlp2s0"},
            {"dst": "10.8.0.0/24", "dev": "wg0"},
            {"dst": "10.8.0.0/24", "dev": "wg0"},
            {"dst": "172.17.0.0/16", "dev": "docker0"},
            {"dst": "10.9.9.9", "dev": "wg0"},
            {"dst": "169.254.0.0/16", "dev": "wlp2s0"},
            {"dst": "127.0.0.0/8", "dev": "lo"},
            {"dst": "10.1.0.0/24", "dev": "eth0", "type": "blackhole"},
        ]
        extra = netinfo.Iface(
            "virbr0", "192.168.122.1",
            ipaddress.ip_network("192.168.122.0/24"), "")
        nets = netinfo.parse_networks(routes, [extra])
        self.assertEqual(
            [(n.name, str(n.network)) for n in nets],
            [("wlp2s0", "192.168.1.0/24"), ("wg0", "10.8.0.0/24"),
             ("docker0", "172.17.0.0/16"), ("virbr0", "192.168.122.0/24")])

    def test_multiple_networks(self):
        wg = ipaddress.ip_network("10.8.0.0/24")
        self.assertEqual(
            scanner.parse_targets("192.168.1.0/24, 10.8.0.0/24"), [NET, wg])
        self.assertEqual(scanner.parse_targets("  "), [])
        with self.assertRaises(scanner.ScanError):
            scanner.parse_targets("192.168.1.0/24 --script=x")
        cmd = scanner.discovery_cmd([NET, wg], False)
        self.assertEqual(cmd[-2:], ["192.168.1.0/24", "10.8.0.0/24"])
        self.assertTrue(scanner.inside("10.8.0.7", [NET, wg]))
        self.assertFalse(scanner.inside("10.9.0.7", [NET, wg]))
        store = Store(":memory:")
        self.addCleanup(store.db.close)
        store.merge_scan(
            [Host("192.168.1.2", mac="AA"), Host("10.8.0.2"),
             Host("172.17.0.2", mac="CC")], now=1)
        store.merge_scan([Host("10.8.0.3")], [NET, wg], now=2)
        online = sorted(d.ip for d in store.devices() if d.online)
        self.assertEqual(online, ["10.8.0.3", "172.17.0.2"])

    def test_map_groups(self):
        from lanscan.mapview import group_by_network
        wg = ipaddress.ip_network("10.8.0.0/24")
        devices = [Device(ip="192.168.1.2"), Device(ip="10.8.0.2"),
                   Device(ip="8.8.8.8"), Device(ip="192.168.1.3")]
        groups = group_by_network(devices, [("wlan0", NET), ("wg0", wg)])
        self.assertEqual(
            [(label, [d.ip for d in devs]) for label, devs in groups],
            [("wlan0  ·  192.168.1.0/24", ["192.168.1.2", "192.168.1.3"]),
             ("wg0  ·  10.8.0.0/24", ["10.8.0.2"]), ("Other", ["8.8.8.8"])])
        self.assertEqual(group_by_network(devices[:1], []),
                         [("", devices[:1])])

    def test_interfaces(self):
        data = [
            {"ifname": "lo", "flags": ["LOOPBACK"], "addr_info": [
                {"family": "inet", "local": "127.0.0.1", "prefixlen": 8,
                 "scope": "host"}]},
            {"ifname": "wlp2s0", "flags": ["UP"], "operstate": "UP",
             "address": "aa:bb:cc:dd:ee:ff", "addr_info": [
                 {"family": "inet", "local": "10.0.3.17", "prefixlen": 22,
                  "scope": "global"},
                 {"family": "inet6", "local": "fe80::1", "prefixlen": 64,
                  "scope": "link"}]},
        ]
        (iface,) = netinfo.parse_interfaces(data)
        self.assertEqual(str(iface.network), "10.0.0.0/22")
        self.assertEqual(iface.mac, "AA:BB:CC:DD:EE:FF")


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.db.close)

    def test_first_scan_is_all_known(self):
        new = self.store.merge_scan(
            [Host("192.168.1.1", mac="AA"), Host("192.168.1.2")], NET, now=1)
        self.assertEqual(new, [])
        self.assertTrue(all(d.known for d in self.store.devices()))

    def test_new_offline_and_ip_change(self):
        self.store.merge_scan(
            [Host("192.168.1.1", mac="AA"), Host("192.168.1.2", mac="BB")],
            NET, now=1)
        new = self.store.merge_scan(
            [Host("192.168.1.9", mac="AA"), Host("192.168.1.3", mac="CC")],
            NET, now=2)
        by_mac = {d.mac: d for d in self.store.devices()}
        self.assertEqual(len(by_mac), 3)
        self.assertEqual(by_mac["AA"].ip, "192.168.1.9")
        self.assertEqual(by_mac["AA"].first_seen, 1)
        self.assertFalse(by_mac["BB"].online)
        self.assertEqual(new, [by_mac["CC"]])
        self.assertFalse(by_mac["CC"].known)

    def test_other_network_left_alone(self):
        self.store.merge_scan([Host("10.0.0.5", mac="AA")], now=1)
        self.store.merge_scan([Host("192.168.1.2", mac="BB")], NET, now=2)
        by_mac = {d.mac: d for d in self.store.devices()}
        self.assertTrue(by_mac["AA"].online)

    def test_macless_device_adopted(self):
        self.store.merge_scan([Host("192.168.1.2")], NET, now=1)
        self.store.merge_scan([Host("192.168.1.2", mac="BB")], NET, now=2)
        (dev,) = self.store.devices()
        self.assertEqual(dev.mac, "BB")

    def test_root_scan_candidates(self):
        self.store.merge_scan([Host("192.168.1.1", mac="AA")], NET, now=1)
        self.store.merge_scan([
            Host("192.168.1.1", mac="AA"),
            Host("192.168.1.2", mac="BB"),           # new, unknown type
            Host("192.168.1.3", mac="CC", hostname="my-iphone"),
            Host("192.168.1.4"),                     # no MAC, local
            Host("192.168.1.5", is_self=True),
        ], NET, now=2)
        unidentified, without_mac = self.store.root_scan_candidates([NET])
        self.assertEqual(
            sorted(d.ip for d in unidentified), ["192.168.1.2", "192.168.1.4"])
        self.assertEqual([d.ip for d in without_mac], ["192.168.1.4"])
        self.assertEqual(self.store.root_scan_candidates([])[1], [])
        dev = unidentified[0]
        self.store.apply_port_scan(
            dev, Host(dev.ip, mac="DD", vendor="Acme", os="Linux"), now=3)
        self.assertNotIn(dev, self.store.root_scan_candidates([NET])[0])

    def test_migration_and_reidentify(self):
        import os
        import sqlite3
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.db")
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE devices (id INTEGER PRIMARY KEY, "
                       "mac TEXT UNIQUE, ip, vendor, online, known)")
            db.execute("INSERT INTO devices (mac, ip, online, known) "
                       "VALUES ('AA:BB:CC:00:00:01', '192.168.1.7', 1, 1)")
            db.commit()
            db.close()
            store = Store(path)
            self.addCleanup(store.db.close)
            (dev,) = store.devices()
            self.assertEqual((dev.ip, dev.model, dev.ports), (
                "192.168.1.7", "", []))

            class Vendors:
                def lookup(self, mac):
                    return "Espressif Inc."
            self.assertEqual(store.reidentify(Vendors()), 1)
            self.assertEqual((dev.vendor, dev.type), ("Espressif Inc.", "iot"))
            self.assertEqual(store.reidentify(Vendors()), 0)

    def test_persistence(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.db")
            store = Store(path)
            store.merge_scan([Host("192.168.1.2", mac="BB")], NET, now=1)
            dev = store.devices()[0]
            dev.custom_name = "TV"
            store.apply_port_scan(
                dev, Host("192.168.1.2", ports=[{"port": 80}]), now=3)
            store.db.close()
            reopened = Store(path)
            self.addCleanup(reopened.db.close)
            (loaded,) = reopened.devices()
            self.assertEqual(loaded.custom_name, "TV")
            self.assertEqual(loaded.ports, [{"port": 80}])
            self.assertTrue(loaded.online)
            self.assertEqual(loaded.display_name, "TV")


class DeviceTest(unittest.TestCase):
    def test_guess(self):
        self.assertEqual(guess_type(Device(is_gateway=True)), "router")
        self.assertEqual(
            Device(is_gateway=True, guessed_type="router").icon_name,
            "lanscan-globe-symbolic")
        self.assertEqual(
            Device(guessed_type="router").icon_name,
            "network-wireless-symbolic")
        self.assertEqual(
            guess_type(Device(services=["_ipp._tcp"])), "printer")
        self.assertEqual(guess_type(Device(hostname="Annas-iPhone")), "phone")
        self.assertEqual(guess_type(Device(vendor="Espressif Inc.")), "iot")
        self.assertEqual(guess_type(Device(ports=[{"port": 9100}])), "printer")
        self.assertEqual(guess_type(Device()), "")
        self.assertEqual(guess_type(Device(mac="DA:A1:19:00:00:01")), "phone")
        self.assertEqual(guess_type(Device(mac="D8:A1:19:00:00:01")), "")
        self.assertEqual(guess_type(Device(nmap_type="WAP")), "router")
        self.assertEqual(guess_type(Device(model="MacBookPro18,3")), "computer")
        self.assertEqual(
            guess_type(Device(upnp_type="urn:x:device:ZonePlayer:1")),
            "speaker")

    def test_top_services(self):
        def port(number, service=""):
            return {"port": number, "proto": "tcp", "service": service}
        dev = Device(ports=[
            port(8080, "http-proxy"), port(445, "microsoft-ds"),
            port(139, "netbios-ssn"), port(80, "http"), port(22, "ssh"),
            port(3000, "ppp")])
        self.assertEqual(dev.top_services(), "ssh, http, samba")
        self.assertEqual(dev.top_services(9), "ssh, http, samba, ppp")
        self.assertEqual(
            Device(ports=[port(49152, "unknown"), port(7000, "afs3?")])
            .top_services(), "afs3, 49152")
        self.assertEqual(Device().top_services(), "")

    def test_network_group(self):
        from lanscan.device import NetworkGroup
        a, b, c = (Device(ip="1.1.1.1", online=True), Device(ip="1.1.1.2"),
                   Device(ip="1.1.1.3", online=True))
        group = NetworkGroup("wg0")
        group.sync([a, b])
        self.assertEqual(group.title, "wg0   —   1 of 2 online")
        group.sync([b, c])
        self.assertEqual(list(group.devices), [b, c])
        self.assertEqual(NetworkGroup("").title, "Devices   —   0 of 0 online")

    def test_service_lines(self):
        dev = Device(services=["_ipp._tcp"])
        self.assertEqual(dev.service_lines(),
                         ["mDNS   ipp", "Ports not scanned yet"])
        dev.ports = [{"port": 22, "proto": "tcp", "service": "ssh",
                      "product": "OpenSSH 9.6"}]
        dev.ports_scanned_at = 1
        self.assertEqual(dev.service_lines(),
                         ["22/tcp   ssh — OpenSSH 9.6", "mDNS   ipp"])

    def test_web_urls(self):
        dev = Device(ip="10.0.0.5", ports_scanned_at=1, ports=[
            {"port": 22, "proto": "tcp", "service": "ssh"},
            {"port": 80, "proto": "tcp", "service": "http"},
            {"port": 8080, "proto": "tcp", "service": "http-proxy"},
            {"port": 443, "proto": "tcp", "service": "http",
             "tunnel": "ssl"},
            {"port": 9443, "proto": "tcp", "service": "https-alt"}])
        self.assertEqual(
            [url for _text, url in dev.service_rows()],
            ["", "http://10.0.0.5/", "http://10.0.0.5:8080/",
             "https://10.0.0.5/", "https://10.0.0.5:9443/"])

    def test_organic_layout(self):
        items = [(f"aa:bb:{i:02x}", rtt_fraction(rtt)) for i, rtt in
                 enumerate([0.3, 0.4, 1, 2, 2, 3, 5, 8, 20, 40, 0, 0])]
        pts = organic_layout(items, 300, 260)
        self.assertEqual(len(pts), len(items))
        self.assertEqual(pts, organic_layout(items, 300, 260))
        for i, (x1, y1) in enumerate(pts):
            for x2, y2 in pts[i + 1:]:
                self.assertTrue(
                    abs(x1 - x2) > 60 or abs(y1 - y2) > 45, (pts,))
        dist = [math.hypot(x / 300, y / 260) for x, y in pts]
        self.assertLess(dist[0], dist[9])   # 0.3 ms inside 40 ms
        self.assertLess(dist[9], dist[10] + 0.05)  # unmeasured outermost
        self.assertEqual(organic_layout([], 300, 260), [])

    def test_even_layout(self):
        self.assertEqual(even_layout(0, 300, 260), [])
        pts = even_layout(14, 300, 260)
        self.assertEqual(len(pts), 14)
        for i, (x1, y1) in enumerate(pts):
            self.assertTrue(abs(x1) > 60 or abs(y1) > 45)
            for x2, y2 in pts[i + 1:]:
                self.assertTrue(abs(x1 - x2) > 60 or abs(y1 - y2) > 45)

    def test_rtt(self):
        self.assertEqual(rtt_fraction(0), 1.0)
        self.assertLess(rtt_fraction(1), rtt_fraction(10))
        self.assertLess(rtt_fraction(5000), 1.0)
        xml = ('<nmaprun><host><status state="up"/>'
               '<address addr="10.0.0.9" addrtype="ipv4"/>'
               '<times srtt="2260" rttvar="5000" to="100000"/>'
               '</host></nmaprun>')
        self.assertEqual(scanner.parse_nmap_xml(xml)[0].rtt, 2.26)
        self.assertEqual(scanner.parse_ping(
            "64 bytes from 10.0.0.9: icmp_seq=1 ttl=64 time=0.412 ms"),
            (0.412, 64))
        self.assertEqual(scanner.parse_ping("100% packet loss"), (0.0, 0))
        hosts = [scanner.Host(ip="10.0.0.1", rtt=1.0),
                 scanner.Host(ip="10.0.0.2"),
                 scanner.Host(ip="10.0.0.3", is_self=True)]
        scanner.add_ping_times(hosts, ping=lambda ip: (7.0, 128))
        self.assertEqual([h.rtt for h in hosts], [1.0, 7.0, 0.0])
        self.assertEqual([h.ttl for h in hosts], [128, 128, 0])

    def test_ping_sweep(self):
        net = ipaddress.ip_network("10.8.0.0/29")
        self.assertEqual(len(scanner.sweep_targets([net])), 6)
        self.assertEqual(scanner.sweep_targets(
            [ipaddress.ip_network("10.0.0.0/16")]), [])
        self.assertEqual(
            scanner.sweep_targets([net], ["10.8.0.2"]), ["10.8.0.2"])
        hosts = [Host(ip="10.8.0.1")]
        asked = []

        def ping(ip):
            asked.append(ip)
            return (21.0, 63) if ip == "10.8.0.6" else (0.0, 0)

        scanner.add_ping_hosts(hosts, scanner.sweep_targets([net]), ping)
        self.assertNotIn("10.8.0.1", asked)
        self.assertEqual([(h.ip, h.rtt, h.ttl) for h in hosts],
                         [("10.8.0.1", 0.0, 0), ("10.8.0.6", 21.0, 63)])

    def test_os_guess(self):
        from lanscan import osguess
        self.assertEqual(
            osguess.os_from_cpe("cpe:/o:microsoft:windows_10"), "Windows")
        self.assertEqual(
            osguess.os_from_cpe("cpe:/o:linux:linux_kernel"), "Linux")
        self.assertEqual(osguess.os_from_cpe("cpe:/a:openbsd:openssh"), "")
        xml = ('<nmaprun><host><status state="up" reason_ttl="63"/>'
               '<address addr="10.0.0.9" addrtype="ipv4"/><ports>'
               '<port protocol="tcp" portid="22"><state state="open"/>'
               '<service name="ssh" product="OpenSSH" version="8.9p1 '
               'Ubuntu 3" extrainfo="Ubuntu Linux; protocol 2.0" '
               'ostype="Linux"><cpe>cpe:/o:linux:linux_kernel</cpe>'
               '</service></port></ports></host>'
               '<host><status state="up"/>'
               '<address addr="10.0.0.8" addrtype="ipv4"/><ports>'
               '<port protocol="tcp" portid="445"><state state="open"/>'
               '<service name="microsoft-ds" ostype="Windows"/></port>'
               '</ports><hostscript><script id="smb-os-discovery">'
               '<elem key="os">Windows 10 Pro 19045</elem></script>'
               '</hostscript></host></nmaprun>')
        linux, windows = scanner.parse_nmap_xml(xml)
        self.assertEqual((linux.service_os, linux.ttl),
                         ("Linux (Ubuntu)", 63))
        self.assertEqual(windows.service_os, "Windows 10 Pro 19045")

        self.assertEqual(Device(ttl=128).os_text, "Windows (likely)")
        self.assertEqual(Device(ttl=64, hostname="Galaxy-S21").os_text,
                         "Android (likely)")
        self.assertEqual(Device(model="MacBookPro18,1", ttl=64).os_text,
                         "macOS (likely)")
        self.assertEqual(
            Device(upnp_server="Linux/5.10 UPnP/1.0 x/1").os_text,
            "Linux (likely)")
        self.assertEqual(
            Device(service_os="Linux (Ubuntu)", os="Linux 5.4").os_text,
            "Linux 5.4")
        self.assertEqual(Device().os_text, "")

        reply = (b"\x30\x30\x02\x01\x00\x04\x06public\xa2\x23"
                 b"\x02\x04LanS\x02\x01\x00\x02\x01\x00\x30\x15"
                 b"\x30\x13\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
                 b"\x04\x07RouterX")
        self.assertEqual(osguess.parse_snmp(reply), "RouterX")
        self.assertEqual(osguess.parse_snmp(b"\x30\x05junk"), "")
        self.assertEqual(len(osguess.SNMP_GET), osguess.SNMP_GET[1] + 2)


AP1, AP2 = "AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"
STA1, STA2, STA3 = (
    "12:00:00:00:00:01", "12:00:00:00:00:02", "12:00:00:00:00:03")


def _raw(mac):
    return bytes.fromhex(mac.replace(":", ""))


def _radiotap(frame, freq=2437, signal=-50, flags=0):
    """Radiotap header with flags, channel and signal in front."""
    return struct.pack(
        "<BBHIBxHHb", 0, 0, 15, 0b101010, flags, freq, 0, signal) + frame


def _element(number, value):
    return bytes([number, len(value)]) + value


RSN = (b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00\x00\x0f\xac\x04"
       + b"\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x08" + b"\x00\x00")


def _beacon(bssid, ssid, channel, elements=b"", privacy=True):
    return (b"\x80\x00\x00\x00" + b"\xff" * 6 + _raw(bssid) * 2
            + b"\x00\x00" + bytes(10)
            + bytes([0x11 if privacy else 0x01, 0])
            + _element(0, ssid) + _element(3, bytes([channel])) + elements)


def _data(first, second, to_ap):
    return (bytes([0x88, 1 if to_ap else 2, 0, 0]) + _raw(first)
            + _raw(second) + _raw(first if to_ap else second) + b"\0\0")


class WifiTest(unittest.TestCase):
    def test_nmcli(self):
        aps = wifi.parse_nmcli(
            "AA\\:BB\\:CC\\:00\\:00\\:01:Home\\: 5G:5180 MHz:70:WPA2 WPA3\n"
            "aa\\:bb\\:cc\\:00\\:00\\:02::2437 MHz:35:\n"
            "garbage\n")
        self.assertEqual(len(aps), 2)
        self.assertEqual(
            (aps[0].bssid, aps[0].ssid, aps[0].freq, aps[0].signal,
             aps[0].security),
            (AP1, "Home: 5G", 5180, -50, "WPA2 WPA3"))
        self.assertEqual((aps[1].bssid, aps[1].ssid, aps[1].security),
                         (AP2, "", "Open"))

    def test_channels(self):
        self.assertEqual(
            [wifi.channel_of(f) for f in (2412, 2484, 5180, 5955)],
            [1, 14, 36, 1])
        self.assertEqual(
            [wifi.band_of(f) for f in (2437, 5500, 6115, 0)],
            ["2.4 GHz", "5 GHz", "6 GHz", ""])
        self.assertEqual(wifi.freq_of(6, 2412), 2437)
        self.assertEqual(wifi.freq_of(36, 5200), 5180)
        self.assertEqual(wifi.signal_fraction(0), 1.0)
        self.assertLess(
            wifi.signal_fraction(-45), wifi.signal_fraction(-80))
        self.assertIn(2437, wifimon.FREQS)
        self.assertIn(5180, wifimon.FREQS)

    def test_radiotap(self):
        frame, freq, signal = wifi.parse_radiotap(
            _radiotap(b"frame-and-fcs", 5180, -61, flags=0x10))
        self.assertEqual((frame, freq, signal), (b"frame-and", 5180, -61))
        # A packet cut short by the capture has no checksum left.
        frame, _freq, _signal = wifi.parse_radiotap(
            _radiotap(b"frame", flags=0x10), complete=False)
        self.assertEqual(frame, b"frame")
        self.assertIsNone(
            wifi.parse_radiotap(_radiotap(b"frame", flags=0x40))[0])
        self.assertIsNone(wifi.parse_radiotap(b"\0\0\xff\xff")[0])

    def test_survey(self):
        survey = wifi.Survey()
        # Overheard weakly on the next channel, then on its own.
        survey.add_packet(_radiotap(
            _beacon(AP1, b"Home", 6, _element(48, RSN)), 2442, -70))
        survey.add_packet(_radiotap(
            _beacon(AP1, b"Home", 6, _element(48, RSN)), 2437, -48))
        survey.add_packet(_radiotap(
            _beacon(AP2, b"\0\0\0", 36, privacy=False), 5180, -80))
        survey.add_packet(_radiotap(_data(AP1, STA1, to_ap=True), 2437, -55))
        survey.add_packet(_radiotap(_data(STA2, AP1, to_ap=False), 2437))
        # Multicast from the access point is nobody's.
        survey.add_packet(_radiotap(
            _data("01:00:5E:00:00:FB", AP1, to_ap=False)))
        # A probe request, and a request-to-send to an access point.
        survey.add_packet(_radiotap(
            b"\x40\x00\x00\x00" + b"\xff" * 6 + _raw(STA3) + b"\xff" * 6
            + b"\0\0" + _element(0, b"Cafe"), 2437, -66))
        survey.add_packet(_radiotap(
            b"\xb4\x00\x00\x00" + _raw(AP2) + _raw(STA3), 5180, -60))
        survey.add_packet(b"junk")
        aps, clients = survey.result()
        aps = {a.bssid: a for a in aps}
        clients = {c.mac: c for c in clients}
        self.assertEqual(
            (aps[AP1].ssid, aps[AP1].freq, aps[AP1].signal,
             aps[AP1].security),
            ("Home", 2437, -48, "WPA2 / WPA3"))
        self.assertEqual(
            (aps[AP2].ssid, aps[AP2].freq, aps[AP2].security),
            ("", 5180, "Open"))
        self.assertEqual(
            (clients[STA1].bssid, clients[STA1].signal), (AP1, -55))
        self.assertEqual(
            (clients[STA2].bssid, clients[STA2].signal), (AP1, 0))
        self.assertEqual(
            (clients[STA3].bssid, clients[STA3].probes, clients[STA3].signal),
            (AP2, ["Cafe"], -60))
        self.assertEqual(len(clients), 3)

    def test_pcap_and_trim(self):
        beacon = _radiotap(_beacon(AP1, b"Home", 6) + bytes(2000))
        data = _radiotap(_data(AP1, STA1, to_ap=True) + bytes(500))
        ack = _radiotap(b"\xd4\x00\x00\x00" + _raw(AP1))
        self.assertIsNone(wifimon.trim(ack))
        self.assertIsNone(wifimon.trim(b"\0"))
        stream = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
        for packet in (beacon, data):
            kept = wifimon.trim(packet)
            self.assertLess(len(kept), len(packet))
            stream += struct.pack(
                "<IIII", 0, 0, len(kept), len(packet)) + kept
        reader, survey = wifi.PcapReader(), wifi.Survey()
        for i in range(0, len(stream), 7):  # arrives in odd pieces
            for packet, complete in reader.feed(stream[i:i + 7]):
                self.assertFalse(complete)
                survey.add_packet(packet, complete)
        aps, clients = survey.result()
        self.assertEqual([a.ssid for a in aps], ["Home"])
        self.assertEqual([c.mac for c in clients], [STA1])
        with self.assertRaises(wifi.WifiError):
            wifi.PcapReader().feed(b"x" * 24)

    def test_store(self):
        store = Store(":memory:")
        store.merge_scan([Host(ip="192.168.1.7", mac=STA1,
                               hostname="laptop.lan")], NET, now=10)
        store.merge_wifi(
            [wifi.AP(AP1, "Home", 5180, -50, "WPA2")], now=20)
        (ap,) = store.wifi_devices()
        self.assertEqual(
            (ap.display_name, ap.type, ap.online, ap.table, ap.known),
            ("Home", "router", True, "wifi", True))
        self.assertEqual(len(store.devices()), 1)
        gone = store.merge_wifi(
            [wifi.AP(AP1, "", 0, -60)],
            [wifi.Client(STA1, AP1, -55), wifi.Client(STA2, "", -80, ["X"]),
             wifi.Client(AP1)], now=30)
        self.assertEqual(gone, [])
        found = {d.mac: d for d in store.wifi_devices()}
        self.assertEqual(len(found), 3)
        self.assertEqual((ap.ssid, ap.freq, ap.signal), ("Home", 5180, -60))
        # The client is the laptop on the LAN, under the same address.
        self.assertEqual(found[STA1].display_name, "laptop")
        self.assertEqual(found[STA1].wifi_text, "on Home · -55 dBm")
        self.assertEqual(store.wifi_for(STA1), found[STA1])
        self.assertIsNone(store.wifi_for(""))
        self.assertEqual(found[STA2].wifi_text, "not connected · -80 dBm")
        # Which makes it, and the access point it uses, "mine".
        self.assertTrue(found[STA1].mine)
        self.assertTrue(ap.mine)
        self.assertFalse(found[STA2].mine)
        self.assertTrue(store.wifi_shown(found[STA1], True))
        self.assertFalse(store.wifi_shown(found[STA2], True))
        self.assertTrue(store.wifi_shown(found[STA2], False))
        # A scan without client data leaves the clients alone ...
        found[STA2].custom_name = "Visitor"
        store.merge_wifi([], now=40)
        self.assertEqual(len(store.wifi_devices()), 3)
        self.assertFalse(ap.online)
        self.assertTrue(found[STA1].online)
        # ... one with client data replaces them, except named ones.
        gone = store.merge_wifi([], [], now=50)
        self.assertEqual(gone, [found[STA1]])
        self.assertFalse(found[STA2].online)
        # Access points out of range for a month are forgotten.
        gone = store.merge_wifi([], now=20 + 40 * 86400)
        self.assertEqual(gone, [ap])
        self.assertEqual(store.wifi_devices(), [found[STA2]])
        self.assertEqual(len(store.devices()), 1)

    def test_mine(self):
        from lanscan.store import near_mac
        self.assertTrue(near_mac("AA:BB:CC:00:00:03", ["AA:BB:CC:00:00:01"]))
        self.assertTrue(near_mac("AE:BB:CC:00:00:01", ["AC:BB:CC:00:00:00"]))
        self.assertFalse(near_mac("AA:BB:CC:00:01:01", ["AA:BB:CC:00:00:01"]))
        self.assertFalse(near_mac("AA:BB:CD:00:00:01", ["AA:BB:CC:00:00:01"]))
        store = Store(":memory:")
        store.merge_wifi([
            wifi.AP("AA:BB:CC:00:00:02", "Home"),
            wifi.AP("AA:BB:CC:77:00:02", "Home"),  # second mesh node
            wifi.AP("DD:00:00:00:00:01", "Neighbour")],
            [wifi.Client(STA1, "AA:BB:CC:77:00:02")], now=10)
        self.assertFalse(any(d.mine for d in store.wifi_devices()))
        # The router shows up on the LAN, one address below its radio.
        store.merge_scan(
            [Host(ip="192.168.1.1", mac="AA:BB:CC:00:00:01")], NET, now=20)
        mine = {d.mac for d in store.wifi_devices() if d.mine}
        self.assertEqual(mine, {"AA:BB:CC:00:00:02", "AA:BB:CC:77:00:02"})
        shown = {d.mac for d in store.wifi_devices()
                 if store.wifi_shown(d, True)}
        self.assertEqual(shown, mine | {STA1})  # a guest on my network

    def test_list(self):
        def dev(kind, mac, **values):
            return Device(wifi=kind, mac=mac, online=True, **values)

        near = dev("ap", AP1, ssid="Home", signal=-48, freq=5180,
                   security="WPA2", mine=True)
        far = dev("ap", AP2, ssid="Home", signal=-70, freq=2437)
        hidden = dev("ap", "AA:00:00:00:00:09", signal=-80, freq=5500)
        old = Device(wifi="ap", mac="AA:00:00:00:00:0A", ssid="Gone")
        laptop = dev("client", STA1, bssid=AP2, signal=-60,
                     friendly_name="laptop")
        roaming = dev("client", STA2, signal=-75)
        grouped = dict(group_wifi(
            [roaming, laptop, far, hidden, near, old,
             Device(ip="192.168.1.5")]))
        self.assertEqual(
            list(grouped), ["Home", hidden.mac, "Gone", LOOSE])
        self.assertEqual(grouped["Home"], [near, far, laptop])
        self.assertEqual(grouped[LOOSE], [roaming])
        groups = {}
        for key, members in grouped.items():
            groups[key] = WifiGroup(key)
            groups[key].sync(members)
        home = groups["Home"]
        self.assertEqual(
            (home.title, home.signal_text, home.band_text, home.security,
             home.mine, row_clients(home, None)),
            ("Home", "-48 dBm", "2.4 + 5 GHz", "WPA2", True, "1"))
        self.assertEqual(
            [row_clients(near, home), row_clients(far, home)], ["", "1"])
        self.assertEqual(
            [row_name(near), row_name(laptop), row_name(groups[hidden.mac])],
            ["Access point", "laptop", "Hidden network"])
        self.assertEqual(groups[hidden.mac].band_text, "5 GHz ch 100")
        self.assertEqual(groups["Gone"].signal_text, "Out of range")
        self.assertEqual(groups[LOOSE].title, "Not connected to a network")
        order = sorted(groups.values(), key=sort_rank)
        self.assertEqual([g.key for g in order],
                         ["Home", hidden.mac, "Gone", LOOSE])
        self.assertLess(sort_rank(far), sort_rank(laptop))

    def test_map(self):
        def ap(mac, ssid, signal, freq=5180):
            return Device(wifi="ap", mac=mac, ssid=ssid, signal=signal,
                          freq=freq, online=True)

        def client(mac, bssid):
            return Device(wifi="client", mac=mac, bssid=bssid, online=True)

        devices = [
            ap(AP1, "Home", -70, 2437), ap(AP2, "Home", -50),
            ap("AA:00:00:00:00:03", "", -80), ap("AA:00:00:00:00:04", "", -85),
            client(STA1, AP1), client(STA2, AP2), client(STA3, ""),
            Device(wifi="ap", mac="AA:00:00:00:00:05", ssid="Gone"),
            Device(ip="192.168.1.5", online=True)]
        networks, loose = wifi_networks(devices)
        self.assertEqual(len(networks), 3)  # hidden ones stay apart
        home = next(n for n in networks if n["key"] == "Home")
        self.assertEqual(home["ap"].mac, AP2)  # the strongest one
        self.assertEqual([c.mac for c in home["clients"]], [STA1, STA2])
        self.assertEqual([c.mac for c in loose], [STA3])
        placed, dots = wifi_layout(devices, 400, 250)
        near = next(n for n in placed if n["key"] == "Home")
        far = next(n for n in placed if n["key"] == "AA:00:00:00:00:04")
        self.assertLess(math.hypot(near["x"] / 400, near["y"] / 250),
                        math.hypot(far["x"] / 400, far["y"] / 250))
        self.assertEqual(len(dots), 1)
        self.assertEqual([len(orbit_positions(n)) for n in (0, 4, 40)],
                         [0, 4, 15])
        self.assertTrue(all(y < 0 for _x, y in orbit_positions(15)))

    def test_device_texts(self):
        ap = Device(wifi="ap", mac=AP1, freq=5180, signal=-54,
                    security="WPA2", online=True)
        self.assertEqual(ap.display_name, "Hidden network")
        self.assertEqual(ap.summary_text, "5 GHz ch 36 · WPA2 · -54 dBm")
        self.assertEqual(ap.status_text, "In range")
        self.assertEqual(ap.service_lines(), [
            "5 GHz, channel 36", "Security   WPA2", "Signal   -54 dBm"])
        self.assertTrue(ap.matches("wpa2"))
        lan = Device(ip="192.168.1.5")
        self.assertEqual((lan.table, lan.summary_text), ("devices", ""))


if __name__ == "__main__":
    unittest.main()
