import os
import tempfile
import unittest

import lanscan  # noqa: F401
from lanscan import updates, wifi


class CheckTest(unittest.TestCase):
    def test_quick_check(self):
        with tempfile.TemporaryDirectory() as root:
            switch = os.path.join(root, "wlan0", "phy80211", "rfkill1")
            os.makedirs(switch)

            def put(path, text):
                with open(os.path.join(root, "wlan0", path), "w") as f:
                    f.write(text + "\n")

            put("type", "1")
            put("phy80211/rfkill1/soft", "0")
            put("phy80211/rfkill1/hard", "0")
            self.assertEqual(wifi.adapters(root), ["wlan0"])
            self.assertIsNone(wifi.quick_check("wlan0", root))
            put("phy80211/rfkill1/soft", "1")
            self.assertEqual(wifi.quick_check("wlan0", root).fix, "radio")
            put("phy80211/rfkill1/hard", "1")
            self.assertEqual(wifi.quick_check("wlan0", root).fix, "")
            put("type", "803")
            self.assertEqual(wifi.quick_check("wlan0", root).fix, "monitor")
            self.assertEqual(wifi.quick_check("gone0", root).fix, "")

    def test_adapter_info(self):
        with tempfile.TemporaryDirectory() as root:
            ids = os.path.join(root, "hwdata")
            os.makedirs(ids)
            with open(os.path.join(ids, "usb.ids"), "w") as f:
                f.write("# comment\n2356  Other\n\t0120  Wrong\n"
                        "2357  TP-Link\n\t0109  TL-WN823N\n"
                        "\t0120  Archer T2U PLUS [RTL8821AU]\n"
                        "2358  Next\n\t0120  Also wrong\n")
            with open(os.path.join(ids, "pci.ids"), "w") as f:
                f.write("10ec  Realtek Semiconductor Co., Ltd.\n"
                        "\tc852  RTL8852CE PCIe 802.11ax\n"
                        "\t\t1a3b 5471  Subsystem\n")
            self.assertEqual(
                wifi.lookup_ids(os.path.join(ids, "usb.ids"), "2357", "0120"),
                ("TP-Link", "Archer T2U PLUS [RTL8821AU]"))
            self.assertEqual(
                wifi.lookup_ids(os.path.join(ids, "usb.ids"), "2357", "ffff"),
                ("TP-Link", ""))
            self.assertEqual(
                wifi.lookup_ids(os.path.join(ids, "nope"), "1", "2"),
                ("", ""))

            def put(path, text):
                path = os.path.join(root, path)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(text + "\n")

            def adapter(name, bus, driver, where):
                os.makedirs(os.path.join(root, "bus", bus, "drivers", driver))
                os.makedirs(os.path.join(root, where))
                os.makedirs(os.path.join(root, "net", name))
                os.symlink(os.path.join(root, where),
                           os.path.join(root, "net", name, "device"))
                os.symlink(os.path.join(root, "bus", bus),
                           os.path.join(root, where, "subsystem"))
                os.symlink(os.path.join(root, "bus", bus, "drivers", driver),
                           os.path.join(root, where, "driver"))

            adapter("wlp13s0", "pci", "rtw89_8852ce", "dev/pci0")
            put("dev/pci0/vendor", "0x10ec")
            put("dev/pci0/device", "0xc852")
            put("net/wlp13s0/operstate", "up")
            adapter("wlx0", "usb", "rtw88_8821au", "dev/usb1/1-5/1-5:1.0")
            put("dev/usb1/1-5/idVendor", "2357")
            put("dev/usb1/1-5/idProduct", "0120")
            put("net/wlx0/operstate", "down")
            adapter("wlx1", "usb", "mt76", "dev/usb1/1-6/1-6:1.0")
            put("dev/usb1/1-6/idVendor", "abcd")
            put("dev/usb1/1-6/idProduct", "0001")
            put("dev/usb1/1-6/product", "WLAN Stick")
            put("dev/usb1/1-6/manufacturer", "Acme")
            net = os.path.join(root, "net")
            info = wifi.adapter_info("wlp13s0", net, ids)
            self.assertEqual(info["driver"], "rtw89_8852ce")
            self.assertEqual(
                wifi.adapter_summary(info),
                "Realtek RTL8852CE PCIe 802.11ax · built in · connected")
            self.assertEqual(
                wifi.adapter_summary(wifi.adapter_info("wlx0", net, ids)),
                "TP-Link Archer T2U PLUS [RTL8821AU] · USB")
            self.assertEqual(
                wifi.adapter_summary(wifi.adapter_info("wlx1", net, ids)),
                "Acme WLAN Stick · USB")
            self.assertEqual(
                wifi.adapter_summary(wifi.adapter_info("gone", net, ids)), "")

    def test_updates(self):
        self.assertTrue(updates.is_newer("v0.2.0", "0.1.12"))
        self.assertTrue(updates.is_newer("0.1.10", "0.1.9"))
        self.assertFalse(updates.is_newer("0.1.2", "0.1.2"))
        self.assertFalse(updates.is_newer("0.1.1", "0.1.2"))
        self.assertFalse(updates.is_newer("nightly", "0.1.2"))
        page = "https://github.com/subsite/lanscan/releases/tag/v0.2.0"
        self.assertEqual(updates.parse_release(
            '{"tag_name": "v0.2.0", "html_url": "%s"}' % page),
            ("0.2.0", page))
        # A link to somewhere else is not passed on.
        self.assertEqual(updates.parse_release(
            '{"tag_name": "0.2.0", "html_url": "https://evil.example/x"}'),
            ("0.2.0", "https://github.com/subsite/lanscan/releases"))
        with self.assertRaises(ValueError):
            updates.parse_release('{"tag_name": "latest"}')
        self.assertTrue(updates.API.startswith(
            "https://api.github.com/repos/subsite/lanscan/"))

    def test_device_state(self):
        text = "enp14s0:connected\nwlp13s0:unmanaged\nlo:connected (externally)\n"
        self.assertEqual(wifi.parse_device_state(text, "wlp13s0"), "unmanaged")
        self.assertEqual(wifi.parse_device_state(text, "wlan9"), "")
