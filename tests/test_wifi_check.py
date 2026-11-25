import os
import tempfile
import unittest

import lanscan  # noqa: F401
from lanscan import wifi


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

    def test_device_state(self):
        text = "enp14s0:connected\nwlp13s0:unmanaged\nlo:connected (externally)\n"
        self.assertEqual(wifi.parse_device_state(text, "wlp13s0"), "unmanaged")
        self.assertEqual(wifi.parse_device_state(text, "wlan9"), "")
