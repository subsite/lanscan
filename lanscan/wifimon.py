"""Root helper for the deep Wi-Fi scan. Run on its own, not imported:

    pkexec python3 -I wifimon.py IFACE SECONDS
    pkexec python3 -I wifimon.py IFACE restore

The second form only puts an adapter back in its normal mode.

Puts the adapter in monitor mode, hops through the channels and writes
the headers of the frames it hears to stdout as a pcap stream, then
gives the adapter back to NetworkManager. Nothing is ever transmitted,
and the stream is parsed by the unprivileged app, not here.
"""

import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

DWELL = 0.25  # seconds per channel
MAX_SECONDS = 300
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# 20 MHz channels: 2.4 GHz 1-13, 5 GHz 36-165, 6 GHz scanning channels.
FREQS = (
    [2407 + 5 * c for c in range(1, 14)]
    + [5000 + 5 * c for c in (
        *range(36, 65, 4), *range(100, 145, 4), *range(149, 166, 4))]
    + [5950 + 5 * c for c in range(5, 230, 16)])
BEACON_BYTES = 768  # enough for the name and security of a network
HEADER_BYTES = 24


def tool(name):
    return shutil.which(name, path=PATH)


def call(*cmd):
    """Run a command, -> (ok, last line of its error output)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    lines = proc.stderr.strip().splitlines()
    return proc.returncode == 0, lines[-1] if lines else ""


def trim(packet):
    """The part of a captured packet worth passing on, or None."""
    if len(packet) < 4:
        return None
    start = int.from_bytes(packet[2:4], "little")  # after radiotap
    if len(packet) < start + 10:
        return None
    kind, subtype = (packet[start] >> 2) & 3, packet[start] >> 4
    if kind == 0 and subtype in (4, 5, 8):  # probes and beacons
        return packet[:start + BEACON_BYTES]
    if kind == 1 and subtype not in (8, 9, 10, 11):
        return None
    if kind == 3:
        return None
    return packet[:start + HEADER_BYTES]


class Monitor:
    def __init__(self, iface):
        self.iface = iface
        self.ip, self.iw, self.nmcli = tool("ip"), tool("iw"), tool("nmcli")
        self.changed = False
        self.unmanaged = False

    def start(self):
        if not self.ip or not self.iw:
            raise RuntimeError("the 'iw' and 'ip' tools are needed")
        if self.nmcli:
            # Was it NetworkManager's to begin with?
            proc = subprocess.run(
                [self.nmcli, "-t", "-f", "GENERAL.STATE", "device", "show",
                 self.iface], capture_output=True, text=True, timeout=15)
            if proc.returncode == 0 and "unmanaged" not in proc.stdout:
                self.unmanaged = call(
                    self.nmcli, "device", "set", self.iface,
                    "managed", "no")[0]
        self.changed = True
        call(self.ip, "link", "set", self.iface, "down")
        ok, error = call(
            self.iw, "dev", self.iface, "set", "type", "monitor")
        if not ok:
            raise RuntimeError(
                f"{self.iface} cannot do monitor mode ({error})")
        ok, error = call(self.ip, "link", "set", self.iface, "up")
        if not ok:
            raise RuntimeError(
                f"could not switch {self.iface} on ({error}); "
                "is Wi-Fi turned off?")

    def stop(self):
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, signal.SIG_IGN)  # finish tidying up
        if self.changed:
            call(self.ip, "link", "set", self.iface, "down")
            call(self.iw, "dev", self.iface, "set", "type", "managed")
            call(self.ip, "link", "set", self.iface, "up")
        if self.unmanaged:
            call(self.nmcli, "device", "set", self.iface, "managed", "yes")

    def tune(self, freq):
        return call(self.iw, "dev", self.iface, "set", "freq", str(freq))[0]


def capture(monitor, seconds, out):
    sock = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((monitor.iface, 0))
    # pcap file header; link type 127 is 802.11 with radiotap.
    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
    freqs, index = list(FREQS), 0
    end = time.monotonic() + seconds
    while freqs and time.monotonic() < end:
        index %= len(freqs)
        if not monitor.tune(freqs[index]):
            del freqs[index]  # not available on this adapter or here
            continue
        index += 1
        hop = min(end, time.monotonic() + DWELL)
        while (left := hop - time.monotonic()) > 0:
            if not select.select([sock], [], [], left)[0]:
                break
            heard = sock.recv(8192)
            packet = trim(heard)
            if packet:
                now = time.time()
                out.write(struct.pack(
                    "<IIII", int(now), int(now % 1 * 1e6),
                    len(packet), len(heard)) + packet)
        out.flush()
    sock.close()
    if not freqs:
        raise RuntimeError("could not tune to any channel")


def main(argv):
    restore = len(argv) == 3 and argv[2] == "restore"
    if len(argv) != 3 or not (restore or argv[2].isdigit()):
        print("usage: wifimon.py IFACE SECONDS|restore", file=sys.stderr)
        return 2
    iface = argv[1]
    seconds = 0 if restore else max(3, min(MAX_SECONDS, int(argv[2])))
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", iface) or not os.path.isdir(
            f"/sys/class/net/{iface}/phy80211"):
        print(f"{iface} is not a Wi-Fi adapter", file=sys.stderr)
        return 2

    def stop(_signal, _frame):
        raise SystemExit(1)

    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, stop)
    monitor = Monitor(iface)
    if restore:
        monitor.changed = True
        monitor.unmanaged = bool(monitor.nmcli)
        monitor.stop()
        return 0
    try:
        monitor.start()
        capture(monitor, seconds, sys.stdout.buffer)
    except BrokenPipeError:
        return 0  # the app stopped listening
    except (RuntimeError, OSError) as e:
        print(str(e), file=sys.stderr)
        return 1
    finally:
        monitor.stop()
    return 0


if __name__ == "__main__":
    code = main(sys.argv)
    try:
        sys.stdout.flush()
    except OSError:
        pass
    os._exit(code)
