"""Wi-Fi scanning.

A quick scan asks NetworkManager for the access points in range. A deep
scan puts the adapter in monitor mode (through the root helper in
wifimon.py) and reads frame headers off the air, which also shows the
client devices and the access point each of them talks to.
"""

import os
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass, field

from .netinfo import normalize_mac

DEEP_SECONDS = 30
HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wifimon.py")
BROADCAST = "FF:FF:FF:FF:FF:FF"


class WifiError(Exception):
    pass


@dataclass
class AP:
    bssid: str
    ssid: str = ""  # "" for a hidden network
    freq: int = 0  # MHz
    signal: int = 0  # dBm, 0 = unknown
    security: str = ""


@dataclass
class Client:
    mac: str
    bssid: str = ""  # access point it talks to, "" if none was seen
    signal: int = 0
    probes: list = field(default_factory=list)  # networks it asked for


# ---- channels -----------------------------------------------------------

def band_of(freq):
    if not freq:
        return ""
    if freq < 3000:
        return "2.4 GHz"
    return "5 GHz" if freq < 5945 else "6 GHz"


def channel_of(freq):
    if not freq:
        return 0
    if freq == 2484:
        return 14
    if freq < 3000:
        return (freq - 2407) // 5
    if freq < 5945:
        return (freq - 5000) // 5
    return (freq - 5950) // 5


def freq_of(channel, near):
    """Frequency of `channel` in the band that `near` (MHz) lies in."""
    if near < 3000:
        return 2484 if channel == 14 else 2407 + 5 * channel
    return (5000 if near < 5945 else 5950) + 5 * channel


def signal_fraction(signal):
    """dBm -> distance on the map, 0 (strong) .. 1 (weak or unknown)."""
    if not signal:
        return 1.0
    return min(1.0, max(0.0, (-35 - signal) / 60))


# ---- adapters -----------------------------------------------------------

def adapters(root="/sys/class/net"):
    """Names of the Wi-Fi adapters in this machine."""
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    return [n for n in names
            if os.path.isdir(os.path.join(root, n, "phy80211"))]


# ---- quick scan (NetworkManager) ---------------------------------------

def _split_terse(line):
    """Split a line of `nmcli -t` output: fields are separated by ':',
    with '\\:' and '\\\\' for those characters inside a field."""
    fields, current, escaped = [], [], False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def parse_nmcli(text):
    """Output of `nmcli -t -f BSSID,SSID,FREQ,SIGNAL,SECURITY dev wifi`."""
    aps = {}
    for line in text.splitlines():
        fields = _split_terse(line)
        if len(fields) < 5:
            continue
        bssid = normalize_mac(fields[0])
        if len(bssid) != 17:
            continue
        try:
            freq = int(fields[2].split()[0])
            percent = int(fields[3])
        except (ValueError, IndexError):
            freq, percent = 0, 0
        security = " ".join(fields[4].replace("--", "").split())
        aps[bssid] = AP(
            bssid, clean_ssid(fields[1]), freq,
            # NetworkManager maps -90..-20 dBm onto 30..100 %.
            percent - 120 if percent else 0, security or "Open")
    return list(aps.values())


@dataclass
class Problem:
    """Why an adapter cannot scan, and what would put it right."""
    text: str
    fix: str = ""  # "monitor", "radio", "managed" or "" (no fix known)
    remedy: str = ""  # what the fix does, for the user to agree to


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def quick_check(iface, root="/sys/class/net"):
    """Problems that show without running anything (instant)."""
    base = os.path.join(root, iface)
    if not os.path.isdir(os.path.join(base, "phy80211")):
        return Problem(f"{iface} is not plugged in any more.")
    if _read(os.path.join(base, "type")) == "803":
        return Problem(
            f"{iface} is in monitor mode, probably left there by a deep "
            "scan that was interrupted.", "monitor",
            "Switch it back to normal mode (asks for your password).")
    try:
        switches = [os.path.join(base, "phy80211", n)
                    for n in os.listdir(os.path.join(base, "phy80211"))
                    if n.startswith("rfkill")]
    except OSError:
        switches = []
    if any(_read(os.path.join(s, "hard")) == "1" for s in switches):
        return Problem(
            "Wi-Fi is switched off by a hardware switch or key on this "
            "computer. Switch it on and scan again.")
    if any(_read(os.path.join(s, "soft")) == "1" for s in switches):
        return Problem("Wi-Fi is switched off.", "radio",
                       "Switch Wi-Fi on.")
    return None


def parse_device_state(text, iface):
    """State of `iface` in `nmcli -t -f DEVICE,STATE device status`."""
    for line in text.splitlines():
        fields = _split_terse(line)
        if len(fields) >= 2 and fields[0] == iface:
            return fields[1]
    return ""


def diagnose(iface):
    """-> Problem if the adapter cannot do a quick scan now, or None.
    Runs nmcli, so not for the main thread."""
    problem = quick_check(iface)
    if problem:
        return problem
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return Problem(
            "Wi-Fi scanning needs NetworkManager (the nmcli command), "
            "which is not installed.")
    try:
        proc = subprocess.run(
            [nmcli, "-w", "5", "-t", "-f", "DEVICE,STATE", "device",
             "status"], capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        return Problem("NetworkManager does not answer. Is it running?")
    if proc.returncode != 0:
        return Problem("NetworkManager does not answer. Is it running?")
    state = parse_device_state(proc.stdout, iface)
    if state == "unmanaged" or not state:
        return Problem(
            f"NetworkManager is not managing {iface}, so it cannot scan "
            "with it.", "managed",
            f"Let NetworkManager manage {iface} again.")
    if state == "unavailable":
        return Problem(f"{iface} is not available; Wi-Fi may be switched "
                       "off.", "radio", "Switch Wi-Fi on.")
    return None


def fix(iface, kind):
    """Carry out the fix of a Problem. Raises WifiError."""
    nmcli = shutil.which("nmcli")
    cmds = []
    if kind == "monitor":
        pkexec = shutil.which("pkexec")
        if not pkexec:
            raise WifiError("pkexec is not installed")
        cmds.append([pkexec, sys.executable or "/usr/bin/python3", "-I",
                     HELPER, iface, "restore"])
    if nmcli and kind == "radio":
        cmds.append([nmcli, "-w", "10", "radio", "wifi", "on"])
    if nmcli and kind in ("managed", "monitor"):
        cmds.append([nmcli, "-w", "10", "device", "set", iface,
                     "managed", "yes"])
    for cmd in cmds:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as e:
            raise WifiError(f"Could not fix {iface}: {e}") from None
        if proc.returncode in (126, 127) and cmd[0].endswith("pkexec"):
            raise WifiError("Authentication was cancelled or denied")
        if proc.returncode != 0 and cmd is cmds[0]:
            lines = proc.stderr.strip().splitlines()
            raise WifiError(
                f"Could not fix {iface}: " + (lines[-1] if lines else "?"))


def quick_scan(iface):
    """Access points in range, without root. Gives up after about half
    a minute. Raises WifiError."""
    nmcli = shutil.which("nmcli")
    if not nmcli:
        raise WifiError("Wi-Fi scan needs NetworkManager (nmcli)")
    cmd = [nmcli, "-w", "12", "-t", "-f",
           "BSSID,SSID,FREQ,SIGNAL,SECURITY",
           "device", "wifi", "list", "ifname", iface, "--rescan"]
    error = "no answer"
    # A fresh scan is refused right after another one, and can hang on
    # an adapter in a bad state: then take what NetworkManager has.
    for rescan in ("yes", "no"):
        try:
            proc = subprocess.run(
                cmd + [rescan], capture_output=True, text=True, timeout=16)
        except subprocess.TimeoutExpired:
            error = f"{iface} did not answer in time"
            continue
        except (OSError, subprocess.SubprocessError) as e:
            raise WifiError(f"Wi-Fi scan failed: {e}") from None
        if proc.returncode == 0:
            return parse_nmcli(proc.stdout)
        lines = proc.stderr.strip().splitlines()
        error = lines[-1] if lines else f"exit code {proc.returncode}"
    raise WifiError(f"Wi-Fi scan failed: {error}")


# ---- frames off the air -------------------------------------------------

def clean_ssid(ssid):
    """Network name as text; '' for a hidden network."""
    if isinstance(ssid, bytes):
        ssid = ssid.decode("utf-8", errors="replace")
    ssid = "".join(c if c.isprintable() else " " for c in ssid.strip("\0"))
    return ssid.strip()[:32]


def _mac(data):
    return ":".join(f"{b:02X}" for b in data)


def _unicast(mac):
    return not int(mac[:2], 16) & 1


def parse_radiotap(packet, complete=True):
    """-> (802.11 frame, frequency in MHz, signal in dBm); the frame is
    None for packets to skip. Missing values are 0. `complete` is False
    for a packet whose end was cut off by the capture."""
    if len(packet) < 8 or packet[0] != 0:
        return None, 0, 0
    length, present = struct.unpack_from("<HI", packet, 2)
    if length > len(packet):
        return None, 0, 0
    pos, word = 8, present
    while word & 0x80000000:  # more "present" words follow
        if pos + 4 > length:
            return None, 0, 0
        word = struct.unpack_from("<I", packet, pos)[0]
        pos += 4
    flags = freq = signal = 0
    # Fields come in bit order, each aligned to its own size.
    for bit, size in enumerate((8, 1, 1, 4, 2, 1)):
        if not present & (1 << bit):
            continue
        align = 2 if bit == 3 else size
        pos = (pos + align - 1) // align * align
        if pos + size > length:
            break
        if bit == 1:
            flags = packet[pos]
        elif bit == 3:
            freq = struct.unpack_from("<H", packet, pos)[0]
        elif bit == 5:
            signal = struct.unpack_from("b", packet, pos)[0]
        pos += size
    if flags & 0x40:  # damaged in the air
        return None, 0, 0
    frame = packet[length:]
    if flags & 0x10 and complete:  # checksum at the end
        frame = frame[:-4]
    return frame, freq, signal


def _security(privacy, elements):
    """Security of a network from its beacon."""
    rsn, wpa = elements.get(48), elements.get("wpa")
    if rsn is not None:
        try:
            pos = 6  # version, group cipher
            pos += 2 + 4 * struct.unpack_from("<H", rsn, pos)[0]
            count = struct.unpack_from("<H", rsn, pos)[0]
            suites = {rsn[pos + 5 + 4 * i] for i in range(count)
                      if rsn[pos + 2 + 4 * i:pos + 5 + 4 * i]
                      == b"\x00\x0f\xac"}
        except (struct.error, IndexError):
            suites = set()
        names = []
        if suites & {2, 4, 6}:
            names.append("WPA2")
        if suites & {8, 9, 24, 25}:
            names.append("WPA3")
        if suites & {1, 3, 5, 12, 13}:
            names.append("Enterprise")
        if 18 in suites:
            names.append("OWE")
        return " / ".join(names) or "WPA2"
    if wpa is not None:
        return "WPA"
    return "WEP" if privacy else "Open"


def _elements(body):
    """Information elements of a management frame, by number; the old
    WPA element is stored as 'wpa'."""
    found, pos = {}, 0
    while pos + 2 <= len(body):
        number, size = body[pos], body[pos + 1]
        value = body[pos + 2:pos + 2 + size]
        if len(value) < size:
            break  # cut off by the capture
        if number == 221:
            if value[:4] == b"\x00\x50\xf2\x01":
                found["wpa"] = value
        else:
            found.setdefault(number, value)
        pos += 2 + size
    return found


class Survey:
    """Collects what frames tell about access points and clients."""

    def __init__(self):
        self.frames = 0
        self._aps = {}
        self._clients = {}
        self._pairs = {}  # (receiver, sender) of control frames -> signal

    def _client(self, mac, signal=0, bssid=""):
        client = self._clients.setdefault(mac, Client(mac))
        if signal and (not client.signal or signal > client.signal):
            client.signal = signal
        if bssid:
            client.bssid = bssid
        return client

    def add_packet(self, packet, complete=True):
        frame, freq, signal = parse_radiotap(packet, complete)
        if frame is not None:
            self.add_frame(frame, freq, signal)

    def add_frame(self, frame, freq=0, signal=0):
        if len(frame) < 16:
            return
        self.frames += 1
        kind, subtype = (frame[0] >> 2) & 3, frame[0] >> 4
        addr1, addr2 = _mac(frame[4:10]), _mac(frame[10:16])
        if kind == 1:  # control: who talks to whom is sorted out later
            if subtype in (8, 9, 10, 11) and _unicast(addr2):
                key = (addr1, addr2)
                if signal and signal > self._pairs.get(key, -999):
                    self._pairs[key] = signal
                else:
                    self._pairs.setdefault(key, 0)
            return
        if len(frame) < 24 or not _unicast(addr2):
            return
        addr3 = _mac(frame[16:22])
        if kind == 0:
            if subtype in (5, 8):  # probe response, beacon
                self._beacon(frame, addr3, freq, signal)
            elif subtype == 4:  # probe request
                client = self._client(addr2, signal)
                ssid = clean_ssid(_elements(frame[24:]).get(0, b""))
                if ssid and ssid not in client.probes:
                    client.probes.append(ssid)
            elif addr1 == addr3 and addr2 != addr3 and addr3 != BROADCAST:
                self._client(addr2, signal, addr3)  # (re)association etc.
        elif kind == 2:
            to_ap, from_ap = frame[1] & 1, frame[1] & 2
            if to_ap and not from_ap:
                self._client(addr2, signal, addr1)
            elif from_ap and not to_ap and _unicast(addr1):
                self._client(addr1, 0, addr2)

    def _beacon(self, frame, bssid, freq, signal):
        if len(frame) < 36 or not _unicast(bssid):
            return
        elements = _elements(frame[36:])
        privacy = frame[34] & 0x10
        channel = 0
        if len(elements.get(3, b"")) == 1:
            channel = elements[3][0]
        elif len(elements.get(61, b"")) >= 1:
            channel = elements[61][0]
        if channel and freq:
            freq = freq_of(channel, freq)
        ap = self._aps.setdefault(bssid, AP(bssid))
        ap.ssid = clean_ssid(elements.get(0, b"")) or ap.ssid
        ap.security = _security(privacy, elements)
        if not ap.signal or (signal and signal > ap.signal):
            # The strongest frame is the one heard on its own channel.
            ap.signal = signal or ap.signal
            ap.freq = freq or ap.freq

    def result(self):
        """-> ([AP], [Client])"""
        for (receiver, sender), signal in self._pairs.items():
            if receiver in self._aps and sender not in self._aps:
                self._client(sender, signal, receiver)
            elif (sender in self._aps and receiver not in self._aps
                  and _unicast(receiver)):
                self._client(receiver, 0, sender)
        clients = []
        for client in self._clients.values():
            if client.mac in self._aps:
                continue
            if client.bssid and client.bssid not in self._aps:
                # An access point we never heard directly.
                self._aps[client.bssid] = AP(client.bssid)
            clients.append(client)
        return list(self._aps.values()), clients


class PcapReader:
    """Splits a pcap stream, fed in pieces, into (packet, complete);
    complete is False when the capture kept only its beginning."""

    def __init__(self):
        self._buffer = b""
        self._order = None

    def feed(self, data):
        self._buffer += data
        packets = []
        if self._order is None:
            if len(self._buffer) < 24:
                return packets
            magic = self._buffer[:4]
            if magic == b"\xd4\xc3\xb2\xa1":
                self._order = "<"
            elif magic == b"\xa1\xb2\xc3\xd4":
                self._order = ">"
            else:
                raise WifiError("Unexpected data from the Wi-Fi helper")
            self._buffer = self._buffer[24:]
        pos = 0
        while pos + 16 <= len(self._buffer):
            size, original = struct.unpack_from(
                self._order + "II", self._buffer, pos + 8)
            if size > 65535:
                raise WifiError("Unexpected data from the Wi-Fi helper")
            if pos + 16 + size > len(self._buffer):
                break
            packets.append(
                (self._buffer[pos + 16:pos + 16 + size], size >= original))
            pos += 16 + size
        self._buffer = self._buffer[pos:]
        return packets


def deep_cmd(iface, seconds=DEEP_SECONDS):
    pkexec = shutil.which("pkexec")
    if not pkexec:
        raise WifiError("pkexec is not installed")
    if iface not in adapters():
        raise WifiError(f"{iface} is not a Wi-Fi adapter")
    # -I: the helper runs as root, keep the environment out of it.
    return [pkexec, sys.executable or "/usr/bin/python3", "-I", HELPER,
            iface, str(int(seconds))]


def deep_scan(iface, seconds=DEEP_SECONDS):
    """Listen in monitor mode. -> ([AP], [Client]). Raises WifiError."""
    cmd = deep_cmd(iface, seconds)
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise WifiError(f"Could not start the Wi-Fi scan: {e}") from None
    reader, survey = PcapReader(), Survey()
    try:
        while chunk := proc.stdout.read1(65536):
            for packet, complete in reader.feed(chunk):
                survey.add_packet(packet, complete)
    finally:
        proc.stdout.close()  # makes the helper stop and tidy up
        error = proc.stderr.read().decode(errors="replace").strip()
        code = proc.wait()
    if code in (126, 127):
        raise WifiError("Authentication was cancelled or denied")
    if code != 0:
        detail = error.splitlines()[-1] if error else f"exit code {code}"
        raise WifiError(f"Wi-Fi scan failed: {detail}")
    return survey.result()
