"""Asking GitHub whether there is a newer release."""

import json
import urllib.request

from . import WEBSITE

API = WEBSITE.replace(
    "https://github.com/", "https://api.github.com/repos/"
) + "/releases/latest"


def parse_version(text):
    """'v1.2.3' -> (1, 2, 3); () if it is not a version."""
    try:
        return tuple(int(p) for p in text.strip().lstrip("v").split("."))
    except ValueError:
        return ()


def is_newer(latest, current):
    latest, current = parse_version(latest), parse_version(current)
    return bool(latest) and latest > current


def parse_release(data):
    """GitHub's answer -> (version, web page of the release)."""
    release = json.loads(data)
    version = str(release["tag_name"]).lstrip("v")
    if not parse_version(version):
        raise ValueError("unexpected version")
    url = str(release.get("html_url") or "")
    if not url.startswith(WEBSITE + "/"):
        url = WEBSITE + "/releases"
    return version, url


def latest_release(timeout=8):
    """-> (version, url). Raises OSError (also for network trouble and
    when nothing is released yet) or ValueError."""
    request = urllib.request.Request(API, headers={
        "User-Agent": "lanscan", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(1024 * 1024)
    try:
        return parse_release(data)
    except (KeyError, TypeError) as e:
        raise ValueError(f"unexpected answer: {e}") from None
