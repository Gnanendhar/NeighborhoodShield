"""Turn the operating-system names owners and export scripts write into endoflife.date release labels.

Owners write "Windows 11 Home 24H2", "Win 10 Pro 22H2", "macOS Sonoma 14.6",
"iOS 18.1"; the export script writes "11 Pro 24H2". The reference snapshot
uses labels such as "11 24H2 (W)", "10 22H2", "14", "18". This module maps the
first set onto the second. Anything it cannot place returns no candidates, and
the engine then makes no claim: an unknown version is never reported as end
of life.
"""

from __future__ import annotations

import re

# os_name as written -> endoflife.date product key.
PRODUCTS = [
    (re.compile(r"windows\s*server|\bwin\s*server"), "windows-server"),
    (re.compile(r"\bwin(dows)?\b"), "windows"),
    (re.compile(r"mac\s*os|\bos\s*x\b|\bmac\b"), "macos"),
    (re.compile(r"ipad\s*os|\bipad\b"), "ipados"),
    (re.compile(r"\bios\b|\biphone\b"), "ios"),
    (re.compile(r"\bandroid\b"), "android"),
    (re.compile(r"\bubuntu\b"), "ubuntu"),
]

MACOS_NAMES = {
    "tahoe": 26, "sequoia": 15, "sonoma": 14, "ventura": 13, "monterey": 12, "big sur": 11,
    "catalina": 10.15, "mojave": 10.14, "high sierra": 10.13, "sierra": 10.12,
}

# Windows client editions: endoflife.date splits Home/Pro ("W") from Enterprise/Education ("E").
_ENTERPRISE = re.compile(r"\b(enterprise|education|edu|ent)\b")
_IOT = re.compile(r"\biot\b")
_LTSC = re.compile(r"\bltsc\b|\bltsb\b")
_FEATURE = re.compile(r"\b(\d{2}h\d|1[5-9]0\d|20\d\d|1511|1607|1703|1709|1803|1809|1903|1909|2004)\b", re.I)


def product_of(os_name: str | None, os_version: str | None = None) -> str | None:
    text = f"{os_name or ''} {os_version or ''}".lower()
    for pat, product in PRODUCTS:
        if pat.search(text):
            return product
    return None


def _windows_client(text: str) -> list[str]:
    m = re.search(r"\b(11|10|8\.1|8|7)\b", text)
    feat = _FEATURE.search(text)
    if not m:
        # "Windows 24H2" style: a feature release only exists for 10 and 11; 2xH2 is 11.
        if feat and re.match(r"2[2-9]h", feat.group(1).lower()):
            major = "11"
        else:
            return []
    else:
        major = m.group(1)
    if major in ("8.1", "8"):
        return [major]
    if major == "7":
        return ["7 SP1"]
    if not feat:
        return []  # "Windows 11" alone: which release is unknown, so no claim
    rel = feat.group(1).upper()
    if _IOT.search(text):
        return [f"{major} {rel} IoT", f"{major} {rel} IOT"]
    if _LTSC.search(text) or _ENTERPRISE.search(text):
        edition = "E"
    else:
        edition = "W"  # Home and Pro: what neighborhood businesses almost always run
    return [f"{major} {rel} ({edition})", f"{major} {rel}"]


def _windows_server(text: str) -> list[str]:
    m = re.search(r"\b(2025|2022|2019|2016|2012|2008|2003|2000)\b(\s*r2)?", text)
    if not m:
        return []
    year, r2 = m.group(1), bool(m.group(2))
    if r2:
        return [f"Windows Server {year} R2", f"Windows Server {year} R2 SP1"]
    return [year, f"Windows Server {year}", f"Windows Server {year} SP2"]


def _macos(text: str) -> list[str]:
    for name, ver in MACOS_NAMES.items():
        if re.search(rf"\b{name}\b", text):
            return [str(ver)]
    m = re.search(r"\b(10\.\d{1,2}|\d{2})(\.\d+)*\b", text)
    return [m.group(1)] if m else []


def _major(text: str) -> list[str]:
    m = re.search(r"\b(\d{1,2})(\.\d+)*\b", text)
    return [m.group(1)] if m else []


def candidate_labels(os_name: str | None, os_version: str | None) -> tuple[str | None, list[str]]:
    """Return (product, release labels to try in order). Empty list = cannot tell."""
    product = product_of(os_name, os_version)
    if product is None or not os_version:
        return product, []
    text = f"{os_name or ''} {os_version}".lower().replace("_", " ")
    if product == "windows":
        return product, _windows_client(text)
    if product == "windows-server":
        return product, _windows_server(text)
    if product == "macos":
        return product, _macos(os_version.lower())
    if product == "android":
        m = re.search(r"\b(\d{1,2})(?:\.(\d))?", os_version)
        if not m:
            return product, []
        major, minor = m.group(1), m.group(2)
        return product, ([f"{major}.{minor}"] if minor else []) + [major, f"{major}.0"]
    if product in ("ios", "ipados"):
        return product, _major(os_version.lower())
    if product == "ubuntu":
        m = re.search(r"\b(\d{2}\.\d{2})\b", text)
        return product, [m.group(1)] if m else []
    return product, []


# ---------------------------------------------------------------- firewall ports
SERVICE_PORTS = {
    "ftp": [21], "ssh": [22], "telnet": [23], "smtp": [25], "dns": [53], "http": [80], "https": [443],
    "smb": [445], "rdp": [3389], "vnc": [5900], "winrm": [5985, 5986],
}
ANY_PORT = {"any", "*", "all"}
_TOKEN = re.compile(r"[a-z]+|\d+\s*-\s*\d+|\d+|\*")


def parse_ports(service: str | None) -> tuple[bool, list[tuple[int, int]], set[str]]:
    """Return (any_port, port ranges, service words) from text like "tcp/3389, 8080-8090, rdp"."""
    if not service:
        return False, [], set()
    text = service.lower()
    ranges: list[tuple[int, int]] = []
    words: set[str] = set()
    for tok in _TOKEN.findall(text):
        if tok in ANY_PORT:
            return True, [], set()
        if tok[0].isdigit():
            lo, _, hi = tok.replace(" ", "").partition("-")
            a, b = int(lo), int(hi or lo)
            ranges.append((min(a, b), max(a, b)))
        else:
            words.add(tok)
            ranges.extend((p, p) for p in SERVICE_PORTS.get(tok, []))
    return False, ranges, words


def port_matches(service: str | None, targets: list) -> bool:
    """True if the rule's ports or service names include any target port number or service word.

    "any"/"*"/"all" opens every port, so it matches. Port numbers must match exactly
    or fall inside a range: 8000 does not match 80, and 1723 does not match 23.
    """
    any_port, ranges, words = parse_ports(service)
    if any_port:
        return True
    for t in targets:
        t = str(t).lower()
        ports = [int(t)] if t.isdigit() else SERVICE_PORTS.get(t, [])
        if any(lo <= p <= hi for p in ports for lo, hi in ranges):
            return True
        if not t.isdigit() and t in words:
            return True
    return False
