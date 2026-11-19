"""Operating-system spellings map onto endoflife.date labels; firewall ports match exactly."""

from datetime import date

import pytest

from engine.evaluate import eol_release, is_end_of_life
from engine.normalize import parse_ports, port_matches

AS_OF = date(2026, 11, 19)


@pytest.mark.parametrize("os_name, version, label", [
    ("Windows", "11 24H2", "11 24H2 (W)"),              # what the export script wrote before editions
    ("Windows", "11 Pro 24H2", "11 24H2 (W)"),          # what it writes now
    ("Windows", "Windows 11 Home 24H2", "11 24H2 (W)"),
    ("Windows 11", "Pro 24H2", "11 24H2 (W)"),
    ("Windows", "11 Enterprise 24H2", "11 24H2 (E)"),
    ("Windows", "11 Education 23H2", "11 23H2 (E)"),
    ("Windows", "11 IoT Enterprise 24H2", "11 24H2 IoT"),
    ("Windows", "10 Pro 22H2", "10 22H2"),
    ("Windows", "11 24H2 (W)", "11 24H2 (W)"),          # exact label still works
    ("Windows", "7", "7 SP1"),
    ("Windows", "8.1", "8.1"),
    ("Windows Server", "2012 R2", "Windows Server 2012 R2"),
    ("Windows Server", "2022 Standard", "2022"),
    ("macOS", "Sonoma 14.6", "14"),
    ("macOS", "14.6.1", "14"),
    ("macOS", "Big Sur", "11"),
    ("macOS", "10.15.7", "10.15"),
    ("iOS", "18.1.1", "18"),
    ("iPadOS", "15.8", "15"),
    ("Android", "Android 12", "12"),
    ("Android", "8.1", "8.1"),
])
def test_versions_map_to_snapshot_labels(os_name, version, label):
    hit = eol_release(os_name, version)
    assert hit is not None and hit[1] == label


@pytest.mark.parametrize("os_name, version", [
    ("Windows", "11"),               # which release? unknown, so no claim
    ("Windows", ""),
    ("TP-Link firmware", "v14"),     # not in the snapshot
    ("Linux Mint", "21"),
    (None, "10 22H2"),
])
def test_unknown_versions_are_never_guessed(os_name, version):
    assert eol_release(os_name, version) is None
    assert is_end_of_life(os_name, version, AS_OF) is False


@pytest.mark.parametrize("os_name, version, eol", [
    ("Windows", "11 Home 24H2", True),       # ended 2026-10-13
    ("Windows", "11 Enterprise 24H2", False),  # Enterprise runs to 2027 or later
    ("Windows", "10 Pro 22H2", True),
    ("macOS", "Sonoma 14.6", True),
    ("macOS", "Sequoia 15.1", False),
    ("Android", "12", True),
    ("Android", "14", False),
])
def test_end_of_life_after_normalizing(os_name, version, eol):
    assert is_end_of_life(os_name, version, AS_OF) is eol


@pytest.mark.parametrize("service, any_port, ranges, words", [
    ("3389", False, [(3389, 3389)], set()),
    ("tcp/3389, udp/3389", False, [(3389, 3389), (3389, 3389)], {"tcp", "udp"}),
    ("8080-8090", False, [(8080, 8090)], set()),
    ("RDP", False, [(3389, 3389)], {"rdp"}),
    ("any", True, [], set()),
    ("*", True, [], set()),
    ("", False, [], set()),
])
def test_parse_ports(service, any_port, ranges, words):
    assert parse_ports(service) == (any_port, ranges, words)


@pytest.mark.parametrize("service, targets, hit", [
    ("3389", ["3389"], True),
    ("13389", ["3389"], False),          # text matching used to flag this
    ("8000", ["80"], False),
    ("1723", ["23"], False),
    ("3380-3390", ["3389"], True),
    ("rdp", ["3389"], True),
    ("tcp/3389", ["rdp"], True),
    ("web admin", ["admin"], True),
    ("all", ["445"], True),              # every port open includes file sharing
    ("443", ["445", "smb"], False),
])
def test_port_matching(service, targets, hit):
    assert port_matches(service, targets) is hit
