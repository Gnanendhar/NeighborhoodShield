"""Real-world reference snapshots: present, dated, sourced, and sane."""

import csv
from datetime import date

import pandas as pd

from engine.paths import REFERENCE_DIR


def _csv(name):
    return pd.read_csv(REFERENCE_DIR / name, dtype=str, keep_default_na=False)


def test_ig1_has_56_safeguards():
    df = _csv("cis_v81_ig1_safeguards.csv")
    assert len(df) == 56 and df.safeguard_id.is_unique
    assert set(df.control_number.astype(int)) == {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 17}


def test_eol_snapshot_known_dates():
    df = _csv("eol_table.csv")
    win = df[df["product"] == "windows"].set_index("release_label")
    assert win.loc["10 22H2", "eol"] == "2025-10-14"   # Microsoft: Windows 10 end of support
    assert (df.source != "").all() and (df.snapshot_date != "").all()


def test_kev_snapshot_is_recent_and_sourced():
    df = _csv("kev_smb_snapshot.csv")
    assert len(df) > 100
    assert df.cveID.str.match(r"^CVE-\d{4}-\d{4,}$").all()
    snap = date.fromisoformat(df.snapshot_date.iloc[0])
    assert (date.today() - snap).days < 400, "KEV snapshot older than ~13 months: re-run tools/refresh_reference_data.py kev"


def test_attack_snapshot():
    with (REFERENCE_DIR / "attack_techniques_used.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["technique_id"] for r in rows} >= {"T1486", "T1133", "T1078", "T1566", "T1490"}


def test_chicago_snapshot_contains_target_segments():
    df = _csv("chicago_license_counts_by_type.csv")
    by = dict(zip(df.license_description, df.n.astype(int), strict=True))
    assert by["Retail Food Establishment"] > 1000
    assert by["Children's Services Facility License"] > 100
