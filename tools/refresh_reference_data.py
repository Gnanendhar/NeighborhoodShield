"""Refresh the real-world reference data snapshots in data/reference/.

The app never calls these sites live (privacy, reliability, free hosting).
Instead we snapshot public data into versioned CSVs with a source and date
on every row, and re-run this script on a schedule (monthly is plenty).

Usage:
    python tools/refresh_reference_data.py eol        # endoflife.date lifecycle data
    python tools/refresh_reference_data.py kev        # CISA Known Exploited Vulnerabilities
    python tools/refresh_reference_data.py chicago    # Chicago active business licenses (market sizing)
    python tools/refresh_reference_data.py all

Sources:
  * endoflife.date product files (MIT licensed), read from the project's GitHub
    repository so the same code works where the endoflife.date API is blocked.
  * CISA KEV catalog JSON (public domain, U.S. government work); falls back to
    the official cisagov/kev-data GitHub mirror.
  * City of Chicago Data Portal, Business Licenses - Current Active (dataset
    uupf-x98q), Socrata SODA API, aggregated counts only (no business names).
"""

from __future__ import annotations

import csv
import json
import sys
import urllib.parse
import urllib.request
from datetime import UTC, date, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REF = ROOT / "data" / "reference"
UA = {"User-Agent": "NeighborhoodShield-reference-refresh/0.1"}
TODAY = date.today().isoformat()

# Products a neighborhood business is likely to run. Keys are endoflife.date slugs.
EOL_PRODUCTS = {
    "windows": "Microsoft Windows (client)",
    "windows-server": "Microsoft Windows Server",
    "macos": "Apple macOS",
    "ios": "Apple iOS",
    "ipados": "Apple iPadOS",
    "android": "Google Android",
    "samsung-mobile": "Samsung mobile devices",
    "chrome": "Google Chrome",
    "firefox": "Mozilla Firefox",
    "office": "Microsoft Office",
    "ubuntu": "Ubuntu Linux",
    "fortios": "Fortinet FortiOS (firewalls)",
    "opnsense": "OPNsense (firewall)",
    "veeam-backup-and-replication": "Veeam Backup & Replication",
    "msexchange": "Microsoft Exchange Server",
    "wordpress": "WordPress (websites)",
}

# Vendors/products common in small businesses, used to filter the KEV catalog
# (matched case-insensitively against vendorProject + product).
KEV_SMB_TERMS = [
    "microsoft", "apple", "google chromium", "chrome", "mozilla", "adobe", "fortinet",
    "sonicwall", "zyxel", "tp-link", "netgear", "d-link", "linksys", "tenda", "asus",
    "draytek", "ubiquiti", "watchguard", "cisco small business", "cisco rv", "qnap",
    "synology", "veeam", "connectwise", "screenconnect", "teamviewer", "anydesk",
    "simplehelp", "kaseya", "7-zip", "rarlab", "winrar", "zoom", "quickbooks", "intuit",
    "wordpress", "openvpn", "ivanti", "citrix", "paloalto", "palo alto",
]

CHICAGO_ENDPOINT = "https://data.cityofchicago.org/resource/uupf-x98q.json"


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URLs)
        return resp.read()


def _write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows):>5} rows -> {path.relative_to(ROOT)}")


def _date_or_flag(v) -> str:
    """endoflife.date uses either a date or a boolean for eol/support fields."""
    if v is True:
        return "true"
    if v is False or v is None:
        return ""
    return str(v)


def refresh_eol() -> None:
    rows: list[dict] = []
    for slug, label in EOL_PRODUCTS.items():
        url = f"https://raw.githubusercontent.com/endoflife-date/endoflife.date/master/products/{slug}.md"
        text = _get(url).decode("utf-8")
        front = text.split("---", 2)[1]
        meta = yaml.safe_load(front)
        for rel in meta.get("releases", []):
            rows.append({
                "product": slug,
                "product_label": label,
                "release_cycle": str(rel.get("releaseCycle", "")),
                "release_label": str(rel.get("releaseLabel", rel.get("releaseCycle", ""))).replace("__RELEASE_CYCLE__", str(rel.get("releaseCycle", ""))),
                "release_date": _date_or_flag(rel.get("releaseDate")),
                "active_support_until": _date_or_flag(rel.get("eoas")),
                "eol": _date_or_flag(rel.get("eol")),
                "extended_support_until": _date_or_flag(rel.get("eoes")),
                "latest": str(rel.get("latest", "") or ""),
                "source": url,
                "snapshot_date": TODAY,
            })
    fields = ["product", "product_label", "release_cycle", "release_label", "release_date",
              "active_support_until", "eol", "extended_support_until", "latest", "source", "snapshot_date"]
    _write_csv(REF / "eol_table.csv", rows, fields)


def refresh_kev() -> None:
    urls = [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    ]
    data, used = None, None
    for u in urls:
        try:
            data, used = json.loads(_get(u)), u
            break
        except Exception as exc:  # noqa: BLE001 - try the mirror
            print(f"  could not fetch {u}: {exc}", file=sys.stderr)
    if data is None:
        raise SystemExit("KEV catalog unavailable from all sources")
    rows = []
    for v in data["vulnerabilities"]:
        hay = f"{v['vendorProject']} {v['product']}".lower()
        if any(t in hay for t in KEV_SMB_TERMS):
            rows.append({**v, "cwes": ";".join(v.get("cwes", [])),
                         "catalog_version": data["catalogVersion"], "source": used, "snapshot_date": TODAY})
    fields = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate",
              "knownRansomwareCampaignUse", "requiredAction", "shortDescription", "cwes",
              "catalog_version", "source", "snapshot_date"]
    rows.sort(key=lambda r: r["dateAdded"], reverse=True)
    _write_csv(REF / "kev_smb_snapshot.csv", rows, fields)
    print(f"  KEV catalog {data['catalogVersion']}: {data['count']} total, {len(rows)} SMB-relevant")


def refresh_chicago() -> None:
    """Aggregate counts of active Chicago licenses. No names or addresses are downloaded."""
    where = f"license_status='AAI' AND expiration_date > '{TODAY}'"
    queries = {
        "chicago_license_counts_by_type.csv": {
            "$select": "license_description, count(*) as n", "$where": where,
            "$group": "license_description", "$order": "n DESC", "$limit": "500"},
        "chicago_license_counts_by_area.csv": {
            "$select": "community_area_name, license_description, count(*) as n", "$where": where,
            "$group": "community_area_name, license_description", "$order": "n DESC", "$limit": "50000"},
    }
    for fname, q in queries.items():
        url = CHICAGO_ENDPOINT + "?" + urllib.parse.urlencode(q)
        rows = json.loads(_get(url))
        for r in rows:
            r["source"] = "City of Chicago Data Portal, Business Licenses - Current Active (uupf-x98q)"
            r["snapshot_date"] = TODAY
        fields = [k for k in rows[0].keys()] if rows else ["n"]
        _write_csv(REF / fname, rows, fields)


def main(argv: list[str]) -> None:
    what = argv[1] if len(argv) > 1 else "all"
    jobs = {"eol": refresh_eol, "kev": refresh_kev, "chicago": refresh_chicago}
    targets = jobs.keys() if what == "all" else [what]
    for t in targets:
        print(f"[{datetime.now(UTC):%Y-%m-%d %H:%M}Z] refreshing {t}")
        try:
            jobs[t]()
        except Exception as exc:  # noqa: BLE001 - keep going, report at the end
            print(f"  FAILED {t}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv)
