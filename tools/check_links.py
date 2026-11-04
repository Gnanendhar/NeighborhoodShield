"""Check every URL in rules/sources.yaml and data/reference/*.csv.

Run locally or from the monthly refresh workflow:  python tools/check_links.py
Prints one line per URL and exits 1 if any link is broken (4xx/5xx or unreachable).
"""

from __future__ import annotations

import csv
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
UA = {"User-Agent": "Mozilla/5.0 (NeighborhoodShield link check)"}


def collect() -> dict[str, str]:
    urls: dict[str, str] = {}
    for key, s in yaml.safe_load((ROOT / "rules/sources.yaml").read_text(encoding="utf-8"))["sources"].items():
        urls[s["url"]] = f"sources.yaml:{key}"
    for f in sorted((ROOT / "data/reference").glob("*.csv")):
        with f.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                for col in ("source_url", "url", "source", "web_or_email"):
                    v = (row.get(col) or "").strip()
                    if v.startswith("https://") and "raw.githubusercontent.com" not in v:
                        urls.setdefault(v, f"{f.name}:{col}")
    return urls


def status(url: str) -> str:
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, headers=UA, method=method)
            with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (known https URLs)
                return str(r.status)
        except urllib.error.HTTPError as e:
            if method == "GET":
                return str(e.code)
        except Exception as e:  # noqa: BLE001
            if method == "GET":
                return f"ERR {type(e).__name__}"
    return "ERR"


def main() -> int:
    bad = 0
    for url, where in collect().items():
        s = status(url)
        ok = s.startswith(("2", "3")) or s in ("401", "403", "405")  # some sites block bots but exist
        bad += not ok
        print(f"{'OK ' if ok else 'BAD'} {s:>8}  {url}  ({where})")
    print(f"\n{bad} broken link(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
