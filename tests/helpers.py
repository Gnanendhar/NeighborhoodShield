"""Shared lookups for tests."""

import csv
from functools import lru_cache

from engine.loader import load_strings
from engine.paths import REFERENCE_DIR


@lru_cache
def questions() -> dict[str, dict]:
    return {q["id"]: q for q in load_strings()["questions"]}


def valid_codes(q: dict) -> set[str] | None:
    """Allowed answer codes, or None for free-text questions."""
    if q["type"] == "text":
        return None
    if q["type"] == "ynd":
        return {"yes", "no", "dont_know"}
    return set(q["options"].keys())


@lru_cache
def ig1_ids() -> set[str]:
    with (REFERENCE_DIR / "cis_v81_ig1_safeguards.csv").open(encoding="utf-8") as fh:
        return {r["safeguard_id"] for r in csv.DictReader(fh)}


@lru_cache
def attack_ids() -> set[str]:
    with (REFERENCE_DIR / "attack_techniques_used.csv").open(encoding="utf-8") as fh:
        return {r["technique_id"] for r in csv.DictReader(fh)}


@lru_cache
def beyond_ig1_ids() -> set[str]:
    with (REFERENCE_DIR / "cis_v81_beyond_ig1_used.csv").open(encoding="utf-8") as fh:
        return {r["safeguard_id"] for r in csv.DictReader(fh)}
