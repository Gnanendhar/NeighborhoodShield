"""Load a sample business into an Assessment, through the same ingest path as a real upload."""

from __future__ import annotations

import csv
from datetime import date
from pathlib import Path

import yaml

from .evaluate import Assessment
from .ingest import ingest
from .paths import SAMPLE_DIR
from .schemas import LOOKUP_MODELS

BUSINESS_DIR = SAMPLE_DIR / "businesses"


def sample_businesses() -> list[Path]:
    return sorted(p for p in BUSINESS_DIR.iterdir() if p.is_dir())


def _yaml(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def load_profile(biz: Path) -> dict:
    return _yaml(biz / "profile.yaml")


def load_expected(biz: Path) -> dict:
    return _yaml(biz / "expected_findings.yaml")


def load_sample(biz: Path, salt: bytes = b"sample", with_uploads: bool = True) -> Assessment:
    profile = load_profile(biz)
    a = Assessment(answers=_yaml(biz / "answers.yaml"), as_of=date.fromisoformat(str(profile["as_of"])))
    if with_uploads:
        for f in sorted((biz / "uploads").glob("*.csv")):
            res = ingest(f.stem, f.read_bytes(), f.name, salt)
            if not res.ok:
                raise ValueError(f"{biz.name}/{f.name}: {res.errors}")
            a.tables[f.stem] = res.rows
        # Lookups are public DNS results the app produces itself; validated, nothing to redact.
        for f in sorted((biz / "lookups").glob("*.csv")):
            with f.open(encoding="utf-8", newline="") as fh:
                model = LOOKUP_MODELS[f.stem]
                a.tables[f.stem] = [model.model_validate(r).model_dump() for r in csv.DictReader(fh)]
    return a
