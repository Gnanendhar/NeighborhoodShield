"""Read an uploaded template, validate it, and redact it before anything else sees it.

Privacy contract (docs/design.md section 4):

* Files are read from memory only. Nothing is written to disk.
* Columns that are not part of the template are dropped on read, so a stray
  "email" or "full name" column never reaches the engine.
* Columns listed in ``schemas.REDACT_COLUMNS`` are replaced immediately:
  user IDs are hashed with a per-session salt, IP addresses are shortened to
  their network, and device or system names become role labels.
* The whole file is rejected if any row is invalid, with plain-language
  messages, so a half-read file can never produce a misleading finding.

Safety: size cap, row cap, Excel read in values-only mode (formulas are not
evaluated), CSV parsed with the standard library.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from .schemas import REDACT_COLUMNS, TEMPLATE_MODELS

MAX_BYTES = 5 * 1024 * 1024  # matches .streamlit/config.toml maxUploadSize
MAX_ROWS = 2000              # far above any small business; stops runaway files
MAX_MESSAGES = 10            # owners need the first few problems, not hundreds

# Firewall words that are not addresses and carry meaning for the rules.
NETWORK_KEYWORDS = {"any", "lan", "wan", "guest", "*", "all", "internet", "local"}

_MIDNIGHT = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T]00:00(:00)?$")


class UploadError(ValueError):
    """The file could not be read at all (wrong type, too big, empty)."""


@dataclass
class IngestResult:
    table: str
    rows: list[dict[str, Any]] = field(default_factory=list)  # validated, redacted
    errors: list[str] = field(default_factory=list)           # plain-language, owner-facing
    notes: list[str] = field(default_factory=list)            # e.g. dropped extra columns

    @property
    def ok(self) -> bool:
        return not self.errors


# ---------------------------------------------------------------- reading
def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252")  # Excel "Save as CSV" on Windows


def _read_csv(data: bytes) -> list[list[str]]:
    reader = csv.reader(io.StringIO(_decode(data)))
    out = []
    for i, row in enumerate(reader):
        if i > MAX_ROWS + 1:
            raise UploadError(f"This file has more than {MAX_ROWS} rows. Please upload a shorter list.")
        out.append(row)
    return out


def _cell(v: Any) -> str:
    if v is None:
        return ""
    if hasattr(v, "date") and hasattr(v, "hour"):  # datetime from Excel
        return v.date().isoformat() if (v.hour, v.minute, v.second) == (0, 0, 0) else v.isoformat(sep=" ")
    if hasattr(v, "isoformat"):  # date
        return v.isoformat()
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _read_xlsx(data: bytes) -> list[list[str]]:
    from openpyxl import load_workbook

    try:
        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:  # corrupt or not really Excel
        raise UploadError("This Excel file could not be opened. Save it again as .xlsx or .csv.") from exc
    try:
        ws = wb.worksheets[0]
        out = []
        for i, row in enumerate(ws.iter_rows(values_only=True)):
            if i > MAX_ROWS + 1:
                raise UploadError(f"This file has more than {MAX_ROWS} rows. Please upload a shorter list.")
            out.append([_cell(v) for v in row])
        return out
    finally:
        wb.close()


def read_table(data: bytes, filename: str) -> tuple[list[str], list[dict[str, str]]]:
    """Return the normalized header and the rows as dicts of trimmed strings."""
    if len(data) > MAX_BYTES:
        raise UploadError("This file is larger than 5 MB. Please upload only the template columns.")
    name = filename.lower()
    if name.endswith(".xlsx"):
        grid = _read_xlsx(data)
    elif name.endswith(".csv"):
        grid = _read_csv(data)
    else:
        raise UploadError("Please upload a .csv or .xlsx file.")
    grid = [r for r in grid if any(str(c).strip() for c in r)]
    if not grid:
        raise UploadError("This file is empty.")
    header = [str(h).strip().lower() for h in grid[0]]
    rows = []
    for r in grid[1:]:
        r = list(r) + [""] * (len(header) - len(r))
        rows.append({h: str(v).strip() for h, v in zip(header, r, strict=False) if h})
    return header, rows


# ---------------------------------------------------------------- redaction
def _digest(value: str, salt: bytes, n: int = 8) -> str:
    return hmac.new(salt, value.strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()[:n]


def redact_hash(value: str | None, salt: bytes) -> str | None:
    return None if not value else f"user-{_digest(value, salt)}"


def redact_ip(value: str | None, salt: bytes) -> str | None:
    """Keep firewall keywords; shorten addresses to their network; hide anything else."""
    if not value:
        return value
    v = value.strip()
    if v.lower() in NETWORK_KEYWORDS:
        return v.lower()
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        return f"host-{_digest(v, salt, 6)}"  # a hostname or free text: never keep it
    keep = 24 if net.version == 4 else 48
    if net.prefixlen > keep:
        net = net.supernet(new_prefix=keep)
    return str(net)


def redact_role(value: str | None, salt: bytes, kind: str | None) -> str | None:
    if not value:
        return value
    return f"{kind or 'system'}-{_digest(value, salt, 6)}"


def redact_rows(table: str, rows: list[dict[str, Any]], salt: bytes) -> list[dict[str, Any]]:
    plan = REDACT_COLUMNS.get(table, {})
    out = []
    for row in rows:
        row = dict(row)
        for col, how in plan.items():
            v = row.get(col)
            if how == "hash":
                row[col] = redact_hash(v, salt)
            elif how == "truncate_ip":
                row[col] = redact_ip(v, salt)
            elif how == "role_label":
                kind = row.get("device_type")
                row[col] = redact_role(v, salt, str(kind) if kind else None)
            else:  # a new strategy declared in schemas.py but not implemented here
                raise ValueError(f"unknown redaction {how!r} for {table}.{col}")
        out.append(row)
    return out


# ---------------------------------------------------------------- validation
def _plain_error(row_no: int, err: dict) -> str:
    col = ".".join(str(p) for p in err.get("loc", ())) or "row"
    t = err.get("type", "")
    ctx = err.get("ctx") or {}
    if t == "missing":
        why = "is empty but needs a value"
    elif t in ("literal_error", "enum"):
        why = f"must be one of: {ctx.get('expected', '').replace(chr(39), '')}"
    elif t.startswith("date"):
        why = "must be a date like 2026-11-04"
    elif t.startswith("int") or t == "greater_than_equal":
        why = "must be a whole number, 0 or more"
    else:
        why = err.get("msg", "is not valid")
    return f"Row {row_no}, column {col}: {why}."


def ingest(table: str, data: bytes, filename: str, salt: bytes) -> IngestResult:
    """Read, validate and redact one uploaded template."""
    if table not in TEMPLATE_MODELS:
        raise KeyError(f"unknown template {table!r}")
    model = TEMPLATE_MODELS[table]
    columns = list(model.model_fields)
    result = IngestResult(table=table)

    try:
        header, raw = read_table(data, filename)
    except UploadError as exc:
        result.errors.append(str(exc))
        return result

    present = {h for h in header if h}
    missing = [c for c in columns if c not in present]
    extra = sorted(present - set(columns))
    if missing:
        result.errors.append(
            "Missing column(s): " + ", ".join(missing) + ". Please start from the template so the headers match.")
        return result
    if extra:
        result.notes.append("Ignored column(s) that are not in the template: " + ", ".join(extra) + ".")
    if not raw:
        result.notes.append("The file has headers but no rows.")

    clean = []
    for i, r in enumerate(raw, start=2):  # row 1 is the header
        rec = {c: r.get(c, "") for c in columns}
        for c, v in rec.items():
            m = _MIDNIGHT.match(v)
            if m:
                rec[c] = m.group(1)
        try:
            clean.append(model.model_validate(rec).model_dump())
        except ValidationError as exc:
            for e in exc.errors():
                if len(result.errors) < MAX_MESSAGES:
                    result.errors.append(_plain_error(i, e))
    if result.errors:
        if len(result.errors) == MAX_MESSAGES:
            result.errors.append("Fix these first; there may be more.")
        return result

    result.rows = redact_rows(table, clean, salt)
    return result
