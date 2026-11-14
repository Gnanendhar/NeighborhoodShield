"""Upload parsing: validation messages, redaction on read, and safety limits."""

import io

import pytest
from openpyxl import Workbook

from engine.ingest import MAX_ROWS, ingest, redact_ip
from engine.paths import TEMPLATES_DIR
from engine.samples import sample_businesses
from engine.schemas import REDACT_COLUMNS, TEMPLATE_MODELS

SALT = b"test-salt"
USERS_HEADER = "user_id,account_type,is_admin,mfa_enabled,status,created_date,last_login_date,role_or_department\n"


def _csv(text: str) -> bytes:
    return text.encode("utf-8")


def test_valid_csv_is_read_and_user_ids_are_hashed():
    data = _csv(USERS_HEADER + "maria.lopez@example.com,staff,Y,N,active,2024-01-02,2026-11-01,Front desk\n")
    res = ingest("users_permissions", data, "users.csv", SALT)
    assert res.ok, res.errors
    row = res.rows[0]
    assert row["user_id"].startswith("user-") and "maria" not in row["user_id"]
    assert row["role_or_department"] == "Front desk"
    assert str(row["is_admin"]) == "Y"


def test_hash_is_stable_within_a_session_and_differs_across_sessions():
    data = _csv(USERS_HEADER + "owner,admin,Y,Y,active,,,Owner\n")
    a = ingest("users_permissions", data, "u.csv", SALT).rows[0]["user_id"]
    b = ingest("users_permissions", data, "u.csv", SALT).rows[0]["user_id"]
    c = ingest("users_permissions", data, "u.csv", b"other-session").rows[0]["user_id"]
    assert a == b != c


def test_extra_columns_are_dropped_and_mentioned():
    data = _csv(USERS_HEADER.strip() + ",email\nowner,admin,Y,Y,active,,,Owner,owner@example.com\n")
    res = ingest("users_permissions", data, "u.csv", SALT)
    assert res.ok
    assert "email" not in res.rows[0]
    assert any("email" in n for n in res.notes)


def test_missing_column_is_a_plain_message():
    res = ingest("users_permissions", _csv("user_id,account_type\nowner,admin\n"), "u.csv", SALT)
    assert not res.ok
    assert "Missing column(s)" in res.errors[0] and "is_admin" in res.errors[0]


@pytest.mark.parametrize("bad, expected", [
    ("owner,boss,Y,Y,active,,,Owner", "account_type: must be one of"),
    ("owner,admin,maybe,Y,active,,,Owner", "is_admin: must be one of"),
    ("owner,admin,Y,Y,active,yesterday,,Owner", "created_date: must be a date"),
])
def test_invalid_values_reject_the_whole_file_with_row_numbers(bad, expected):
    data = _csv(USERS_HEADER + "cashier-1,staff,N,N,active,,,Register\n" + bad + "\n")
    res = ingest("users_permissions", data, "u.csv", SALT)
    assert not res.ok and not res.rows
    assert res.errors[0].startswith("Row 3,") and expected in res.errors[0]


def test_headers_are_case_and_space_insensitive_and_blank_rows_skipped():
    header = " User_ID , Account_Type,is_admin,mfa_enabled,status,created_date,last_login_date,role_or_department\n"
    data = _csv(header + "owner,admin,Y,Y,active,,,Owner\n,,,,,,,\n")
    res = ingest("users_permissions", data, "u.csv", SALT)
    assert res.ok and len(res.rows) == 1


def test_windows_ansi_csv_is_accepted():
    data = (USERS_HEADER + "owner,admin,Y,Y,active,,,Dueño\n").encode("cp1252")
    assert ingest("users_permissions", data, "u.csv", SALT).ok


def test_xlsx_first_sheet_values_only():
    from datetime import datetime

    wb = Workbook()
    ws = wb.active
    ws.append(USERS_HEADER.strip().split(","))
    ws.append(["owner", "admin", "Y", "Y", "active", datetime(2024, 1, 2), "=TODAY()", "Owner"])
    buf = io.BytesIO()
    wb.save(buf)
    res = ingest("users_permissions", buf.getvalue(), "users.xlsx", SALT)
    # The formula is never evaluated: openpyxl data mode has no cached value, so the cell is empty.
    assert res.ok, res.errors
    assert str(res.rows[0]["created_date"]) == "2024-01-02"
    assert res.rows[0]["last_login_date"] is None


def test_wrong_file_type_and_size_and_row_caps():
    assert "csv or .xlsx" in ingest("users_permissions", b"x", "u.pdf", SALT).errors[0]
    assert "5 MB" in ingest("users_permissions", b"x" * (5 * 1024 * 1024 + 1), "u.csv", SALT).errors[0]
    many = USERS_HEADER + "".join(f"u{i},staff,N,Y,active,,,Staff\n" for i in range(MAX_ROWS + 5))
    assert "more than" in ingest("users_permissions", _csv(many), "u.csv", SALT).errors[0]


def test_corrupt_xlsx_is_a_plain_message():
    assert "could not be opened" in ingest("users_permissions", b"not a zip", "u.xlsx", SALT).errors[0]


@pytest.mark.parametrize("value, expected", [
    ("192.168.0.25", "192.168.0.0/24"),
    ("10.1.2.0/28", "10.1.2.0/24"),
    ("10.0.0.0/8", "10.0.0.0/8"),
    ("2001:db8::1", "2001:db8::/48"),
    ("WAN", "wan"),
    ("any", "any"),
])
def test_ip_truncation(value, expected):
    assert redact_ip(value, SALT) == expected


def test_hostnames_in_firewall_rules_are_hidden():
    assert redact_ip("danielle-laptop", SALT).startswith("host-")


def test_device_names_become_role_labels_consistent_across_templates():
    for biz in sample_businesses():
        p = biz / "uploads" / "patch_inventory.csv"
        e = biz / "uploads" / "endpoint_protection.csv"
        if not (p.exists() and e.exists()):
            continue
        pr = ingest("patch_inventory", p.read_bytes(), p.name, SALT).rows
        er = ingest("endpoint_protection", e.read_bytes(), e.name, SALT).rows
        for r in pr + er:
            assert r["device_id"].startswith(f"{r['device_type']}-")
        raw_p = {line.split(",")[0] for line in p.read_text(encoding="utf-8").splitlines()[1:]}
        raw_e = {line.split(",")[0] for line in e.read_text(encoding="utf-8").splitlines()[1:]}
        if raw_p & raw_e:  # the same laptop in both files keeps the same label
            assert {r["device_id"] for r in pr} & {r["device_id"] for r in er}


@pytest.mark.parametrize("table", sorted(TEMPLATE_MODELS))
def test_every_redaction_rule_is_applied(table):
    """Each REDACT_COLUMNS entry changes the value it covers (no silent pass-through)."""
    example = TEMPLATES_DIR / "examples" / f"{table}_example.csv"
    rows = ingest(table, example.read_bytes(), example.name, SALT).rows
    raw = example.read_text(encoding="utf-8").splitlines()
    header = raw[0].split(",")
    for col, how in REDACT_COLUMNS[table].items():
        originals = {line.split(",")[header.index(col)] for line in raw[1:]}
        for r in rows:
            v = r[col]
            if how == "hash":
                assert v.startswith("user-") and v not in originals
            elif how == "role_label":
                assert v not in originals


@pytest.mark.parametrize("table", sorted(TEMPLATE_MODELS))
def test_blank_templates_and_examples_ingest(table):
    blank = TEMPLATES_DIR / f"{table}.csv"
    example = TEMPLATES_DIR / "examples" / f"{table}_example.csv"
    assert ingest(table, blank.read_bytes(), blank.name, SALT).ok
    res = ingest(table, example.read_bytes(), example.name, SALT)
    assert res.ok and res.rows, res.errors
