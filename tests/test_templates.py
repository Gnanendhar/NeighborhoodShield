"""Upload templates: headers match the schema, worked examples validate, guides exist."""

import pandas as pd
import pytest

from engine.paths import TEMPLATES_DIR
from engine.schemas import REDACT_COLUMNS, TEMPLATE_MODELS, template_columns

NAMES = list(TEMPLATE_MODELS)


@pytest.mark.parametrize("name", NAMES)
def test_header_matches_schema(name):
    header = (TEMPLATES_DIR / f"{name}.csv").read_text(encoding="utf-8").strip().split(",")
    assert header == template_columns(name)


@pytest.mark.parametrize("name", NAMES)
def test_worked_example_validates(name):
    df = pd.read_csv(TEMPLATES_DIR / "examples" / f"{name}_example.csv", dtype=str, keep_default_na=False)
    assert len(df) >= 3
    for row in df.to_dict("records"):
        TEMPLATE_MODELS[name].model_validate(row)


@pytest.mark.parametrize("name", NAMES)
def test_guide_exists_and_explains_every_column(name):
    guide = (TEMPLATES_DIR / "guides" / f"{name}.md").read_text(encoding="utf-8")
    for col in template_columns(name):
        assert col in guide, f"{name} guide does not explain {col}"


@pytest.mark.parametrize("name", NAMES)
def test_redaction_contract_declared(name):
    assert set(REDACT_COLUMNS[name]) <= set(template_columns(name))


def test_bad_row_rejected_with_field_name():
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc:
        TEMPLATE_MODELS["users_permissions"].model_validate(
            {"user_id": "a", "account_type": "boss", "is_admin": "Y", "mfa_enabled": "Y", "status": "active"})
    assert "account_type" in str(exc.value)


def test_export_scripts_are_read_only():
    """The PowerShell exporters must never change settings on a customer machine."""
    forbidden = ["Set-", "Remove-", "Disable-", "Enable-", "New-ItemProperty", "Stop-", "Restart-", "Invoke-WebRequest"]
    for ps1 in (TEMPLATES_DIR / "export_scripts").glob("*.ps1"):
        text = ps1.read_text(encoding="utf-8")
        code = "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))
        for verb in forbidden:
            assert verb not in code.replace("Set-StrictMode", ""), f"{ps1.name} uses {verb}"
