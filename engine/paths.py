"""Repository-relative paths, so the engine works from any working directory."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
CONTENT_DIR = ROOT / "content"
TEMPLATES_DIR = ROOT / "templates"
SAMPLE_DIR = ROOT / "sample_data"
REFERENCE_DIR = ROOT / "data" / "reference"
