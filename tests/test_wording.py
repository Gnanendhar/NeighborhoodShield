"""Project wording rule: describe sample data as samples created for testing, never with these words.

The words are assembled from pieces so this file does not trip its own check.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BANNED = re.compile("|".join(["fic" + "tion", "fa" + "ke", "imag" + "inar", "dum" + "my", "made[- ]" + "up",
                              "pla" + "ceholder", "bog" + "us", "pho" + "ny"]), re.IGNORECASE)
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules"}
TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".csv", ".toml", ".txt", ".ps1", ".json", ".mmd", ".svg", ".drawio",
                 ".cfg", ".ini", ".html", ".gitignore", ".gitattributes"}


def _files():
    for p in ROOT.rglob("*"):
        if p.is_file() and not (SKIP_DIRS & set(p.relative_to(ROOT).parts)) and (
                p.suffix.lower() in TEXT_SUFFIXES or p.name.startswith(".git")):
            yield p


def test_no_banned_wording_anywhere():
    hits = []
    for p in _files():
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            if BANNED.search(line):
                hits.append(f"{p.relative_to(ROOT)}:{n}: {line.strip()[:100]}")
    assert not hits, "\n".join(hits)
