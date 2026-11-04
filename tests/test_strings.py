"""Questionnaire and UI strings: one YAML file, translation-ready, Quick Check fits 10 minutes."""

import re
from pathlib import Path

import yaml

from engine.loader import load_strings
from engine.paths import CONTENT_DIR

S = load_strings()
QS = S["questions"]


def _walk_keys(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k, f"{path}/{k}"
            yield from _walk_keys(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_keys(v, f"{path}[{i}]")


def test_no_yaml_boolean_traps():
    """Bare yes/no/on/off become booleans in YAML 1.1. Every key must be a string."""
    bad = [p for k, p in _walk_keys(S) if not isinstance(k, str)]
    assert not bad, bad


def test_question_ids_unique_and_prefixed():
    ids = [q["id"] for q in QS]
    assert len(ids) == len(set(ids))
    prefix = {"profile": "bp_", "identity": "iam_", "network": "net_", "patching": "pat_", "endpoint": "end_", "recovery": "bkp_"}
    for q in QS:
        assert q["id"].startswith(prefix[q["section"]]), q["id"]


def test_quick_check_length():
    core = [q for q in QS if q["tier"] == "core"]
    always = [q for q in core if "show_if" not in q]
    assert 30 <= len(always) and len(core) <= 36, (len(always), len(core))


def test_six_sections_each_with_core_questions():
    sections = [s["id"] for s in S["sections"]]
    assert sections == ["profile", "identity", "network", "patching", "endpoint", "recovery"]
    for s in sections:
        assert any(q["section"] == s and q["tier"] == "core" for q in QS), s


def test_types_and_options():
    for q in QS:
        assert q["type"] in {"ynd", "single", "multi", "text"}, q["id"]
        if q["type"] == "text":
            assert q.get("optional"), f"{q['id']}: free-text questions must be optional"
        elif q["type"] != "ynd":
            assert q.get("options"), q["id"]
            assert all(isinstance(v, str) and v for v in q["options"].values())


def test_show_if_points_backwards():
    seen = set()
    by = {q["id"]: q for q in QS}
    for q in QS:
        if "show_if" in q:
            dep = q["show_if"]["q"]
            assert dep in seen, f"{q['id']} depends on later/unknown {dep}"
            assert by[dep]["type"] == "ynd"
        seen.add(q["id"])


def test_statements_present():
    for key in ("self_assessment", "privacy", "acceptable_use", "estimates"):
        assert len(S["statements"][key]) > 40


def _syllables(word: str) -> int:
    word = re.sub(r"[^a-z]", "", word.lower())
    if not word:
        return 0
    groups = re.findall(r"[aeiouy]+", word)
    n = len(groups) - (1 if word.endswith("e") and len(groups) > 1 else 0)
    return max(1, n)


def _fk_grade(text: str) -> float:
    """Flesch-Kincaid grade level (dependency-free approximation)."""
    sentences = max(1, len(re.findall(r"[.?!]", text)))
    words = re.findall(r"[A-Za-z']+", text)
    if not words:
        return 0.0
    syl = sum(_syllables(w) for w in words)
    return 0.39 * len(words) / sentences + 11.8 * syl / len(words) - 15.59


def test_question_text_reading_level():
    """Owners are not IT people: average question reads at about grade 8 or below."""
    grades = [_fk_grade(q["text"]) for q in QS]
    avg = sum(grades) / len(grades)
    assert avg <= 8.5, avg


def test_spanish_ready_structure():
    """A future strings.es.yaml must have exactly the same keys; check the loader path exists."""
    assert (CONTENT_DIR / "strings.yaml").exists()
    raw = yaml.safe_load(Path(CONTENT_DIR / "strings.yaml").read_text(encoding="utf-8"))
    assert raw["meta"]["locale"] == "en"
