"""Streamlit smoke test: every page renders, and the sample flow reaches real findings."""

from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py")
PAGES = ["Start", "Questionnaire", "Results", "Rule catalog", "Sample businesses", "Real-world data"]


def _app():
    return AppTest.from_file(APP, default_timeout=30).run()


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(page):
    at = _app()
    at.sidebar.radio[0].set_value(page).run()
    assert not at.exception, at.exception


def test_follow_up_question_appears_only_when_relevant():
    at = _app()
    at.sidebar.radio[0].set_value("Questionnaire").run()
    labels = [r.label for r in at.radio]
    follow_up = "Does that remote connection ask for a code or an app approval in addition to a password?"
    assert follow_up not in labels
    remote = next(r for r in at.radio if r.label.startswith("Does anyone connect to a business computer"))
    remote.set_value("yes").run()
    assert follow_up in [r.label for r in at.radio]


def test_sample_business_flows_through_to_findings():
    at = _app()
    at.sidebar.radio[0].set_value("Questionnaire").run()
    at.selectbox(key="sample_choice").set_value("Taqueria Luna Azul (sample)").run()
    next(b for b in at.button if b.label.startswith("Fill in")).click().run()
    assert not at.exception, at.exception
    at.sidebar.radio[0].set_value("Results").run()
    assert not at.exception, at.exception
    titles = [e.label for e in at.expander]
    assert any("Shared logins" in t for t in titles), titles
    assert any("Administrator accounts without multi-factor authentication" in t for t in titles), titles
    # Hashed labels only: the sample's raw user names never reach the page.
    page_text = " ".join(str(c.value) for c in at.caption)
    assert "former-cashier" not in page_text and "user-" in page_text


def test_results_page_without_answers_explains_what_to_do():
    at = _app()
    at.sidebar.radio[0].set_value("Results").run()
    assert any("Answer some questions first" in i.value for i in at.info)
