"""Streamlit smoke test: every page renders without an exception."""

from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = str(Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py")


@pytest.mark.parametrize("page", ["Start", "Questionnaire", "Rule catalog", "Sample businesses", "Real-world data"])
def test_page_renders(page):
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.sidebar.radio[0].set_value(page).run()
    assert not at.exception, at.exception


def test_follow_up_question_appears_only_when_relevant():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.sidebar.radio[0].set_value("Questionnaire").run()
    labels = [r.label for r in at.radio]
    follow_up = "Does that remote connection ask for a code or an app approval in addition to a password?"
    assert follow_up not in labels
    remote = next(r for r in at.radio if r.label.startswith("Does anyone connect to a business computer"))
    remote.set_value("yes").run()
    assert follow_up in [r.label for r in at.radio]
