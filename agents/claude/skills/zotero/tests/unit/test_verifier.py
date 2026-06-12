"""Tests for lib/verifier.py — PDF validation logic."""

import os
import pytest
from lib.verifier import verify, _is_short_form, _expected_pages, _fuzzy_match


class TestIsShortForm:
    def test_poster_in_title(self):
        assert _is_short_form({"itemType": "conferencePaper", "title": "A Poster on Graphs", "extra": ""})

    def test_extended_abstract(self):
        assert _is_short_form({"itemType": "conferencePaper", "title": "Extended Abstract: Token Sliding", "extra": ""})

    def test_regular_paper(self):
        assert not _is_short_form({"itemType": "conferencePaper", "title": "Regular Paper", "extra": ""})

    def test_journal_article_not_short(self):
        assert not _is_short_form({"itemType": "journalArticle", "title": "Poster Results", "extra": ""})


class TestExpectedPages:
    def test_page_range(self):
        assert _expected_pages({"pages": "113-133"}) == 21

    def test_page_range_endash(self):
        assert _expected_pages({"pages": "1–15"}) == 15

    def test_no_pages(self):
        assert _expected_pages({"pages": ""}) is None

    def test_single_page(self):
        assert _expected_pages({"pages": "42"}) is None


class TestFuzzyMatch:
    def test_title_in_text(self):
        assert _fuzzy_match("Decision Comfort in Life", "This paper studies decision comfort in life choices.")

    def test_title_not_in_text(self):
        assert not _fuzzy_match(
            "Token Sliding on Caterpillar Graphs",
            "This paper is about quantum computing and machine learning applications."
        )

    def test_short_title(self):
        # Very short words are skipped, so short titles default to True
        assert _fuzzy_match("On A B", "something else entirely")


class TestVerify:
    def test_missing_file(self):
        result = verify("/nonexistent/file.pdf")
        assert result["status"] == "reject"
        assert "does not exist" in result["reason"]

    def test_not_pdf(self, tmp_path):
        f = tmp_path / "fake.pdf"
        f.write_bytes(b"<html>not a pdf</html>" + b"\x00" * 60000)
        result = verify(str(f))
        assert result["status"] == "reject"
        assert "%PDF" in result["reason"]

    def test_too_small(self, tmp_path):
        f = tmp_path / "tiny.pdf"
        f.write_bytes(b"%PDF-1.4 " + b"\x00" * 100)
        result = verify(str(f))
        assert result["status"] == "reject"
        assert "Too small" in result["reason"]
