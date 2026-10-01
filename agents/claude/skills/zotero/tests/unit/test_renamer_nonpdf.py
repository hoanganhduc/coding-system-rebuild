"""Tests for rename_non_pdf in lib/renamer.py."""

import pytest
from lib.renamer import rename_non_pdf


class TestRenameNonPdf:
    def _meta(self, **overrides):
        base = {
            "title": "Decision Comfort",
            "creators": [
                {"creatorType": "author", "lastName": "Parker"},
                {"creatorType": "author", "lastName": "Schrift"},
            ],
            "date": "2016",
            "itemType": "journalArticle",
        }
        base.update(overrides)
        return base

    def test_with_metadata(self):
        result = rename_non_pdf("figure1.png", self._meta())
        assert "Parker_Schrift" in result
        assert "2016" in result
        assert "figure1" in result

    def test_without_metadata(self):
        result = rename_non_pdf("photo.jpg")
        assert result == "photo"

    def test_without_metadata_with_spaces(self):
        result = rename_non_pdf("my cool document.epub")
        assert result == "my cool document"

    def test_with_metadata_no_authors(self):
        result = rename_non_pdf("data.xlsx", self._meta(creators=[]))
        assert "2016" in result
        assert "data" in result
        assert result.startswith("2016_")

    def test_sanitizes_special_chars(self):
        result = rename_non_pdf('file "with" <special>.png', self._meta())
        assert '"' not in result
        assert "<" not in result

    def test_extension_stripped(self):
        """Extension should not be in the returned name (caller adds it)."""
        result = rename_non_pdf("document.epub", self._meta())
        assert ".epub" not in result
