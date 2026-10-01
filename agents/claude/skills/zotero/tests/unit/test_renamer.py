"""Tests for lib/renamer.py — ZotFile pattern engine."""

import pytest
from lib.renamer import rename, _format_authors, _format_title, _extract_year


class TestFormatAuthors:
    def test_single_author(self):
        creators = [{"creatorType": "author", "lastName": "Parker"}]
        assert _format_authors(creators) == "Parker"

    def test_two_authors(self):
        creators = [
            {"creatorType": "author", "lastName": "Parker"},
            {"creatorType": "author", "lastName": "Schrift"},
        ]
        assert _format_authors(creators) == "Parker_Schrift"

    def test_three_authors(self):
        creators = [
            {"creatorType": "author", "lastName": "A"},
            {"creatorType": "author", "lastName": "B"},
            {"creatorType": "author", "lastName": "C"},
        ]
        assert _format_authors(creators) == "A_B_C"

    def test_four_authors_omitted(self):
        creators = [
            {"creatorType": "author", "lastName": "Parker"},
            {"creatorType": "author", "lastName": "Schrift"},
            {"creatorType": "author", "lastName": "Smith"},
            {"creatorType": "author", "lastName": "Jones"},
        ]
        assert _format_authors(creators) == "Parker et al"

    def test_no_authors(self):
        assert _format_authors([]) == ""

    def test_editors_ignored(self):
        creators = [
            {"creatorType": "editor", "lastName": "Editor"},
            {"creatorType": "author", "lastName": "Author"},
        ]
        assert _format_authors(creators) == "Author"

    def test_name_field_instead_of_lastname(self):
        creators = [{"creatorType": "author", "name": "Organization"}]
        assert _format_authors(creators) == "Organization"


class TestFormatTitle:
    def test_simple_title(self):
        assert _format_title("Decision Comfort") == "Decision Comfort"

    def test_truncate_at_colon(self):
        assert _format_title("Token Sliding: A Reconfiguration Approach") == "Token Sliding"

    def test_truncate_at_period(self):
        assert _format_title("Graph Problems. New Approaches and Results") == "Graph Problems"

    def test_skip_early_period(self):
        # "e.g." should not trigger truncation
        result = _format_title("e.g. this is a title with a period later. second part")
        assert "this is a title" in result

    def test_max_length(self):
        long_title = "A" * 200
        result = _format_title(long_title)
        assert len(result) <= 150

    def test_empty_title(self):
        assert _format_title("") == "Untitled"

    def test_none_title(self):
        assert _format_title(None) == "Untitled"


class TestExtractYear:
    def test_full_date(self):
        assert _extract_year("2016-03-15") == "2016"

    def test_year_only(self):
        assert _extract_year("2016") == "2016"

    def test_month_year(self):
        assert _extract_year("March 2016") == "2016"

    def test_empty(self):
        assert _extract_year("") == ""

    def test_no_year(self):
        assert _extract_year("no date") == ""


class TestRename:
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

    def test_default_pattern(self):
        result = rename(self._meta())
        assert result == "Parker_Schrift_2016_Decision Comfort [Journal Article]"

    def test_conference_paper(self):
        result = rename(self._meta(itemType="conferencePaper"))
        assert "[Conference Paper]" in result

    def test_preprint(self):
        result = rename(self._meta(itemType="preprint"))
        assert "[Preprint]" in result

    def test_many_authors(self):
        creators = [{"creatorType": "author", "lastName": n} for n in ["A", "B", "C", "D"]]
        result = rename(self._meta(creators=creators))
        assert "A et al" in result
        assert "B" not in result

    def test_no_authors(self):
        result = rename(self._meta(creators=[]))
        assert result.startswith("2016_")

    def test_no_date(self):
        result = rename(self._meta(date=""))
        assert "Parker_Schrift" in result
        assert "Decision Comfort" in result

    def test_unicode_preserved(self):
        result = rename(self._meta(
            creators=[{"creatorType": "author", "lastName": "Müller"}],
            title="Über Graphen",
        ))
        # NFKD normalization decomposes accents
        assert "Muller" in result or "Müller" in result

    def test_title_with_colon_truncated(self):
        result = rename(self._meta(title="Reconfiguration: New Perspectives on Old Problems"))
        assert "Reconfiguration" in result
        assert "New Perspectives" not in result

    def test_special_chars_removed(self):
        result = rename(self._meta(title='Graphs & Algorithms: A "New" Approach'))
        # & and " should be removed by sanitization
        assert '"' not in result
