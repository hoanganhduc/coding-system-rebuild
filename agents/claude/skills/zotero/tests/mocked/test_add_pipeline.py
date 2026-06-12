"""Tests for zot add pipeline with mocked HTTP responses."""

import json
import os
import pytest
import responses
from unittest.mock import patch, MagicMock

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")


def _load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


class TestMetadataFetch:
    @responses.activate
    def test_doi_fetch_success(self):
        from lib.metadata import fetch_metadata

        fixture = _load_fixture("metadata_journal.json")
        responses.add(responses.GET, "http://localhost:1969", status=200)
        responses.add(responses.POST, "http://localhost:1969/web",
                      json=fixture, status=200)

        meta, itype, norm = fetch_metadata("10.1093/jcr/ucw010", "http://localhost:1969")
        assert itype == "doi"
        assert meta["title"] == "Decision Comfort"
        assert meta["DOI"] == "10.1093/jcr/ucw010"

    @responses.activate
    def test_arxiv_fetch_success(self):
        from lib.metadata import fetch_metadata

        fixture = _load_fixture("metadata_arxiv.json")
        responses.add(responses.GET, "http://localhost:1969", status=200)
        responses.add(responses.POST, "http://localhost:1969/web",
                      json=fixture, status=200)

        meta, itype, norm = fetch_metadata("2301.12345", "http://localhost:1969")
        assert itype == "arxiv"
        assert norm == "2301.12345"
        assert meta["_arxiv_id"] == "2301.12345"

    @responses.activate
    def test_server_unreachable(self):
        from lib.metadata import fetch_metadata

        responses.add(responses.GET, "http://localhost:1969",
                      body=ConnectionError("refused"))

        with pytest.raises(ConnectionError, match="Translation Server unreachable"):
            fetch_metadata("10.1093/jcr/ucw010", "http://localhost:1969")

    @responses.activate
    def test_no_translator_found(self):
        from lib.metadata import fetch_metadata

        responses.add(responses.GET, "http://localhost:1969", status=200)
        responses.add(responses.POST, "http://localhost:1969/web", status=501)

        with pytest.raises(ValueError, match="no translator found"):
            fetch_metadata("10.9999/nonexistent", "http://localhost:1969")


class TestDuplicateDetection:
    def test_search_by_doi_with_title_hint(self):
        from lib.zotero_client import ZoteroClient

        mock_items = [{
            "key": "ABC123",
            "data": {"title": "Decision Comfort", "DOI": "10.1093/jcr/ucw010", "collections": []}
        }]

        config = {"zotero_user_id": "000", "ZOTERO_API_KEY": "fake"}
        client = ZoteroClient(config)
        client.zot = MagicMock()
        client.zot.top.return_value = mock_items

        result = client.search_by_doi("10.1093/jcr/ucw010", title_hint="Decision Comfort")
        assert result is not None
        assert result["key"] == "ABC123"

    def test_search_by_doi_no_match(self):
        from lib.zotero_client import ZoteroClient

        config = {"zotero_user_id": "000", "ZOTERO_API_KEY": "fake"}
        client = ZoteroClient(config)
        client.zot = MagicMock()
        client.zot.top.return_value = []

        result = client.search_by_doi("10.9999/nonexistent", title_hint="No Such Paper")
        assert result is None
