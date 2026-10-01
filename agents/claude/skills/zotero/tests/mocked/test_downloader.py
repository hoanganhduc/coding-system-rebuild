"""Tests for lib/downloader.py — download chain branching and source fallback."""

import os
import json
import pytest
import responses
from unittest.mock import patch, MagicMock

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")


class TestBuildSourceChain:
    def test_doi_chain_order(self):
        from lib.downloader import _build_source_chain
        chain = _build_source_chain("doi", "10.1093/jcr/ucw010", "", "10.1093/jcr/ucw010", {})
        labels = [label for _, _, label in chain]
        assert "getscipapers" in labels[0].lower()
        assert "semantic scholar" in labels[1].lower()

    def test_doi_with_arxiv_adds_fallback(self):
        from lib.downloader import _build_source_chain
        chain = _build_source_chain("doi", "10.1093/jcr/ucw010", "2301.12345", "10.1093/jcr/ucw010", {})
        labels = [label for _, _, label in chain]
        assert len(labels) == 4  # doi + semantic scholar + arxiv gsp + arxiv direct
        assert "arxiv" in labels[2].lower()
        assert "arxiv direct" in labels[3].lower()

    def test_isbn_chain(self):
        from lib.downloader import _build_source_chain
        chain = _build_source_chain("isbn", "", "", "9780134685991", {})
        labels = [label for _, _, label in chain]
        assert len(labels) == 1
        assert "isbn" in labels[0].lower()

    def test_arxiv_chain(self):
        from lib.downloader import _build_source_chain
        chain = _build_source_chain("arxiv", "", "", "2301.12345", {})
        labels = [label for _, _, label in chain]
        assert len(labels) == 2  # getscipapers --arxiv + arxiv direct
        assert "getscipapers" in labels[0].lower()
        assert "arxiv direct" in labels[1].lower()

    def test_arxiv_with_publisher_doi(self):
        from lib.downloader import _build_source_chain
        chain = _build_source_chain("arxiv", "10.1145/12345", "", "2301.12345", {})
        labels = [label for _, _, label in chain]
        assert len(labels) == 4  # arxiv gsp + arxiv direct + doi + semantic scholar


class TestStagingFilenames:
    def test_unique_filenames(self):
        from lib.downloader import _staging_path
        import time
        p1 = _staging_path("/tmp", "doi1")
        time.sleep(0.01)
        p2 = _staging_path("/tmp", "doi2")
        assert p1 != p2

    def test_same_doi_different_timestamp(self):
        from lib.downloader import _staging_path
        import time
        p1 = _staging_path("/tmp", "same_doi")
        time.sleep(1.1)
        p2 = _staging_path("/tmp", "same_doi")
        assert p1 != p2


class TestSemanticScholar:
    @responses.activate
    def test_semantic_scholar_success(self):
        from lib.downloader import _semantic_scholar

        ss_fixture = json.load(open(os.path.join(FIXTURES_DIR, "semantic_scholar.json")))
        responses.add(responses.GET,
                      "https://api.semanticscholar.org/graph/v1/paper/DOI:10.1093/jcr/ucw010",
                      json=ss_fixture, status=200)

        pdf_content = open(os.path.join(FIXTURES_DIR, "valid_paper.pdf"), "rb").read()
        responses.add(responses.GET, "https://arxiv.org/pdf/2301.12345.pdf",
                      body=pdf_content, status=200)

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _semantic_scholar(tmpdir, "10.1093/jcr/ucw010", {})
            assert result is not None
            assert os.path.exists(result)

    @responses.activate
    def test_semantic_scholar_no_pdf(self):
        from lib.downloader import _semantic_scholar

        responses.add(responses.GET,
                      "https://api.semanticscholar.org/graph/v1/paper/DOI:10.1093/jcr/ucw010",
                      json={"paperId": "abc", "openAccessPdf": None}, status=200)

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _semantic_scholar(tmpdir, "10.1093/jcr/ucw010", {})
            assert result is None
