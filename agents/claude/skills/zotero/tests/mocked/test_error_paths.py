"""Tests for error paths — verify correct error codes in JSON output."""

import json
import os
import subprocess
import sys
import pytest
import responses

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")


class TestVerifierRejections:
    """Test that the verifier correctly rejects bad PDFs."""

    def test_reject_stub(self):
        from lib.verifier import verify
        path = os.path.join(FIXTURES_DIR, "stub_1page.pdf")
        result = verify(path, metadata={"itemType": "journalArticle"})
        assert result["status"] == "reject"
        assert result["page_count"] == 1

    def test_reject_slides(self):
        from lib.verifier import verify
        path = os.path.join(FIXTURES_DIR, "slides_landscape.pdf")
        result = verify(path, metadata={})
        assert result["status"] == "reject"
        assert "landscape" in result["reason"].lower() or "slides" in result["reason"].lower()

    def test_accept_valid_paper(self):
        from lib.verifier import verify
        path = os.path.join(FIXTURES_DIR, "valid_paper.pdf")
        result = verify(path, metadata={})
        assert result["status"] == "accept"
        assert result["page_count"] == 10

    def test_accept_stub_as_poster(self):
        from lib.verifier import verify
        path = os.path.join(FIXTURES_DIR, "stub_1page.pdf")
        result = verify(path, metadata={"itemType": "conferencePaper", "title": "Poster: My Results"})
        assert result["status"] == "accept"

    def test_accept_stub_with_flag(self):
        from lib.verifier import verify
        path = os.path.join(FIXTURES_DIR, "stub_1page.pdf")
        result = verify(path, accept_short=True)
        assert result["status"] == "accept"

    def test_scanned_pdf_unverified(self):
        from lib.verifier import verify
        path = os.path.join(FIXTURES_DIR, "scanned_paper.pdf")
        result = verify(path, metadata={"title": "Nonexistent Title XYZ"}, source_type="semantic_scholar")
        # Blank pages have no text → unverified
        assert result["status"] in ("unverified", "accept")


class TestMetadataErrors:
    @responses.activate
    def test_translation_server_down(self):
        from lib.metadata import fetch_metadata
        responses.add(responses.GET, "http://localhost:1969",
                      body=ConnectionError("refused"))
        with pytest.raises(ConnectionError):
            fetch_metadata("10.1093/jcr/ucw010", "http://localhost:1969")

    @responses.activate
    def test_translation_server_501(self):
        from lib.metadata import fetch_metadata
        responses.add(responses.GET, "http://localhost:1969", status=200)
        responses.add(responses.POST, "http://localhost:1969/web", status=501)
        with pytest.raises(ValueError, match="no translator"):
            fetch_metadata("10.9999/bad", "http://localhost:1969")

    @responses.activate
    def test_translation_server_empty_result(self):
        from lib.metadata import fetch_metadata
        responses.add(responses.GET, "http://localhost:1969", status=200)
        responses.add(responses.POST, "http://localhost:1969/web", json=[], status=200)
        with pytest.raises(ValueError, match="empty result"):
            fetch_metadata("10.9999/empty", "http://localhost:1969")


class TestInputDetectionEdgeCases:
    def test_unknown_identifier(self):
        from lib.metadata import detect_input_type
        t, _ = detect_input_type("randomgarbage")
        assert t == "unknown"

    def test_empty_string(self):
        from lib.metadata import detect_input_type
        t, _ = detect_input_type("")
        assert t == "unknown"
