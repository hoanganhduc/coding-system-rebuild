"""Tests for lib/metadata.py — input auto-detection and normalization."""

import pytest
from lib.metadata import detect_input_type


class TestDetectInputType:
    # DOI
    def test_bare_doi(self):
        assert detect_input_type("10.1093/jcr/ucw010") == ("doi", "10.1093/jcr/ucw010")

    def test_doi_url(self):
        assert detect_input_type("https://doi.org/10.1093/jcr/ucw010") == ("doi", "10.1093/jcr/ucw010")

    def test_dx_doi_url(self):
        assert detect_input_type("https://dx.doi.org/10.1093/jcr/ucw010") == ("doi", "10.1093/jcr/ucw010")

    # arXiv
    def test_arxiv_new_format(self):
        assert detect_input_type("2301.12345") == ("arxiv", "2301.12345")

    def test_arxiv_with_prefix(self):
        assert detect_input_type("arXiv:2301.12345") == ("arxiv", "2301.12345")

    def test_arxiv_with_version(self):
        assert detect_input_type("2301.12345v2") == ("arxiv", "2301.12345v2")

    def test_arxiv_url(self):
        assert detect_input_type("https://arxiv.org/abs/2301.12345") == ("arxiv", "2301.12345")

    def test_arxiv_pdf_url(self):
        assert detect_input_type("https://arxiv.org/pdf/2301.12345") == ("arxiv", "2301.12345")

    def test_arxiv_old_format(self):
        assert detect_input_type("math/0601001") == ("arxiv", "math/0601001")

    def test_arxiv_old_format_with_prefix(self):
        assert detect_input_type("arXiv:cs/0601001") == ("arxiv", "cs/0601001")

    # ISBN
    def test_isbn_13_hyphens(self):
        t, n = detect_input_type("978-0-13-468599-1")
        assert t == "isbn"
        assert n == "9780134685991"

    def test_isbn_13_bare(self):
        t, n = detect_input_type("9780134685991")
        assert t == "isbn"

    def test_isbn_10(self):
        t, n = detect_input_type("0134685997")
        assert t == "isbn"

    def test_isbn_with_prefix(self):
        t, n = detect_input_type("ISBN:978-0-13-468599-1")
        assert t == "isbn"

    # URL
    def test_generic_url(self):
        assert detect_input_type("https://example.com/paper")[0] == "url"

    # Fallback
    def test_unknown_with_slash_as_doi(self):
        t, _ = detect_input_type("some/identifier")
        assert t == "doi"

    def test_truly_unknown(self):
        assert detect_input_type("randomstring")[0] == "unknown"
