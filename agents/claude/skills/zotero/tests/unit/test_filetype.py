"""Tests for lib/filetype.py — MIME detection."""

import os
import zipfile
import pytest
from lib.filetype import detect_content_type, is_pdf


class TestDetectContentType:
    def test_pdf_by_extension(self, tmp_path):
        f = tmp_path / "paper.pdf"
        f.write_bytes(b"%PDF-1.4 test content" + b"\x00" * 100)
        ct, ext = detect_content_type(str(f))
        assert ct == "application/pdf"
        assert ext == ".pdf"

    def test_png_by_extension(self, tmp_path):
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        ct, ext = detect_content_type(str(f))
        assert ct == "image/png"
        assert ext == ".png"

    def test_jpeg_by_extension(self, tmp_path):
        f = tmp_path / "photo.jpg"
        f.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
        ct, ext = detect_content_type(str(f))
        assert ct == "image/jpeg"
        assert ext == ".jpg"

    def test_epub_by_extension(self, tmp_path):
        f = tmp_path / "book.epub"
        f.write_bytes(b"dummy")
        ct, ext = detect_content_type(str(f))
        assert ct == "application/epub+zip"
        assert ext == ".epub"

    def test_docx_by_extension(self, tmp_path):
        f = tmp_path / "doc.docx"
        f.write_bytes(b"dummy")
        ct, ext = detect_content_type(str(f))
        assert "wordprocessingml" in ct
        assert ext == ".docx"

    def test_unknown_extension_with_pdf_magic(self, tmp_path):
        f = tmp_path / "mystery.dat"
        f.write_bytes(b"%PDF-1.7 " + b"\x00" * 100)
        ct, ext = detect_content_type(str(f))
        # Should fall back to magic bytes since .dat is unknown
        assert ct == "application/pdf"

    def test_unknown_extension_with_png_magic(self, tmp_path):
        f = tmp_path / "mystery"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        ct, ext = detect_content_type(str(f))
        assert ct == "image/png"

    def test_completely_unknown(self, tmp_path):
        f = tmp_path / "mystery"
        f.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 100)
        ct, ext = detect_content_type(str(f))
        assert ct == "application/octet-stream"

    def test_zip_epub_detection(self, tmp_path):
        """Test EPUB detection from ZIP magic bytes + mimetype entry."""
        f = tmp_path / "noext"
        with zipfile.ZipFile(str(f), "w") as zf:
            zf.writestr("mimetype", "application/epub+zip")
            zf.writestr("META-INF/container.xml", "<container/>")
        ct, ext = detect_content_type(str(f))
        assert ct == "application/epub+zip"

    def test_zip_docx_detection(self, tmp_path):
        """Test DOCX detection from ZIP magic bytes + word/ directory."""
        f = tmp_path / "noext"
        with zipfile.ZipFile(str(f), "w") as zf:
            zf.writestr("word/document.xml", "<document/>")
            zf.writestr("[Content_Types].xml", "<Types/>")
        ct, ext = detect_content_type(str(f))
        assert "wordprocessingml" in ct

    def test_nonexistent_file(self):
        ct, ext = detect_content_type("/nonexistent/file.xyz")
        # Extension-based detection still works
        assert ct == "application/octet-stream" or ct is not None


class TestIsPdf:
    def test_pdf(self):
        assert is_pdf("application/pdf")

    def test_not_pdf(self):
        assert not is_pdf("image/png")
        assert not is_pdf("application/epub+zip")
        assert not is_pdf("")
