"""Tests for lib/webdav.py — zip format, upload/download, auth, rollback."""

import io
import os
import json
import zipfile
import pytest
import responses

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")


def _make_config():
    return {
        "webdav_url": "https://example.com/dav/",
        "webdav_user": "testuser",
        "WEBDAV_PASSWORD": "testpass",
    }


class TestWebDAVUpload:
    @responses.activate
    def test_upload_creates_correct_zip(self):
        from lib.webdav import WebDAVClient

        uploaded_data = {}

        def capture_upload(request):
            uploaded_data["body"] = request.body
            return (201, {}, "")

        responses.add_callback(responses.PUT,
                               "https://example.com/dav/zotero/TESTKEY.zip",
                               callback=capture_upload)

        client = WebDAVClient(_make_config())
        pdf_path = os.path.join(FIXTURES_DIR, "valid_paper.pdf")
        client.upload("TESTKEY", pdf_path, "Author_2024_Title [Journal Article].pdf")

        # Verify zip structure
        zf = zipfile.ZipFile(io.BytesIO(uploaded_data["body"]))
        names = zf.namelist()
        assert len(names) == 1
        assert names[0] == "Author_2024_Title [Journal Article].pdf"
        assert zf.infolist()[0].compress_type == zipfile.ZIP_DEFLATED

    @responses.activate
    def test_upload_failure_raises(self):
        from lib.webdav import WebDAVClient

        responses.add(responses.PUT,
                      "https://example.com/dav/zotero/FAILKEY.zip",
                      status=507)  # Insufficient Storage

        client = WebDAVClient(_make_config())
        pdf_path = os.path.join(FIXTURES_DIR, "valid_paper.pdf")
        with pytest.raises(RuntimeError, match="507"):
            client.upload("FAILKEY", pdf_path, "test.pdf")


class TestWebDAVDownload:
    @responses.activate
    def test_download_extracts_pdf(self):
        from lib.webdav import WebDAVClient

        # Serve the sample zip
        zip_data = open(os.path.join(FIXTURES_DIR, "sample_webdav.zip"), "rb").read()
        responses.add(responses.GET,
                      "https://example.com/dav/zotero/DLKEY.zip",
                      body=zip_data, status=200)

        client = WebDAVClient(_make_config())
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            result = client.download("DLKEY", tmpdir)
            assert result is not None
            assert os.path.exists(result)
            assert result.endswith(".pdf")

    @responses.activate
    def test_download_not_found(self):
        from lib.webdav import WebDAVClient

        responses.add(responses.GET,
                      "https://example.com/dav/zotero/MISSING.zip",
                      status=404)

        client = WebDAVClient(_make_config())
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            result = client.download("MISSING", tmpdir)
            assert result is None


class TestWebDAVAuth:
    @responses.activate
    def test_digest_fallback(self):
        from lib.webdav import WebDAVClient

        # First request returns 401, second succeeds
        responses.add(responses.HEAD,
                      "https://example.com/dav/zotero/KEY.zip",
                      status=401)
        responses.add(responses.HEAD,
                      "https://example.com/dav/zotero/KEY.zip",
                      status=200)

        client = WebDAVClient(_make_config())
        assert client.exists("KEY")
        assert client._auth_type == "digest"
