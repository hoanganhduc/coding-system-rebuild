"""Live integration test — WebDAV upload, download, delete."""

import os
import tempfile
import pytest
from lib.config import load_config
from lib.webdav import WebDAVClient

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")
TEST_KEY = "ZOTTEST0"


@pytest.mark.live
def test_webdav_roundtrip():
    config = load_config(require=["WEBDAV_PASSWORD"])
    if not config.get("webdav_url"):
        pytest.skip("WebDAV not configured")

    client = WebDAVClient(config)

    # Check connection
    ok, msg = client.check_connection()
    assert ok, f"WebDAV connection failed: {msg}"

    pdf_path = os.path.join(FIXTURES_DIR, "valid_paper.pdf")

    # Upload
    client.upload(TEST_KEY, pdf_path, "Test_2024_Roundtrip [Journal Article].pdf")
    assert client.exists(TEST_KEY)

    # Download
    with tempfile.TemporaryDirectory() as tmpdir:
        result = client.download(TEST_KEY, tmpdir)
        assert result is not None
        assert os.path.exists(result)
        assert result.endswith(".pdf")

    # Delete
    client.delete(TEST_KEY)
    assert not client.exists(TEST_KEY)
