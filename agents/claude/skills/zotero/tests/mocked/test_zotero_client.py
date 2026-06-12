"""Tests for lib/zotero_client.py — retry logic and API wrapper."""

import pytest
from unittest.mock import patch, MagicMock
from pyzotero.zotero_errors import HTTPError

from lib.zotero_client import ZoteroClient, _extract_status, _extract_retry_after


class TestRetryLogic:
    def _make_client(self):
        config = {
            "zotero_user_id": "000000",
            "ZOTERO_API_KEY": "fake_key",
        }
        client = ZoteroClient(config)
        client._base_delay = 0.01  # fast retries for testing
        return client

    def test_retry_on_429(self):
        client = self._make_client()
        call_count = 0

        def flaky_func(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise HTTPError("429 Too Many Requests")
            return [{"key": "TEST", "data": {"title": "Test"}}]

        result = client._retry(flaky_func)
        assert call_count == 3
        assert result[0]["key"] == "TEST"

    def test_no_retry_on_400(self):
        client = self._make_client()

        def bad_request(*args, **kwargs):
            raise HTTPError("400 Bad Request")

        with pytest.raises(HTTPError):
            client._retry(bad_request)

    def test_exhausted_retries_raises(self):
        client = self._make_client()

        def always_429(*args, **kwargs):
            raise HTTPError("429 Too Many Requests")

        with pytest.raises(HTTPError):
            client._retry(always_429)


class TestHelpers:
    def test_extract_status_429(self):
        assert _extract_status(Exception("429 Too Many Requests")) == 429

    def test_extract_status_500(self):
        assert _extract_status(Exception("500 Internal Server Error")) == 500

    def test_extract_status_none(self):
        assert _extract_status(Exception("some other error")) is None

    def test_extract_retry_after(self):
        result = _extract_retry_after(Exception("Retry-After: 5"))
        assert result == 5

    def test_extract_retry_after_missing(self):
        assert _extract_retry_after(Exception("no header")) is None
