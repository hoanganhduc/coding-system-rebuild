"""Live integration test — search Zotero library."""

import pytest
from lib.config import load_config
from lib.zotero_client import ZoteroClient


@pytest.mark.live
def test_search_known_item():
    config = load_config(require=["ZOTERO_API_KEY"])
    client = ZoteroClient(config)
    items = client.search("token sliding", limit=5)
    assert len(items) > 0
    titles = [i["data"]["title"].lower() for i in items]
    assert any("token" in t or "sliding" in t for t in titles)


@pytest.mark.live
def test_search_returns_metadata():
    config = load_config(require=["ZOTERO_API_KEY"])
    client = ZoteroClient(config)
    items = client.search("reconfiguration", limit=1)
    assert len(items) > 0
    data = items[0]["data"]
    assert "title" in data
    assert "creators" in data
    assert "key" in items[0]
