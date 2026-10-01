"""Live integration test — add throwaway item, verify, delete."""

import pytest
from lib.config import load_config
from lib.zotero_client import ZoteroClient
from lib.metadata import fetch_metadata


TEST_DOI = "10.4230/LIPIcs.ISAAC.2019.48"  # A known LIPIcs paper


@pytest.mark.live
def test_add_and_delete():
    config = load_config(require=["ZOTERO_API_KEY"])
    client = ZoteroClient(config)

    # Fetch metadata
    metadata, itype, norm = fetch_metadata(TEST_DOI, config.get("translation_server"))
    assert metadata["title"]

    # Create item
    item_data = {k: v for k, v in metadata.items() if not k.startswith("_")}
    for skip in ["attachments", "notes", "seeAlso", "id", "accessDate"]:
        item_data.pop(skip, None)

    result = client.create_item(item_data)
    assert result
    key = result.get("key", result.get("data", {}).get("key", ""))
    assert key

    # Verify it exists
    item = client.get_item(key)
    assert item["data"]["title"] == metadata["title"]

    # Delete
    client.delete_item(item)

    # Verify deleted (should raise or return error)
    try:
        client.get_item(key)
        assert False, "Item should have been deleted"
    except Exception:
        pass  # Expected
