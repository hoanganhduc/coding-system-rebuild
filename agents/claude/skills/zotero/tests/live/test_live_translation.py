"""Live integration test — Translation Server metadata fetch."""

import pytest
from lib.config import load_config
from lib.metadata import fetch_metadata


@pytest.mark.live
def test_fetch_doi():
    config = load_config()
    meta, itype, norm = fetch_metadata("10.4230/LIPIcs.FSTTCS.2025.31",
                                        config.get("translation_server"))
    assert itype == "doi"
    assert meta["title"]
    assert meta.get("DOI")
    assert len(meta.get("creators", [])) > 0


@pytest.mark.live
def test_fetch_arxiv():
    config = load_config()
    meta, itype, norm = fetch_metadata("2301.12345",
                                        config.get("translation_server"))
    assert itype == "arxiv"
    assert meta["title"]
    assert meta["itemType"] == "manuscript"  # arXiv → manuscript


@pytest.mark.live
def test_fetch_url():
    config = load_config()
    meta, itype, norm = fetch_metadata("https://arxiv.org/abs/2301.12345",
                                        config.get("translation_server"))
    assert itype == "arxiv"
    assert meta["title"]
