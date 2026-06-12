"""Shared test configuration and fixtures."""

import os
import sys
import json
import pytest

# Add skill root to path so lib is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def pytest_addoption(parser):
    parser.addoption("--live", action="store_true", default=False, help="Run live integration tests")


def pytest_configure(config):
    config.addinivalue_line("markers", "live: mark test as requiring live credentials and network")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--live"):
        skip_live = pytest.mark.skip(reason="Need --live flag to run")
        for item in items:
            if "live" in item.keywords:
                item.add_marker(skip_live)


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def test_config():
    """Config dict for testing — no real credentials."""
    return {
        "zotero_user_id": "000000",
        "ZOTERO_API_KEY": "fake_test_key",
        "translation_server": "http://localhost:1969",
        "zotfile_pattern": "{author}_{year}_{title}",
        "default_collection": "",
        "auto_catalog_threshold": 80,
        "cache_max_age_hours": 24,
        "workspace": "/tmp/zot_test_workspace",
        "staging_dir": "/tmp/zot_test_workspace/staging",
    }
