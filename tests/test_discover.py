"""Tests for darkmach.discover — App Store discovery and amp-api compatibility checks."""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import patch

import pytest

import darkmach.discover as discover_mod
from darkmach.discover import (
    CATEGORIES,
    STATUS_LABELS,
    check_mac_compatible,
    check_token,
    itunes_lookup,
    itunes_search,
    itunes_top_free,
    save_results,
    set_token,
)

# ── Helpers ───────────────────────────────────────────────────────


def _make_jwt(payload: dict) -> str:
    """Build a minimal 3-part JWT with the given payload dict."""
    header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


# ── check_token ───────────────────────────────────────────────────


class TestCheckToken:
    def test_valid_token(self):
        future_exp = int(time.time()) + 86400 * 365  # 1 year from now
        token = _make_jwt({"iss": "test", "exp": future_exp})
        original = discover_mod.TOKEN
        try:
            discover_mod.TOKEN = token
            assert check_token() is True
        finally:
            discover_mod.TOKEN = original

    def test_expired_token(self):
        past_exp = int(time.time()) - 86400  # yesterday
        token = _make_jwt({"iss": "test", "exp": past_exp})
        original = discover_mod.TOKEN
        try:
            discover_mod.TOKEN = token
            assert check_token() is False
        finally:
            discover_mod.TOKEN = original

    def test_token_expiring_soon_still_valid(self, capsys):
        """Token with <30 days left should return True but print a note."""
        exp = int(time.time()) + 86400 * 15  # 15 days from now
        token = _make_jwt({"iss": "test", "exp": exp})
        original = discover_mod.TOKEN
        try:
            discover_mod.TOKEN = token
            assert check_token() is True
            captured = capsys.readouterr()
            assert "expires in" in captured.out.lower()
        finally:
            discover_mod.TOKEN = original

    def test_malformed_token(self):
        original = discover_mod.TOKEN
        try:
            discover_mod.TOKEN = "not-a-jwt"
            assert check_token() is False
        finally:
            discover_mod.TOKEN = original

    def test_token_with_missing_exp(self):
        token = _make_jwt({"iss": "test"})  # no exp field
        original = discover_mod.TOKEN
        try:
            discover_mod.TOKEN = token
            assert check_token() is False
        finally:
            discover_mod.TOKEN = original


# ── set_token ─────────────────────────────────────────────────────


class TestSetToken:
    def test_set_token_overrides_module_global(self):
        original = discover_mod.TOKEN
        try:
            set_token("my-custom-token")
            assert discover_mod.TOKEN == "my-custom-token"
        finally:
            discover_mod.TOKEN = original


# ── itunes_search ─────────────────────────────────────────────────


class TestItunesSearch:
    def test_basic_search(self):
        mock_response = {
            "resultCount": 2,
            "results": [
                {
                    "trackId": 123,
                    "trackName": "TestApp",
                    "bundleId": "com.test.app",
                    "primaryGenreName": "Utilities",
                    "kind": "software",
                },
                {
                    "trackId": 456,
                    "trackName": "OtherApp",
                    "bundleId": "com.test.other",
                    "primaryGenreName": "Games",
                    "kind": "software",
                },
            ],
        }
        with patch("darkmach.discover._get", return_value=mock_response):
            results = itunes_search("test")

        assert len(results) == 2
        assert results[0]["id"] == "123"
        assert results[0]["name"] == "TestApp"
        assert results[0]["bundle"] == "com.test.app"
        assert results[0]["category"] == "Utilities"

    def test_filters_non_software(self):
        """Only results with kind containing 'software' (case-sensitive) are returned."""
        mock_response = {
            "results": [
                {"trackId": 1, "trackName": "App", "kind": "software", "bundleId": "x"},
                {"trackId": 2, "trackName": "Song", "kind": "song", "bundleId": "y"},
                {"trackId": 3, "trackName": "iPad", "kind": "iPadSoftware", "bundleId": "z"},
            ]
        }
        with patch("darkmach.discover._get", return_value=mock_response):
            results = itunes_search("mixed")

        # "iPadSoftware" does NOT contain lowercase "software" — only trackId=1 matches
        assert len(results) == 1
        assert results[0]["id"] == "1"

    def test_returns_empty_on_api_failure(self):
        with patch("darkmach.discover._get", return_value=None):
            results = itunes_search("anything")
        assert results == []

    def test_returns_empty_on_no_results(self):
        with patch("darkmach.discover._get", return_value={"results": []}):
            results = itunes_search("nonexistent")
        assert results == []


# ── itunes_top_free ───────────────────────────────────────────────


class TestItunesTopFree:
    def test_parses_rss_feed(self):
        mock_response = {
            "feed": {
                "entry": [
                    {
                        "id": {"attributes": {"im:id": "111", "im:bundleId": "com.a.b"}},
                        "im:name": {"label": "TopApp"},
                        "category": {"attributes": {"label": "Games"}},
                    }
                ]
            }
        }
        with patch("darkmach.discover._get", return_value=mock_response):
            results = itunes_top_free(6014)

        assert len(results) == 1
        assert results[0]["id"] == "111"
        assert results[0]["name"] == "TopApp"
        assert results[0]["bundle"] == "com.a.b"
        assert results[0]["category"] == "Games"

    def test_returns_empty_on_failure(self):
        with patch("darkmach.discover._get", return_value=None):
            results = itunes_top_free(6001)
        assert results == []

    def test_returns_empty_on_missing_feed(self):
        with patch("darkmach.discover._get", return_value={}):
            results = itunes_top_free(6001)
        assert results == []


# ── itunes_lookup ─────────────────────────────────────────────────


class TestItunesLookup:
    def test_lookup_by_ids(self):
        mock_response = {
            "results": [
                {
                    "trackId": 999,
                    "trackName": "LookupApp",
                    "bundleId": "com.lookup",
                    "primaryGenreName": "Finance",
                }
            ]
        }
        with patch("darkmach.discover._get", return_value=mock_response):
            results = itunes_lookup(["999"])

        assert len(results) == 1
        assert results[0]["name"] == "LookupApp"

    def test_returns_empty_on_failure(self):
        with patch("darkmach.discover._get", return_value=None):
            assert itunes_lookup(["1", "2"]) == []


# ── check_mac_compatible ─────────────────────────────────────────


class TestCheckMacCompatible:
    def _make_app(self, app_id="100"):
        return {"id": app_id, "name": "TestApp", "bundle": "com.test", "category": "Utilities"}

    def test_available_status(self):
        """iOS binary compatible with Mac should return status=available."""
        api_resp = {
            "data": [
                {
                    "attributes": {
                        "deviceFamilies": ["iphone", "ipad"],
                        "isIOSBinaryMacOSCompatible": True,
                        "fileSizeByDevice": {"Universal_Mac": 52428800},
                    }
                }
            ]
        }
        with patch("darkmach.discover._get", return_value=api_resp):
            result = check_mac_compatible(self._make_app())

        assert result["status"] == "available"
        assert result["size_mb"] == pytest.approx(50.0, abs=0.1)

    def test_opted_out_status(self):
        """Mac sizes present but not compatible should return opted_out."""
        api_resp = {
            "data": [
                {
                    "attributes": {
                        "deviceFamilies": ["iphone"],
                        "isIOSBinaryMacOSCompatible": False,
                        "fileSizeByDevice": {"Universal_Mac": 10485760},
                    }
                }
            ]
        }
        with patch("darkmach.discover._get", return_value=api_resp):
            result = check_mac_compatible(self._make_app())

        assert result["status"] == "opted_out"

    def test_native_mac_status(self):
        """Apps with 'mac' in deviceFamilies are native Mac apps."""
        api_resp = {
            "data": [
                {
                    "attributes": {
                        "deviceFamilies": ["iphone", "mac"],
                        "isIOSBinaryMacOSCompatible": False,
                        "fileSizeByDevice": {},
                    }
                }
            ]
        }
        with patch("darkmach.discover._get", return_value=api_resp):
            result = check_mac_compatible(self._make_app())

        assert result["status"] == "native_mac"

    def test_unavailable_status(self):
        """No Mac sizes and not compatible should return unavailable."""
        api_resp = {
            "data": [
                {
                    "attributes": {
                        "deviceFamilies": ["iphone"],
                        "isIOSBinaryMacOSCompatible": False,
                        "fileSizeByDevice": {"Universal": 5000000},
                    }
                }
            ]
        }
        with patch("darkmach.discover._get", return_value=api_resp):
            result = check_mac_compatible(self._make_app())

        assert result["status"] == "unavailable"

    def test_error_on_api_failure(self):
        with patch("darkmach.discover._get", return_value=None):
            result = check_mac_compatible(self._make_app())

        assert result["status"] == "error"
        assert "error" in result

    def test_error_on_empty_data(self):
        with patch("darkmach.discover._get", return_value={"data": []}):
            result = check_mac_compatible(self._make_app())

        assert result["status"] == "error"

    def test_preserves_app_info(self):
        api_resp = {
            "data": [
                {
                    "attributes": {
                        "deviceFamilies": [],
                        "isIOSBinaryMacOSCompatible": False,
                        "fileSizeByDevice": {},
                    }
                }
            ]
        }
        with patch("darkmach.discover._get", return_value=api_resp):
            result = check_mac_compatible(self._make_app("777"))

        assert result["id"] == "777"
        assert result["name"] == "TestApp"
        assert result["bundle"] == "com.test"


# ── save_results ──────────────────────────────────────────────────


class TestSaveResults:
    def test_saves_json_file(self, tmp_path):
        outfile = tmp_path / "results.json"
        results = [
            {"id": "1", "name": "App1", "status": "available"},
            {"id": "2", "name": "App2", "status": "opted_out"},
        ]
        save_results(results, outfile)

        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert data["available_count"] == 1
        assert data["opted_out_count"] == 1
        assert data["total_checked"] == 2

    def test_deduplicates_by_id(self, tmp_path):
        outfile = tmp_path / "dedup.json"
        results = [
            {"id": "1", "name": "App", "status": "available"},
            {"id": "1", "name": "App", "status": "available"},
            {"id": "2", "name": "Other", "status": "error"},
        ]
        save_results(results, outfile)

        data = json.loads(outfile.read_text())
        assert data["total_checked"] == 2

    def test_creates_parent_dirs(self, tmp_path):
        outfile = tmp_path / "deep" / "nested" / "results.json"
        save_results([{"id": "1", "name": "X", "status": "available"}], outfile)
        assert outfile.exists()


# ── STATUS_LABELS / display helpers ───────────────────────────────


class TestStatusLabels:
    def test_all_statuses_have_labels(self):
        for status in ("available", "opted_out", "native_mac", "unavailable", "error"):
            assert status in STATUS_LABELS

    def test_categories_dict_populated(self):
        assert len(CATEGORIES) > 10
        assert 6014 in CATEGORIES  # Games
        assert CATEGORIES[6014] == "Games"
