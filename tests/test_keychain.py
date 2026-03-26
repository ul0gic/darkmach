"""Tests for darkmach.keychain — Simulator keychain SQLite reader."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from darkmach.keychain import (
    apple_timestamp_to_str,
    decode_blob,
    find_keychain_db,
    read_keychain,
)

if TYPE_CHECKING:
    from pathlib import Path

# ── apple_timestamp_to_str ────────────────────────────────────────


class TestAppleTimestampToStr:
    def test_zero_returns_none(self):
        assert apple_timestamp_to_str(0) is None

    def test_none_returns_none(self):
        assert apple_timestamp_to_str(None) is None

    def test_known_timestamp(self):
        """Apple epoch is 2001-01-01 00:00:00 UTC. Timestamp 0 = that date."""
        # 1 day = 86400 seconds after Apple epoch = 2001-01-02
        result = apple_timestamp_to_str(86400)
        assert result is not None
        assert "2001-01-02" in result

    def test_recent_timestamp(self):
        """A timestamp in 2024 should produce a reasonable date string."""
        # About 23 years worth of seconds from Apple epoch
        ts = 23 * 365.25 * 86400  # ~2024
        result = apple_timestamp_to_str(ts)
        assert result is not None
        assert result.startswith("202")

    def test_format_is_datetime_string(self):
        result = apple_timestamp_to_str(86400)
        assert result is not None
        # Should be YYYY-MM-DD HH:MM:SS format
        parts = result.split(" ")
        assert len(parts) == 2
        assert len(parts[0].split("-")) == 3
        assert len(parts[1].split(":")) == 3


# ── decode_blob ───────────────────────────────────────────────────


class TestDecodeBlob:
    def test_none_returns_none(self):
        assert decode_blob(None) is None

    def test_string_passthrough(self):
        assert decode_blob("hello") == "hello"

    def test_utf8_bytes(self):
        result = decode_blob(b"hello world")
        assert result == "hello world"

    def test_short_non_utf8_bytes_as_hex(self):
        """Bytes that fail UTF-8 decoding and plist parsing should return hex."""
        # Use bytes that are invalid UTF-8 (0x80-0xFF without proper leading bytes)
        data = bytes(
            [
                0x80,
                0x81,
                0x82,
                0x83,
                0xFE,
                0xFF,
                0x90,
                0xA0,
                0xB0,
                0xC0,
                0xD0,
                0xE0,
                0xF0,
                0xF8,
                0xFC,
                0xFD,
            ]
        )
        result = decode_blob(data)
        assert result == data.hex()

    def test_long_non_utf8_bytes_truncated(self):
        data = bytes(range(256)) * 2  # 512 bytes, non-printable
        result = decode_blob(data)
        assert "bytes)" in result
        assert "512" in result

    def test_plist_bytes_decoded(self):
        """Binary plist data should be decoded via plistlib."""
        import plistlib

        plist_data = plistlib.dumps({"key": "value"})
        result = decode_blob(plist_data)
        assert "key" in result
        assert "value" in result

    def test_non_string_non_bytes(self):
        assert decode_blob(42) == "42"
        assert decode_blob(3.14) == "3.14"


# ── find_keychain_db ──────────────────────────────────────────────


class TestFindKeychainDb:
    def test_returns_path_when_db_exists(self, tmp_path, monkeypatch):
        """Simulate the keychain db path existing."""
        fake_udid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        db_dir = tmp_path / fake_udid / "data" / "Library" / "Keychains"
        db_dir.mkdir(parents=True)
        db_file = db_dir / "keychain-2-debug.db"
        db_file.write_bytes(b"")

        # Monkeypatch SIMDEVICES_DIR to point to tmp_path
        monkeypatch.setattr("darkmach.keychain.SIMDEVICES_DIR", tmp_path)

        result = find_keychain_db(fake_udid)
        assert result is not None
        assert result == db_file

    def test_returns_none_when_db_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("darkmach.keychain.SIMDEVICES_DIR", tmp_path)
        result = find_keychain_db("nonexistent-udid")
        assert result is None


# ── read_keychain ─────────────────────────────────────────────────


class TestReadKeychain:
    def _create_test_db(self, db_path: Path) -> None:
        """Create a minimal keychain SQLite database for testing."""
        conn = sqlite3.connect(str(db_path))
        # Create genp (Generic Passwords) table
        conn.execute(
            """
            CREATE TABLE genp (
                svce TEXT,
                acct TEXT,
                agrp TEXT,
                labl TEXT,
                gena TEXT,
                pdmn TEXT,
                sync INTEGER,
                cdat REAL,
                mdat REAL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO genp (svce, acct, agrp, labl, pdmn, sync, cdat)
            VALUES ('com.test.service', 'testuser', 'group1', 'Test Label', 'ak', 0, 694224000)
            """
        )
        # Create inet (Internet Passwords) table
        conn.execute(
            """
            CREATE TABLE inet (
                srvr TEXT,
                acct TEXT,
                agrp TEXT,
                port INTEGER,
                ptcl TEXT,
                pdmn TEXT,
                sync INTEGER,
                cdat REAL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO inet (srvr, acct, agrp, port, ptcl, pdmn, sync)
            VALUES ('example.com', 'user@example.com', 'group2', 443, 'htps', 'ak', 1)
            """
        )
        conn.commit()
        conn.close()

    def test_reads_generic_passwords(self, tmp_path):
        db_path = tmp_path / "keychain.db"
        self._create_test_db(db_path)

        results = read_keychain(db_path)

        assert "genp" in results["tables"]
        genp = results["tables"]["genp"]
        assert genp["label"] == "Generic Passwords"
        assert genp["count"] == 1
        entry = genp["entries"][0]
        assert entry["Service"] == "com.test.service"
        assert entry["Account"] == "testuser"

    def test_reads_internet_passwords(self, tmp_path):
        db_path = tmp_path / "keychain.db"
        self._create_test_db(db_path)

        results = read_keychain(db_path)

        assert "inet" in results["tables"]
        inet = results["tables"]["inet"]
        assert inet["label"] == "Internet Passwords"
        assert inet["count"] == 1
        entry = inet["entries"][0]
        assert entry["Server"] == "example.com"
        assert entry["Account"] == "user@example.com"

    def test_returns_path_in_results(self, tmp_path):
        db_path = tmp_path / "keychain.db"
        self._create_test_db(db_path)

        results = read_keychain(db_path)
        assert str(db_path) in results["path"]

    def test_handles_missing_tables_gracefully(self, tmp_path):
        """If a table doesn't exist, it should be skipped without error."""
        db_path = tmp_path / "minimal.db"
        conn = sqlite3.connect(str(db_path))
        # Only create genp, skip inet/cert/keys
        conn.execute("CREATE TABLE genp (svce TEXT, acct TEXT)")
        conn.execute("INSERT INTO genp (svce, acct) VALUES ('svc', 'usr')")
        conn.commit()
        conn.close()

        results = read_keychain(db_path)
        assert "genp" in results["tables"]
        # inet, cert, keys should just not appear (no error)
        assert results["tables"]["genp"]["count"] == 1

    def test_empty_database(self, tmp_path):
        """A database with tables but no rows should return empty entries."""
        db_path = tmp_path / "empty.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE genp (svce TEXT, acct TEXT)")
        conn.commit()
        conn.close()

        results = read_keychain(db_path)
        assert results["tables"]["genp"]["count"] == 0
        assert results["tables"]["genp"]["entries"] == []

    def test_json_output_mode(self, tmp_path, capsys):
        db_path = tmp_path / "keychain.db"
        self._create_test_db(db_path)

        read_keychain(db_path, as_json=True)
        captured = capsys.readouterr()

        import json

        data = json.loads(captured.out)
        assert "tables" in data
        assert "genp" in data["tables"]

    def test_text_output_mode(self, tmp_path, capsys):
        db_path = tmp_path / "keychain.db"
        self._create_test_db(db_path)

        read_keychain(db_path, as_json=False)
        captured = capsys.readouterr()

        assert "Generic Passwords" in captured.out
        assert "com.test.service" in captured.out

    def test_apple_timestamp_decoded_in_entries(self, tmp_path):
        """cdat/mdat fields with numeric values should be converted to date strings."""
        db_path = tmp_path / "ts.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE genp (svce TEXT, cdat REAL, mdat REAL)")
        # 694224000 seconds after Apple epoch (2001-01-01) = ~2023
        conn.execute("INSERT INTO genp (svce, cdat, mdat) VALUES ('svc', 694224000, 694224000)")
        conn.commit()
        conn.close()

        results = read_keychain(db_path)
        entry = results["tables"]["genp"]["entries"][0]
        # The Created/Modified fields should be date strings, not raw numbers
        created = entry.get("Created")
        assert created is not None
        assert "2023" in str(created) or "2022" in str(created)
