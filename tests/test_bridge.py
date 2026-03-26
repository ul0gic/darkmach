"""Tests for darkmach.bridge — Unix domain socket bridge client."""

from __future__ import annotations

import json
import socket
import threading

import pytest

from darkmach.bridge import format_response, parse_cli_args, send_command

# ── parse_cli_args ────────────────────────────────────────────────


class TestParseCLIArgs:
    def test_simple_command(self):
        cmd, args = parse_cli_args(["info"])
        assert cmd == "info"
        assert args is None

    def test_command_with_flag(self):
        cmd, args = parse_cli_args(["enumerate_classes", "--filter", "UIView"])
        assert cmd == "enumerate_classes"
        assert args == {"filter": "UIView"}

    def test_hex_address_parsing(self):
        cmd, args = parse_cli_args(["read_memory", "--address", "0x1234abcd", "--size", "64"])
        assert cmd == "read_memory"
        assert args["address"] == 0x1234ABCD
        assert args["size"] == 64

    def test_decimal_address(self):
        cmd, args = parse_cli_args(["read_memory", "--address", "1000", "--size", "128"])
        assert cmd == "read_memory"
        assert args["address"] == 1000
        assert args["size"] == 128

    def test_index_as_integer(self):
        cmd, args = parse_cli_args(["unhook_method", "--index", "3"])
        assert cmd == "unhook_method"
        assert args["index"] == 3

    def test_boolean_flag(self):
        cmd, args = parse_cli_args(["info", "--verbose"])
        assert cmd == "info"
        assert args == {"verbose": True}

    def test_multiple_flags(self):
        cmd, args = parse_cli_args(["get_methods", "--class", "AppDelegate", "--filter", "init"])
        assert cmd == "get_methods"
        assert args["class"] == "AppDelegate"
        assert args["filter"] == "init"

    def test_empty_args(self):
        cmd, args = parse_cli_args([])
        assert cmd is None
        assert args is None

    def test_non_flag_arguments_skipped(self):
        cmd, args = parse_cli_args(["info", "extra", "stuff"])
        assert cmd == "info"
        assert args is None

    def test_string_value_for_non_numeric_key(self):
        """Keys not in (address, size, index) should remain strings."""
        cmd, args = parse_cli_args(["heap_search", "--class", "NSObject"])
        assert cmd == "heap_search"
        assert args["class"] == "NSObject"

    def test_invalid_hex_stays_string(self):
        """If a value for --address is not valid hex/int, it stays a string."""
        cmd, args = parse_cli_args(["read_memory", "--address", "notanumber"])
        assert cmd == "read_memory"
        assert args["address"] == "notanumber"  # ValueError suppressed, stays string


# ── format_response ───────────────────────────────────────────────


class TestFormatResponse:
    def test_error_response(self):
        resp = {"ok": False, "error": "connection refused"}
        result = format_response(resp, "info")
        assert "ERROR: connection refused" in result

    def test_error_without_ok_field(self):
        resp = {"error": "something bad"}
        result = format_response(resp, "anything")
        assert "ERROR:" in result

    def test_info_command(self):
        resp = {
            "ok": True,
            "bridge": "darkmach-bridge",
            "version": "1.0",
            "appName": "TestApp",
            "appVersion": "2.0",
            "appBuild": "42",
            "bundleId": "com.test.app",
            "pid": 12345,
            "totalClasses": 500,
            "activeHooks": 3,
            "commands": ["info", "keychain_dump"],
        }
        result = format_response(resp, "info")
        assert "darkmach-bridge" in result
        assert "TestApp" in result
        assert "12345" in result
        assert "500" in result
        assert "info, keychain_dump" in result

    def test_enumerate_classes(self):
        resp = {"ok": True, "count": 3, "classes": ["NSObject", "UIView", "AppDelegate"]}
        result = format_response(resp, "enumerate_classes")
        assert "3 classes" in result
        assert "NSObject" in result
        assert "AppDelegate" in result

    def test_get_methods(self):
        resp = {
            "ok": True,
            "methods": [
                {"name": "viewDidLoad", "attributes": "void"},
                {"name": "init", "attributes": "id"},
            ],
        }
        result = format_response(resp, "get_methods")
        assert "2 methods" in result
        assert "viewDidLoad" in result

    def test_get_properties(self):
        resp = {
            "ok": True,
            "properties": [{"name": "title", "type": "NSString"}],
        }
        result = format_response(resp, "get_properties")
        assert "1 properties" in result
        assert "title" in result

    def test_get_ivars(self):
        resp = {"ok": True, "ivars": ["_name", "_age"]}
        result = format_response(resp, "get_ivars")
        assert "2 ivars" in result
        assert "_name" in result

    def test_read_property(self):
        resp = {"ok": True, "property": "title", "value": "Hello", "valueClass": "NSString"}
        result = format_response(resp, "read_property")
        assert "title" in result
        assert "Hello" in result
        assert "NSString" in result

    def test_call_method(self):
        resp = {
            "ok": True,
            "result": "42",
            "resultClass": "NSNumber",
            "resultAddress": "0x600001234",
        }
        result = format_response(resp, "call_method")
        assert "42" in result
        assert "NSNumber" in result
        assert "0x600001234" in result

    def test_call_method_without_address(self):
        resp = {"ok": True, "result": "nil", "resultClass": "NSNull"}
        result = format_response(resp, "call_method")
        assert "nil" in result
        assert "Address" not in result

    def test_keychain_dump(self):
        resp = {
            "ok": True,
            "items": [
                {"class": "genp", "data": {"service": "com.test", "account": "user1"}},
            ],
        }
        result = format_response(resp, "keychain_dump")
        assert "Keychain items: 1" in result
        assert "genp" in result

    def test_cookies_dump(self):
        resp = {
            "ok": True,
            "cookies": [
                {"name": "session", "value": "abc123", "domain": ".example.com"},
            ],
        }
        result = format_response(resp, "cookies_dump")
        assert "Cookies: 1" in result
        assert "session=abc123" in result
        assert ".example.com" in result

    def test_userdefaults_dump(self):
        resp = {
            "ok": True,
            "count": 2,
            "entries": [
                {"key": "theme", "value": "dark"},
                {"key": "onboarded", "value": True},
            ],
        }
        result = format_response(resp, "userdefaults_dump")
        assert "UserDefaults entries: 2" in result
        assert "theme: dark" in result

    def test_heap_search(self):
        resp = {
            "ok": True,
            "found": 1,
            "instances": [
                {"address": "0x600001234", "via": "scan", "description": "UIView frame=..."},
            ],
        }
        result = format_response(resp, "heap_search")
        assert "1 instances" in result
        assert "0x600001234" in result

    def test_read_memory(self):
        resp = {
            "ok": True,
            "address": "0x1000",
            "size": 4,
            "hex": "deadbeef",
            "ascii": "....",
        }
        result = format_response(resp, "read_memory")
        assert "0x1000" in result
        assert "4 bytes" in result

    def test_hook_method(self):
        resp = {"ok": True, "hooked": True, "class": "X", "method": "y"}
        result = format_response(resp, "hook_method")
        assert "hooked" in result

    def test_db_dump(self):
        resp = {
            "ok": True,
            "home": "/var/mobile",
            "databases": [
                {
                    "path": "/data/test.db",
                    "tables": [
                        {
                            "name": "users",
                            "row_count": 5,
                            "columns": [{"name": "id", "type": "INTEGER"}],
                            "rows": [{"id": 1}],
                        }
                    ],
                }
            ],
        }
        result = format_response(resp, "db_dump")
        assert "/var/mobile" in result
        assert "Databases found: 1" in result
        assert "users" in result

    def test_db_dump_with_error(self):
        resp = {
            "ok": True,
            "home": "/var/mobile",
            "databases": [{"path": "/data/locked.db", "error": "database is locked"}],
        }
        result = format_response(resp, "db_dump")
        assert "database is locked" in result

    def test_fs_scan(self):
        resp = {
            "ok": True,
            "root": "/var/mobile/Containers",
            "total_files": 10,
            "files": [
                {"type": "dir", "path": "Documents", "children": []},
                {"name": "config.json", "size": 1024},
            ],
        }
        result = format_response(resp, "fs_scan")
        assert "/var/mobile/Containers" in result
        assert "10" in result

    def test_memory_scan(self):
        resp = {
            "ok": True,
            "regions_scanned": 50,
            "match_count": 2,
            "matches": [
                {"pattern": "password", "address": "0x7000", "context": "user_password=secret"},
            ],
        }
        result = format_response(resp, "memory_scan")
        assert "50" in result
        assert "password" in result

    def test_unknown_command_dumps_json(self):
        resp = {"ok": True, "custom": "data"}
        result = format_response(resp, "unknown_future_command")
        assert '"custom": "data"' in result

    # ── Sprint 13.1: Foundation command formatters ────────────────

    # -- heap_dump --

    def test_heap_dump_empty(self):
        resp = {
            "ok": True,
            "instances": [],
            "total_scanned": 10000,
            "total_matched": 0,
            "returned": 0,
            "time_ms": 5,
        }
        result = format_response(resp, "heap_dump")
        assert "Found 0 instances" in result
        assert "scanned 10000 objects" in result
        assert "5ms" in result
        # No table header when no instances
        assert "ADDRESS" not in result

    def test_heap_dump_single_instance(self):
        resp = {
            "ok": True,
            "instances": [
                {"addr": "0x600001a000", "class": "NSString", "size": 48},
            ],
            "total_scanned": 5000,
            "total_matched": 1,
            "returned": 1,
            "time_ms": 12,
        }
        result = format_response(resp, "heap_dump")
        assert "Found 1 instances" in result
        assert "scanned 5000 objects in 12ms" in result
        assert "ADDRESS" in result
        assert "CLASS" in result
        assert "SIZE" in result
        assert "0x600001a000" in result
        assert "NSString" in result
        assert "48" in result

    def test_heap_dump_multiple_instances(self):
        resp = {
            "ok": True,
            "instances": [
                {"addr": "0x1234", "class": "NSString", "size": 48},
                {"addr": "0x5678", "class": "NSArray", "size": 64},
                {"addr": "0x9abc", "class": "NSDictionary", "size": 128},
            ],
            "total_scanned": 50000,
            "total_matched": 3,
            "returned": 3,
            "time_ms": 42,
        }
        result = format_response(resp, "heap_dump")
        assert "Found 3 instances" in result
        assert "NSString" in result
        assert "NSArray" in result
        assert "NSDictionary" in result
        # Should have table separator
        assert "-" * 68 in result

    def test_heap_dump_truncated_results(self):
        """When returned < total_matched, a 'more' hint should appear."""
        resp = {
            "ok": True,
            "instances": [
                {"addr": "0x1000", "class": "UIView", "size": 96},
            ],
            "total_scanned": 80000,
            "total_matched": 250,
            "returned": 1,
            "time_ms": 100,
        }
        result = format_response(resp, "heap_dump")
        assert "Found 250 instances" in result
        assert "249 more" in result
        assert "use offset/limit" in result

    # -- event_tap --

    def test_event_tap_enable(self):
        resp = {"ok": True, "enabled": True}
        result = format_response(resp, "event_tap")
        assert "Event tap enabled" in result
        # No filter should mean no filter text
        assert "filter:" not in result

    def test_event_tap_enable_with_filter(self):
        resp = {"ok": True, "enabled": True, "name_filter": "UIKeyboard"}
        result = format_response(resp, "event_tap")
        assert "Event tap enabled" in result
        assert "filter: UIKeyboard" in result

    def test_event_tap_disable(self):
        resp = {"ok": True, "disabled": True, "total_captured": 42}
        result = format_response(resp, "event_tap")
        assert "Event tap disabled" in result
        assert "captured 42 events" in result

    def test_event_tap_recent_empty(self):
        resp = {"ok": True, "events": [], "total_captured": 0}
        result = format_response(resp, "event_tap")
        assert "Events captured: 0" in result
        assert "showing 0" in result

    def test_event_tap_recent_populated(self):
        resp = {
            "ok": True,
            "events": [
                {
                    "timestamp": "2026-03-25T10:30:45.123Z",
                    "name": "NSApplicationDidBecomeActiveNotification",
                    "object_class": "NSApplication",
                    "user_info_keys": ["reason", "source"],
                },
                {
                    "timestamp": "2026-03-25T10:30:46.456Z",
                    "name": "UIKeyboardWillShowNotification",
                    "object_class": "",
                    "user_info_keys": [],
                },
            ],
            "total_captured": 15,
        }
        result = format_response(resp, "event_tap")
        assert "Events captured: 15 (showing 2)" in result
        assert "NSApplicationDidBecomeActiveNotification" in result
        assert "from=NSApplication" in result
        assert "keys=[reason, source]" in result
        assert "UIKeyboardWillShowNotification" in result
        # Timestamp should be truncated to HH:MM:SS.mmm
        assert "10:30:45.123" in result

    # -- env_dump --

    def test_env_dump_all_sections(self):
        resp = {
            "ok": True,
            "env": {"HOME": "/var/mobile", "PATH": "/usr/bin"},
            "args": ["/path/to/app", "-NSDocumentRevisionsDebugMode", "YES"],
            "images": [
                {"name": "FakeApp", "slide": "0x100000"},
                {"name": "UIKitCore", "slide": "0x7fff20000"},
            ],
            "fds": [
                {"fd": 0, "path": "/dev/null"},
                {"fd": 3, "path": "/data/Containers/app.db"},
            ],
            "pid": 12345,
        }
        result = format_response(resp, "env_dump")
        # Environment section
        assert "Environment Variables (2)" in result
        assert "HOME=/var/mobile" in result
        assert "PATH=/usr/bin" in result
        # Arguments section
        assert "Launch Arguments (3)" in result
        assert "/path/to/app" in result
        assert "-NSDocumentRevisionsDebugMode" in result
        # Images section
        assert "Loaded Images (2)" in result
        assert "FakeApp" in result
        assert "slide=0x100000" in result
        # FDs section
        assert "Open File Descriptors (2)" in result
        assert "fd 0" in result
        assert "/dev/null" in result
        assert "fd 3" in result
        assert "app.db" in result
        # PID
        assert "PID: 12345" in result

    def test_env_dump_empty_sections(self):
        resp = {
            "ok": True,
            "env": {},
            "args": [],
            "images": [],
            "fds": [],
        }
        result = format_response(resp, "env_dump")
        assert "Environment Variables (0)" in result
        assert "Launch Arguments (0)" in result
        assert "Loaded Images (0)" in result
        assert "Open File Descriptors (0)" in result
        # No PID when not present
        assert "PID:" not in result

    # -- db_query / db_inject --

    def test_db_query_select_results(self):
        resp = {
            "ok": True,
            "columns": ["id", "name", "email"],
            "rows": [
                [1, "Alice", "alice@example.com"],
                [2, "Bob", "bob@example.com"],
            ],
            "row_count": 2,
        }
        result = format_response(resp, "db_query")
        assert "id | name | email" in result
        assert "1 | Alice | alice@example.com" in result
        assert "2 | Bob | bob@example.com" in result
        assert "(2 rows)" in result

    def test_db_query_select_single_row(self):
        resp = {
            "ok": True,
            "columns": ["count(*)"],
            "rows": [[42]],
            "row_count": 1,
        }
        result = format_response(resp, "db_query")
        assert "count(*)" in result
        assert "42" in result
        assert "(1 row)" in result  # singular

    def test_db_query_select_empty(self):
        resp = {
            "ok": True,
            "columns": ["id", "name"],
            "rows": [],
            "row_count": 0,
        }
        result = format_response(resp, "db_query")
        assert "id | name" in result
        assert "(0 rows)" in result

    def test_db_query_select_truncated(self):
        resp = {
            "ok": True,
            "columns": ["id"],
            "rows": [[1], [2], [3]],
            "row_count": 3,
            "truncated": True,
        }
        result = format_response(resp, "db_query")
        assert "results truncated" in result

    def test_db_query_write_result(self):
        resp = {
            "ok": True,
            "affected": 5,
            "last_insert_id": 42,
        }
        result = format_response(resp, "db_query")
        assert "Affected rows: 5" in result
        assert "Last insert ID: 42" in result

    def test_db_inject_write_no_last_id(self):
        """db_inject uses the same formatter as db_query."""
        resp = {
            "ok": True,
            "affected": 1,
            "last_insert_id": 0,
        }
        result = format_response(resp, "db_inject")
        assert "Affected rows: 1" in result
        # last_insert_id=0 is falsy, so it should not appear
        assert "Last insert ID" not in result

    # -- db_queries --

    def test_db_queries_empty(self):
        resp = {"ok": True, "queries": [], "total_captured": 0}
        result = format_response(resp, "db_queries")
        assert "Intercepted queries: 0 (showing 0)" in result

    def test_db_queries_populated(self):
        resp = {
            "ok": True,
            "queries": [
                {
                    "timestamp": "2026-03-25T10:30:45.123Z",
                    "sql": "SELECT * FROM users WHERE id = ?",
                    "path": "/data/Containers/Data/app.db",
                    "duration_us": 350,
                },
                {
                    "timestamp": "2026-03-25T10:30:46.789Z",
                    "sql": "INSERT INTO logs (msg) VALUES (?)",
                    "path": "/data/Containers/Data/analytics.db",
                    "duration_us": 120,
                },
            ],
            "total_captured": 50,
        }
        result = format_response(resp, "db_queries")
        assert "Intercepted queries: 50 (showing 2)" in result
        assert "SELECT * FROM users WHERE id = ?" in result
        assert "350us" in result
        assert "app.db" in result
        assert "INSERT INTO logs" in result
        assert "analytics.db" in result
        # Timestamp truncation
        assert "10:30:45.123" in result

    # ── Sprint 13.2: Network Intelligence command formatters ──────

    # -- net_tap / net_filter --

    def test_net_tap_empty(self):
        resp = {"ok": True, "requests": [], "total_captured": 0}
        result = format_response(resp, "net_tap")
        assert "HTTP traffic: 0 captured (showing 0)" in result

    def test_net_tap_single_request(self):
        resp = {
            "ok": True,
            "requests": [
                {
                    "timestamp": "2026-03-25T14:22:01.500Z",
                    "method": "GET",
                    "url": "https://api.example.com/v1/users",
                    "status": 200,
                    "duration_ms": 150,
                },
            ],
            "total_captured": 1,
        }
        result = format_response(resp, "net_tap")
        assert "HTTP traffic: 1 captured (showing 1)" in result
        assert "GET" in result
        assert "https://api.example.com/v1/users" in result
        assert "200" in result
        assert "150ms" in result
        assert "14:22:01.500" in result

    def test_net_tap_multiple_requests(self):
        resp = {
            "ok": True,
            "requests": [
                {
                    "timestamp": "2026-03-25T14:22:01.500Z",
                    "method": "GET",
                    "url": "https://api.example.com/v1/users",
                    "status": 200,
                    "duration_ms": 150,
                },
                {
                    "timestamp": "2026-03-25T14:22:02.100Z",
                    "method": "POST",
                    "url": "https://api.example.com/v1/auth/login",
                    "status": 401,
                    "duration_ms": 80,
                },
            ],
            "total_captured": 2,
        }
        result = format_response(resp, "net_tap")
        assert "HTTP traffic: 2 captured (showing 2)" in result
        assert "GET" in result
        assert "POST" in result
        assert "200" in result
        assert "401" in result

    def test_net_tap_url_truncation(self):
        """URLs longer than 80 chars get truncated with ellipsis."""
        long_url = "https://api.example.com/v1/" + "a" * 80
        assert len(long_url) > 80  # Sanity check
        resp = {
            "ok": True,
            "requests": [
                {
                    "timestamp": "2026-03-25T14:22:01.500Z",
                    "method": "GET",
                    "url": long_url,
                    "status": 200,
                    "duration_ms": 50,
                },
            ],
            "total_captured": 1,
        }
        result = format_response(resp, "net_tap")
        # URL should be truncated to 77 chars + "..."
        assert long_url not in result
        assert "..." in result
        # The first 77 chars should be present
        assert long_url[:77] in result

    def test_net_filter_uses_same_format(self):
        """net_filter shares the same formatter as net_tap."""
        resp = {
            "ok": True,
            "requests": [
                {
                    "timestamp": "2026-03-25T14:22:01.500Z",
                    "method": "GET",
                    "url": "https://api.example.com/filtered",
                    "status": 200,
                    "duration_ms": 10,
                },
            ],
            "total_captured": 1,
        }
        result = format_response(resp, "net_filter")
        assert "HTTP traffic: 1 captured (showing 1)" in result
        assert "GET" in result
        assert "/filtered" in result

    # -- crypto_tap --

    def test_crypto_tap_empty(self):
        resp = {"ok": True, "operations": [], "total_captured": 0}
        result = format_response(resp, "crypto_tap")
        assert "Crypto operations: 0 captured (showing 0)" in result

    def test_crypto_tap_encrypt_operation(self):
        resp = {
            "ok": True,
            "operations": [
                {
                    "timestamp": "2026-03-25T14:22:01.500Z",
                    "op": "CCCrypt",
                    "algorithm": "AES-256-CBC",
                    "encrypt": True,
                    "key_hex": "deadbeef01234567890abcdef0123456",
                },
            ],
            "total_captured": 1,
        }
        result = format_response(resp, "crypto_tap")
        assert "Crypto operations: 1 captured (showing 1)" in result
        assert "CCCrypt" in result
        assert "AES-256-CBC" in result
        assert "ENC" in result
        # Key should be truncated to first 16 chars + "..."
        assert "key=deadbeef01234567..." in result

    def test_crypto_tap_decrypt_operation(self):
        resp = {
            "ok": True,
            "operations": [
                {
                    "timestamp": "2026-03-25T14:22:01.500Z",
                    "op": "CCCrypt",
                    "algorithm": "AES-128-CBC",
                    "encrypt": False,
                    "key_hex": "abcd1234",
                },
            ],
            "total_captured": 1,
        }
        result = format_response(resp, "crypto_tap")
        assert "DEC" in result
        # Short key (<=16 chars) should not be truncated
        assert "key=abcd1234" in result
        assert "..." not in result.split("key=")[1].split("\n")[0]

    # -- crypto_keys --

    def test_crypto_keys_empty(self):
        resp = {"ok": True, "keys": [], "total_unique": 0}
        result = format_response(resp, "crypto_keys")
        assert "Unique keys extracted: 0" in result
        # No table header when empty
        assert "ALGORITHM" not in result

    def test_crypto_keys_single(self):
        resp = {
            "ok": True,
            "keys": [
                {
                    "algorithm": "AES-256-CBC",
                    "key_hex": "deadbeef01234567",
                    "use_count": 5,
                    "first_seen": "2026-03-25T10:00:00Z",
                    "last_seen": "2026-03-25T10:05:00Z",
                },
            ],
            "total_unique": 1,
        }
        result = format_response(resp, "crypto_keys")
        assert "Unique keys extracted: 1" in result
        assert "ALGORITHM" in result
        assert "KEY (hex)" in result
        assert "USES" in result
        assert "AES-256-CBC" in result
        assert "deadbeef01234567" in result
        assert "5" in result
        assert "first:" in result
        assert "last:" in result

    def test_crypto_keys_long_key_truncated(self):
        """Keys longer than 36 hex chars get truncated."""
        long_key = "a" * 64
        resp = {
            "ok": True,
            "keys": [
                {
                    "algorithm": "AES-256-CBC",
                    "key_hex": long_key,
                    "use_count": 1,
                },
            ],
            "total_unique": 1,
        }
        result = format_response(resp, "crypto_keys")
        assert long_key not in result
        assert long_key[:33] + "..." in result

    # -- auth_tap --

    def test_auth_tap_empty(self):
        resp = {"ok": True, "events": [], "total_captured": 0}
        result = format_response(resp, "auth_tap")
        assert "Auth events: 0 captured (showing 0)" in result

    def test_auth_tap_oauth_event(self):
        resp = {
            "ok": True,
            "events": [
                {
                    "timestamp": "2026-03-25T14:22:01.500Z",
                    "type": "oauth_redirect",
                    "provider": "Google",
                    "url": "https://accounts.google.com/o/oauth2/auth?client_id=1234",
                    "token_preview": "",
                },
            ],
            "total_captured": 1,
        }
        result = format_response(resp, "auth_tap")
        assert "Auth events: 1 captured (showing 1)" in result
        assert "oauth_redirect" in result
        assert "provider=Google" in result
        assert "accounts.google.com" in result

    def test_auth_tap_jwt_with_claims(self):
        resp = {
            "ok": True,
            "events": [
                {
                    "timestamp": "2026-03-25T14:22:02.300Z",
                    "type": "jwt_detected",
                    "provider": "",
                    "url": "https://api.example.com/v1/me",
                    "token_preview": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOi...",
                    "claims": {"sub": "user123", "iss": "auth.example.com", "exp": 1711400000},
                },
            ],
            "total_captured": 1,
        }
        result = format_response(resp, "auth_tap")
        assert "jwt_detected" in result
        assert "token:" in result
        assert "claims:" in result
        assert "sub=user123" in result
        assert "iss=auth.example.com" in result

    def test_auth_tap_long_token_preview_truncated(self):
        """Token previews longer than 32 chars get truncated."""
        long_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.very_long_token_string_here"
        assert len(long_token) > 32  # Sanity check
        resp = {
            "ok": True,
            "events": [
                {
                    "timestamp": "2026-03-25T14:22:02.300Z",
                    "type": "bearer_token",
                    "provider": "",
                    "url": "",
                    "token_preview": long_token,
                },
            ],
            "total_captured": 1,
        }
        result = format_response(resp, "auth_tap")
        assert long_token not in result
        assert long_token[:32] + "..." in result

    # -- auth_tokens --

    def test_auth_tokens_jwt(self):
        resp = {
            "ok": True,
            "tokens": [
                {
                    "type": "JWT",
                    "value_preview": "eyJhbGciOiJSUzI1Ni...",
                    "full_value_len": 512,
                    "source": "Authorization header",
                    "claims": {"sub": "user123", "iss": "auth.example.com"},
                    "first_seen": "2026-03-25T10:00:00Z",
                    "last_seen": "2026-03-25T10:05:00Z",
                },
            ],
            "total_unique": 1,
        }
        result = format_response(resp, "auth_tokens")
        assert "Extracted tokens: 1" in result
        assert "[JWT]" in result
        assert "512 chars" in result
        assert "source: Authorization header" in result
        assert "claims:" in result
        assert "sub=user123" in result
        assert "first:" in result
        assert "last:" in result

    def test_auth_tokens_bearer(self):
        resp = {
            "ok": True,
            "tokens": [
                {
                    "type": "Bearer",
                    "value_preview": "sk_live_abc123def456",
                    "full_value_len": 20,
                    "source": "Cookie header",
                },
            ],
            "total_unique": 1,
        }
        result = format_response(resp, "auth_tokens")
        assert "Extracted tokens: 1" in result
        assert "[Bearer]" in result
        assert "sk_live_abc123def456" in result
        assert "20 chars" in result
        assert "source: Cookie header" in result
        # No claims section for bearer tokens
        assert "claims:" not in result

    def test_auth_tokens_long_preview_truncated(self):
        """Value previews longer than 40 chars get truncated."""
        long_preview = "x" * 50
        resp = {
            "ok": True,
            "tokens": [
                {
                    "type": "API_KEY",
                    "value_preview": long_preview,
                    "full_value_len": 50,
                    "source": "Query param",
                },
            ],
            "total_unique": 1,
        }
        result = format_response(resp, "auth_tokens")
        assert long_preview not in result
        assert long_preview[:37] + "..." in result

    # ── Sprint 13.3: Trace command formatters ─────────────────────

    # -- trace --

    def test_trace_hook_with_type_encoding(self):
        """trace formatter parses type encoding via typeenc.py."""
        resp = {
            "ok": True,
            "class": "AppDelegate",
            "method": "application:didFinishLaunchingWithOptions:",
            "slot": 0,
            "type_encoding": "B24@0:8@16@20",
        }
        result = format_response(resp, "trace")
        assert "Hooked -[AppDelegate application:didFinishLaunchingWithOptions:]" in result
        assert "slot 0" in result
        assert "BOOL method" in result
        # Two user args (id, id) after return/self/_cmd
        assert "2 args" in result

    def test_trace_hook_no_user_args(self):
        """Method with no user arguments (only return, self, _cmd)."""
        resp = {
            "ok": True,
            "class": "UIView",
            "method": "layoutSubviews",
            "slot": 3,
            "type_encoding": "v16@0:8",
        }
        result = format_response(resp, "trace")
        assert "Hooked -[UIView layoutSubviews]" in result
        assert "slot 3" in result
        assert "void method" in result
        assert "0 args" in result
        assert "none" in result

    def test_trace_hook_single_arg(self):
        """Singular 'arg' for 1 argument."""
        resp = {
            "ok": True,
            "class": "NSString",
            "method": "stringWithFormat:",
            "slot": 1,
            "type_encoding": "@24@0:8@16",
        }
        result = format_response(resp, "trace")
        assert "1 arg:" in result

    def test_trace_hook_empty_encoding(self):
        """When type_encoding is empty, falls back gracefully."""
        resp = {
            "ok": True,
            "class": "Unknown",
            "method": "foo",
            "slot": 5,
            "type_encoding": "",
        }
        result = format_response(resp, "trace")
        assert "Hooked -[Unknown foo]" in result
        assert "? method" in result

    # -- trace_class --

    def test_trace_class_multiple_methods(self):
        resp = {
            "ok": True,
            "class": "AppDelegate",
            "hooked": 3,
            "methods": ["viewDidLoad", "viewWillAppear:", "dealloc"],
            "skipped": 0,
        }
        result = format_response(resp, "trace_class")
        assert "Hooked 3 methods on AppDelegate" in result
        assert "viewDidLoad" in result
        assert "viewWillAppear:" in result
        assert "dealloc" in result
        assert "Skipped" not in result

    def test_trace_class_with_skipped(self):
        resp = {
            "ok": True,
            "class": "NSObject",
            "hooked": 1,
            "methods": ["init"],
            "skipped": 2,
            "skipped_reasons": ["no slots", "blacklisted"],
        }
        result = format_response(resp, "trace_class")
        assert "Hooked 1 methods on NSObject" in result
        assert "init" in result
        assert "Skipped 2" in result
        assert "no slots" in result
        assert "blacklisted" in result

    # -- trace_log --

    def test_trace_log_empty(self):
        resp = {"ok": True, "entries": [], "total_entries": 0, "returned": 0}
        result = format_response(resp, "trace_log")
        assert "Trace log: 0 total, showing 0" in result

    def test_trace_log_with_typed_args(self):
        """Verify typeenc.py integration — args rendered with type-aware display."""
        resp = {
            "ok": True,
            "entries": [
                {
                    "timestamp": "2026-03-25T10:30:45.123Z",
                    "class": "AppDelegate",
                    "method": "application:didFinishLaunchingWithOptions:",
                    "call_count": 1,
                    "duration_ns": 1500000,
                    "args": {
                        "arg0": {
                            "type": "NSApplication *",
                            "value": "<NSApplication: 0x600001234>",
                        },
                        "arg1": {"type": "NSDictionary *", "value": "{}"},
                    },
                    "return_value": {"value": 1},
                },
            ],
            "total_entries": 1,
            "returned": 1,
        }
        result = format_response(resp, "trace_log")
        assert "Trace log: 1 total, showing 1" in result
        assert "10:30:45.123" in result
        assert "-[AppDelegate application:didFinishLaunchingWithOptions:]" in result
        assert "#1" in result
        # Type-aware arg display
        assert "(NSApplication *)" in result
        assert "arg0" in result
        assert "<NSApplication: 0x600001234>" in result
        assert "(NSDictionary *)" in result
        assert "arg1" in result
        # Return value
        assert "-> 1" in result
        # Duration in ms
        assert "1.5ms" in result

    def test_trace_log_plain_arg_values(self):
        """When arg value is a plain string (not dict), display as-is."""
        resp = {
            "ok": True,
            "entries": [
                {
                    "timestamp": "2026-03-25T10:30:45.123Z",
                    "class": "UIView",
                    "method": "setFrame:",
                    "call_count": 5,
                    "duration_ns": 500000,
                    "args": {
                        "arg0": "{{0, 0}, {375, 812}}",
                    },
                    "return_value": {},
                },
            ],
            "total_entries": 5,
            "returned": 1,
        }
        result = format_response(resp, "trace_log")
        assert "arg0 = {{0, 0}, {375, 812}}" in result
        assert "-> void" in result
        assert "0.5ms" in result

    def test_trace_log_block_arg_type(self):
        """Block type args formatted as '<block at 0x...>'."""
        resp = {
            "ok": True,
            "entries": [
                {
                    "timestamp": "2026-03-25T10:30:45.123Z",
                    "class": "NSURLSession",
                    "method": "dataTaskWithRequest:completionHandler:",
                    "call_count": 1,
                    "duration_ns": 200000,
                    "args": {
                        "arg0": {"type": "NSURLRequest *", "value": "<NSURLRequest: 0xabc>"},
                        "arg1": {"type": "block", "value": "0x600009000"},
                    },
                    "return_value": {"value": "<NSURLSessionDataTask: 0xdef>"},
                },
            ],
            "total_entries": 1,
            "returned": 1,
        }
        result = format_response(resp, "trace_log")
        assert "(block)arg1 = <block at 0x600009000>" in result
        assert "(NSURLRequest *)" in result

    def test_trace_log_void_return(self):
        """Return value that is None or empty renders as void."""
        resp = {
            "ok": True,
            "entries": [
                {
                    "timestamp": "2026-03-25T10:30:45.123Z",
                    "class": "UIView",
                    "method": "layoutSubviews",
                    "call_count": 10,
                    "duration_ns": 100000,
                    "args": {},
                    "return_value": "",
                },
            ],
            "total_entries": 10,
            "returned": 1,
        }
        result = format_response(resp, "trace_log")
        assert "-> void" in result

    # -- untrace --

    def test_untrace_by_class_method(self):
        resp = {"ok": True, "class": "AppDelegate", "method": "init", "slot": 0}
        result = format_response(resp, "untrace")
        assert "Unhooked -[AppDelegate init]" in result

    def test_untrace_by_slot(self):
        resp = {"ok": True, "class": "?", "method": "?", "slot": 7}
        result = format_response(resp, "untrace")
        assert "Unhooked slot 7" in result

    def test_untrace_bare(self):
        resp = {"ok": True}
        result = format_response(resp, "untrace")
        assert "Unhooked" in result

    # ── Sprint 13.4: UI Interact + Stealth command formatters ─────

    # -- ui_tap --

    def test_ui_tap_with_label(self):
        resp = {
            "ok": True,
            "target_class": "UIButton",
            "target_label": "Submit",
            "target_frame": {"x": 100, "y": 200, "w": 80, "h": 44},
        }
        result = format_response(resp, "ui_tap")
        assert "Tapped UIButton with label 'Submit'" in result
        assert "frame=" in result

    def test_ui_tap_by_coordinates(self):
        resp = {
            "ok": True,
            "target_class": "UIView",
            "target_label": "",
            "target_frame": {"x": 150, "y": 300, "w": 50, "h": 50},
        }
        result = format_response(resp, "ui_tap")
        assert "Tapped UIView at (150, 300)" in result

    def test_ui_tap_no_frame(self):
        resp = {
            "ok": True,
            "target_class": "UISwitch",
            "target_label": "",
            "target_frame": {},
        }
        result = format_response(resp, "ui_tap")
        assert "Tapped UISwitch" in result
        assert "frame=" not in result

    # -- ui_type --

    def test_ui_type_basic(self):
        resp = {
            "ok": True,
            "field_class": "UITextField",
            "new_text": "hello@example.com",
        }
        result = format_response(resp, "ui_type")
        assert "Typed 'hello@example.com' into UITextField" in result

    def test_ui_type_with_previous(self):
        resp = {
            "ok": True,
            "field_class": "UISearchBar",
            "new_text": "darkmach",
            "previous_text": "old search",
        }
        result = format_response(resp, "ui_type")
        assert "Typed 'darkmach' into UISearchBar" in result
        assert "was: 'old search'" in result

    # -- ui_scroll --

    def test_ui_scroll_with_content_size(self):
        resp = {
            "ok": True,
            "scroll_view_class": "UITableView",
            "content_offset": {"x": 0, "y": 500},
            "content_size": {"w": 375, "h": 2000},
        }
        result = format_response(resp, "ui_scroll")
        assert "Scrolled UITableView to offset (0, 500)" in result
        assert "content size: 375 x 2000" in result

    # -- ui_back --

    def test_ui_back_pop(self):
        resp = {
            "ok": True,
            "action": "pop",
            "from_class": "DetailViewController",
            "to_class": "ListViewController",
        }
        result = format_response(resp, "ui_back")
        assert "Navigated back (pop from DetailViewController)" in result
        assert "to ListViewController" in result

    def test_ui_back_dismiss(self):
        resp = {
            "ok": True,
            "action": "dismiss",
            "from_class": "SettingsViewController",
            "to_class": "",
        }
        result = format_response(resp, "ui_back")
        assert "Dismissed SettingsViewController" in result

    def test_ui_back_no_action(self):
        resp = {"ok": True, "action": "none", "from_class": "?", "to_class": ""}
        result = format_response(resp, "ui_back")
        assert "No back action available" in result

    # -- ui_alert_dismiss --

    def test_ui_alert_dismiss_with_title_and_button(self):
        resp = {"ok": True, "title": "Delete Item?", "button": "Cancel"}
        result = format_response(resp, "ui_alert_dismiss")
        assert "Dismissed alert 'Delete Item?' via button 'Cancel'" in result

    def test_ui_alert_dismiss_title_only(self):
        resp = {"ok": True, "title": "Error", "button": ""}
        result = format_response(resp, "ui_alert_dismiss")
        assert "Dismissed alert 'Error'" in result
        assert "via button" not in result

    def test_ui_alert_dismiss_bare(self):
        resp = {"ok": True, "title": "", "button": ""}
        result = format_response(resp, "ui_alert_dismiss")
        assert result == "Dismissed alert"

    # -- stealth_scan --

    def test_stealth_scan_detections(self):
        resp = {
            "ok": True,
            "detections": [
                {
                    "technique": "jailbreak_file_check",
                    "library": "libsecurity.dylib",
                    "confidence": "high",
                    "description": "Checks for /Applications/Cydia.app",
                    "class": "JBDetector",
                    "method": "isJailbroken",
                },
                {
                    "technique": "debug_detection",
                    "library": "libprotect.dylib",
                    "confidence": "medium",
                    "description": "Uses sysctl to detect debugger",
                    "class": "",
                    "method": "",
                },
            ],
            "total_detections": 2,
            "risk_level": "high",
        }
        result = format_response(resp, "stealth_scan")
        # Table header
        assert "TECHNIQUE" in result
        assert "LIBRARY" in result
        assert "CONFIDENCE" in result
        assert "-" * 64 in result
        # First detection
        assert "jailbreak_file_check" in result
        assert "libsecurity.dylib" in result
        assert "high" in result
        assert "Checks for /Applications/Cydia.app" in result
        assert "-[JBDetector isJailbroken]" in result
        # Second detection
        assert "debug_detection" in result
        assert "libprotect.dylib" in result
        assert "medium" in result
        assert "Uses sysctl to detect debugger" in result
        # Summary
        assert "Found 2 anti-analysis techniques (risk: high)" in result

    def test_stealth_scan_empty(self):
        resp = {
            "ok": True,
            "detections": [],
            "total_detections": 0,
            "risk_level": "none",
        }
        result = format_response(resp, "stealth_scan")
        # No table header when empty
        assert "TECHNIQUE" not in result
        assert "Found 0 anti-analysis techniques (risk: none)" in result

    def test_stealth_scan_singular(self):
        """Singular 'technique' for count of 1."""
        resp = {
            "ok": True,
            "detections": [
                {
                    "technique": "hook_detection",
                    "library": "libapp.dylib",
                    "confidence": "low",
                },
            ],
            "total_detections": 1,
            "risk_level": "low",
        }
        result = format_response(resp, "stealth_scan")
        assert "Found 1 anti-analysis technique " in result
        assert "techniques" not in result

    # -- stealth_enable --

    def test_stealth_enable(self):
        resp = {
            "ok": True,
            "active_bypasses": ["jailbreak_file_check", "debug_detection", "hook_detection"],
            "total_active": 3,
        }
        result = format_response(resp, "stealth_enable")
        assert "Enabled 3 bypasses:" in result
        assert "jailbreak_file_check" in result
        assert "debug_detection" in result
        assert "hook_detection" in result

    def test_stealth_enable_singular(self):
        resp = {
            "ok": True,
            "active_bypasses": ["jailbreak_file_check"],
            "total_active": 1,
        }
        result = format_response(resp, "stealth_enable")
        assert "Enabled 1 bypass:" in result
        assert "bypasses" not in result

    # -- stealth_status --

    def test_stealth_status_table(self):
        resp = {
            "ok": True,
            "bypasses": [
                {"technique": "jailbreak", "active": True, "intercept_count": 15},
                {"technique": "debug", "active": False, "intercept_count": 0},
                {"technique": "hook", "active": True, "intercept_count": 42},
            ],
        }
        result = format_response(resp, "stealth_status")
        # Table header
        assert "TECHNIQUE" in result
        assert "ACTIVE" in result
        assert "INTERCEPTS" in result
        assert "-" * 40 in result
        # Rows
        assert "jailbreak" in result
        assert "yes" in result
        assert "15" in result
        assert "debug" in result
        assert "no" in result
        assert "hook" in result
        assert "42" in result

    def test_stealth_status_empty(self):
        resp = {"ok": True, "bypasses": []}
        result = format_response(resp, "stealth_status")
        assert "TECHNIQUE" in result
        assert "-" * 40 in result

    # ── Sprint 13.5: Deep command formatters ────────────────────────

    # -- webview_list --

    def test_webview_list_empty(self):
        resp = {"ok": True, "webviews": []}
        result = format_response(resp, "webview_list")
        assert "WebViews found: 0" in result
        assert "ADDRESS" not in result

    def test_webview_list_single(self):
        resp = {
            "ok": True,
            "webviews": [
                {
                    "address": "0x600001a000",
                    "url": "https://example.com/login",
                    "handler_count": 3,
                },
            ],
        }
        result = format_response(resp, "webview_list")
        assert "WebViews found: 1" in result
        assert "ADDRESS" in result
        assert "URL" in result
        assert "HANDLERS" in result
        assert "-" * 80 in result
        assert "0x600001a000" in result
        assert "https://example.com/login" in result
        assert "3" in result

    def test_webview_list_long_url_truncated(self):
        long_url = "https://example.com/" + "a" * 50
        resp = {
            "ok": True,
            "webviews": [
                {"address": "0x1234", "url": long_url, "handler_count": 0},
            ],
        }
        result = format_response(resp, "webview_list")
        assert "..." in result
        assert long_url not in result

    def test_webview_list_user_scripts_and_js_disabled(self):
        resp = {
            "ok": True,
            "webviews": [
                {
                    "address": "0xabc",
                    "url": "about:blank",
                    "handler_count": 0,
                    "user_scripts": 5,
                    "js_enabled": False,
                },
            ],
        }
        result = format_response(resp, "webview_list")
        assert "5 user scripts" in result
        assert "JS disabled" in result

    def test_webview_list_no_notes_when_defaults(self):
        resp = {
            "ok": True,
            "webviews": [
                {
                    "address": "0xdef",
                    "url": "https://app.io",
                    "handler_count": 1,
                    "user_scripts": 0,
                    "js_enabled": True,
                },
            ],
        }
        result = format_response(resp, "webview_list")
        assert "user scripts" not in result
        assert "JS disabled" not in result

    # -- entitlement_scan --

    def test_entitlement_scan_basic(self):
        resp = {
            "ok": True,
            "total_entitlements": 3,
            "risk_count": 1,
            "images": [
                {
                    "name": "FakeApp",
                    "entitlements": {
                        "com.apple.security.app-sandbox": True,
                        "com.apple.developer.team-identifier": "ABC123",
                        "com.apple.security.network.client": True,
                    },
                    "risks": [
                        {
                            "level": "HIGH",
                            "description": "App has unrestricted network client access",
                        },
                    ],
                },
            ],
        }
        result = format_response(resp, "entitlement_scan")
        assert "Scanned 1 images" in result
        assert "3 entitlements (1 flagged)" in result
        assert "=== FakeApp (3 entitlements) ===" in result
        assert "com.apple.security.app-sandbox: True" in result
        assert "com.apple.developer.team-identifier: ABC123" in result
        assert "** HIGH: App has unrestricted network client access" in result

    def test_entitlement_scan_no_risks(self):
        resp = {
            "ok": True,
            "total_entitlements": 1,
            "risk_count": 0,
            "images": [
                {
                    "name": "SafeLib",
                    "entitlements": {"com.apple.security.app-sandbox": True},
                    "risks": [],
                },
            ],
        }
        result = format_response(resp, "entitlement_scan")
        assert "0 flagged" in result
        assert "**" not in result

    def test_entitlement_scan_list_value_formatting(self):
        resp = {
            "ok": True,
            "total_entitlements": 1,
            "risk_count": 0,
            "images": [
                {
                    "name": "MultiApp",
                    "entitlements": {
                        "com.apple.developer.associated-domains": [
                            "applinks:example.com",
                            "webcredentials:example.com",
                        ],
                    },
                    "risks": [],
                },
            ],
        }
        result = format_response(resp, "entitlement_scan")
        assert "applinks:example.com, webcredentials:example.com" in result

    def test_entitlement_scan_long_value_truncated(self):
        long_val = ", ".join(f"item{i}" for i in range(100))
        resp = {
            "ok": True,
            "total_entitlements": 1,
            "risk_count": 0,
            "images": [
                {
                    "name": "BigApp",
                    "entitlements": {"some.key": long_val},
                    "risks": [],
                },
            ],
        }
        result = format_response(resp, "entitlement_scan")
        assert "..." in result

    # -- pin_analyze --

    def test_pin_analyze_empty(self):
        resp = {
            "ok": True,
            "data": {
                "evaluations": [],
                "total_captured": 0,
                "returned": 0,
                "pinned_hosts": [],
                "trustkit": {"detected": False},
                "ats": {"configured": False},
            },
        }
        result = format_response(resp, "pin_analyze")
        assert "Trust evaluations: 0 captured (showing 0)" in result
        assert "HOST" not in result
        assert "TrustKit: not detected" in result
        assert "ATS: not configured" in result

    def test_pin_analyze_with_evaluations(self):
        resp = {
            "ok": True,
            "data": {
                "evaluations": [
                    {
                        "host": "api.example.com",
                        "trusted": True,
                        "bypassed": False,
                        "cert_count": 2,
                        "certs": [
                            {
                                "subject": "CN=api.example.com",
                                "pubkey_sha256": "abcdef1234567890abcdef1234567890",
                            },
                        ],
                    },
                ],
                "total_captured": 5,
                "returned": 1,
                "pinned_hosts": ["api.example.com"],
                "trustkit": {"detected": False},
                "ats": {"configured": False},
            },
        }
        result = format_response(resp, "pin_analyze")
        assert "Trust evaluations: 5 captured (showing 1)" in result
        assert "HOST" in result
        assert "TRUSTED" in result
        assert "BYPASS" in result
        assert "CERTS" in result
        assert "-" * 54 in result
        assert "api.example.com" in result
        assert "yes" in result  # trusted
        assert "CN=api.example.com" in result
        assert "key=abcdef1234567890..." in result
        assert "Pinned hosts (1):" in result

    def test_pin_analyze_bypass_shown(self):
        resp = {
            "ok": True,
            "data": {
                "evaluations": [
                    {
                        "host": "pinned.io",
                        "trusted": False,
                        "bypassed": True,
                        "cert_count": 1,
                        "certs": [],
                    },
                ],
                "total_captured": 1,
                "returned": 1,
                "pinned_hosts": [],
                "trustkit": {"detected": False},
                "ats": {"configured": False},
            },
        }
        result = format_response(resp, "pin_analyze")
        assert "YES" in result  # bypassed uppercase
        # trusted should be "no"
        lines = result.split("\n")
        data_line = next(line for line in lines if "pinned.io" in line)
        assert "no" in data_line

    def test_pin_analyze_trustkit_detected(self):
        resp = {
            "ok": True,
            "data": {
                "evaluations": [],
                "total_captured": 0,
                "returned": 0,
                "pinned_hosts": [],
                "trustkit": {
                    "detected": True,
                    "validator": "TrustKitPinValidator",
                },
                "ats": {"configured": False},
            },
        }
        result = format_response(resp, "pin_analyze")
        assert "TrustKit: detected" in result
        assert "validator: TrustKitPinValidator" in result

    def test_pin_analyze_ats_configured(self):
        resp = {
            "ok": True,
            "data": {
                "evaluations": [],
                "total_captured": 0,
                "returned": 0,
                "pinned_hosts": [],
                "trustkit": {"detected": False},
                "ats": {
                    "configured": True,
                    "allows_arbitrary_loads": True,
                    "allows_arbitrary_loads_web": False,
                    "exception_domains": [
                        {
                            "domain": "legacy.example.com",
                            "allows_insecure_http": True,
                            "includes_subdomains": True,
                            "min_tls_version": "1.0",
                        },
                    ],
                },
            },
        }
        result = format_response(resp, "pin_analyze")
        assert "ATS: configured (allows arbitrary loads)" in result
        assert "legacy.example.com" in result
        assert "insecure HTTP" in result
        assert "incl. subdomains" in result
        assert "TLS>=1.0" in result

    def test_pin_analyze_long_host_truncated(self):
        long_host = "a" * 30 + ".example.com"
        resp = {
            "ok": True,
            "data": {
                "evaluations": [
                    {
                        "host": long_host,
                        "trusted": True,
                        "bypassed": False,
                        "cert_count": 0,
                        "certs": [],
                    },
                ],
                "total_captured": 1,
                "returned": 1,
                "pinned_hosts": [],
                "trustkit": {"detected": False},
                "ats": {"configured": False},
            },
        }
        result = format_response(resp, "pin_analyze")
        assert "..." in result
        assert long_host not in result

    # -- inject_class --

    def test_inject_class_basic(self):
        resp = {
            "ok": True,
            "name": "DarkmachProxy",
            "superclass": "NSObject",
            "protocols": [],
            "class_address": "0x600002a000",
        }
        result = format_response(resp, "inject_class")
        assert "Created class: DarkmachProxy : NSObject" in result
        assert "address: 0x600002a000" in result
        assert "protocols" not in result

    def test_inject_class_with_protocols(self):
        resp = {
            "ok": True,
            "name": "DarkmachDelegate",
            "superclass": "UIResponder",
            "protocols": ["UIApplicationDelegate", "NSCoding"],
            "class_address": "0x7000abc",
        }
        result = format_response(resp, "inject_class")
        assert "Created class: DarkmachDelegate : UIResponder" in result
        assert "protocols: UIApplicationDelegate, NSCoding" in result
        assert "address: 0x7000abc" in result

    def test_inject_class_defaults(self):
        """When superclass is omitted, defaults to NSObject."""
        resp = {"ok": True, "name": "TestClass", "class_address": "0x999"}
        result = format_response(resp, "inject_class")
        assert "Created class: TestClass : NSObject" in result

    def test_view_hierarchy(self):
        resp = {
            "ok": True,
            "views": [
                {
                    "class": "UIWindow",
                    "frame": {"x": 0, "y": 0, "w": 375, "h": 812},
                    "hidden": False,
                    "subviews": [
                        {
                            "class": "UILabel",
                            "frame": {"x": 10, "y": 20, "w": 100, "h": 30},
                            "text": "Hello",
                            "accessibilityLabel": "greeting",
                            "subviews": [],
                        }
                    ],
                }
            ],
        }
        result = format_response(resp, "view_hierarchy")
        assert "UIWindow" in result
        assert "UILabel" in result
        assert "Hello" in result
        assert "greeting" in result


# ── send_command ──────────────────────────────────────────────────


class TestSendCommand:
    """Test send_command with a real Unix domain socket (in-process fake server)."""

    @pytest.fixture(autouse=True)
    def _short_sock_dir(self, tmp_path):
        """Use a short /tmp path for sockets to avoid AF_UNIX 104-char limit on macOS."""
        import tempfile

        self._sock_dir = tempfile.mkdtemp(prefix="spx", dir="/tmp")
        yield
        import shutil

        shutil.rmtree(self._sock_dir, ignore_errors=True)

    def _sock_path(self, name="test.sock"):
        from pathlib import Path

        return str(Path(self._sock_dir) / name)

    def _make_server(self, response_data, name="test.sock"):
        """Create a fake UDS server that echoes a canned JSON response."""
        sock_path = self._sock_path(name)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(1)

        def handle():
            conn, _ = server.accept()
            # Read the incoming request
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            # Send response
            response_bytes = (json.dumps(response_data) + "\n").encode()
            conn.sendall(response_bytes)
            conn.close()
            server.close()

        t = threading.Thread(target=handle, daemon=True)
        t.start()
        return sock_path, t

    def test_send_command_success(self):
        response = {"ok": True, "bridge": "test", "version": "0.1"}
        sock_path, thread = self._make_server(response)

        result = send_command("info", socket_path=sock_path)
        thread.join(timeout=5)

        assert result["ok"] is True
        assert result["bridge"] == "test"

    def test_send_command_with_args(self):
        response = {"ok": True, "classes": ["NSObject"]}
        sock_path, thread = self._make_server(response, name="args.sock")

        result = send_command("enumerate_classes", args={"filter": "NS"}, socket_path=sock_path)
        thread.join(timeout=5)

        assert result["ok"] is True
        assert "NSObject" in result["classes"]

    def test_send_command_connection_refused(self):
        """If the socket does not exist, send_command returns an error dict."""
        nonexistent = self._sock_path("nonexistent.sock")
        result = send_command("info", socket_path=nonexistent)
        assert result["ok"] is False
        assert "Cannot connect" in result["error"]

    def test_send_command_empty_response(self):
        """If the server closes without sending data, we get an error."""
        sock_path = self._sock_path("empty.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(1)

        def handle():
            conn, _ = server.accept()
            conn.recv(4096)
            conn.close()
            server.close()

        t = threading.Thread(target=handle, daemon=True)
        t.start()

        result = send_command("info", socket_path=sock_path)
        t.join(timeout=5)
        assert result["ok"] is False
        assert "No response" in result["error"]

    def test_send_command_invalid_json(self):
        """If the server sends invalid JSON, we get an error with raw preview."""
        sock_path = self._sock_path("bad.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(1)

        def handle():
            conn, _ = server.accept()
            conn.recv(4096)
            conn.sendall(b"this is not json\n")
            conn.close()
            server.close()

        t = threading.Thread(target=handle, daemon=True)
        t.start()

        result = send_command("info", socket_path=sock_path)
        t.join(timeout=5)
        assert result["ok"] is False
        assert "Invalid JSON" in result["error"]
        assert "raw" in result

    def test_send_command_increments_request_id(self):
        """Each call should use an incrementing request ID."""
        captured_requests = []

        response = {"ok": True}
        sock_path = self._sock_path("id1.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(2)

        def handle():
            for _ in range(2):
                conn, _ = server.accept()
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in data:
                        break
                captured_requests.append(json.loads(data.decode()))
                conn.sendall((json.dumps(response) + "\n").encode())
                conn.close()
            server.close()

        t = threading.Thread(target=handle, daemon=True)
        t.start()

        send_command("info", socket_path=sock_path)
        send_command("info", socket_path=sock_path)
        t.join(timeout=5)

        assert len(captured_requests) == 2
        assert captured_requests[1]["id"] > captured_requests[0]["id"]
