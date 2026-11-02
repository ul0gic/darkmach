"""Tests for darkmach.hermes — Hermes bytecode extraction and secret scanning."""

from __future__ import annotations

import re

from darkmach.analysis.hermes import (
    HERMES_MAGIC,
    INTERESTING_PREFIXES,
    SECRET_PATTERNS,
    extract_strings_from_binary,
    extract_strings_from_js,
    find_js_bundles,
    is_hermes_bytecode,
    scan_strings_for_secrets,
)

# ── is_hermes_bytecode ────────────────────────────────────────────


class TestIsHermesBytecode:
    def test_valid_hermes_magic(self, tmp_path):
        hbc = tmp_path / "main.jsbundle"
        hbc.write_bytes(HERMES_MAGIC + b"\x90" + b"\x00" * 100)
        assert is_hermes_bytecode(hbc) is True

    def test_non_hermes_file(self, tmp_path):
        js = tmp_path / "bundle.js"
        js.write_bytes(b"var x = 1;\n")
        assert is_hermes_bytecode(js) is False

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty"
        empty.write_bytes(b"")
        assert is_hermes_bytecode(empty) is False

    def test_too_short_file(self, tmp_path):
        short = tmp_path / "short"
        short.write_bytes(b"\xc6\x1f")
        assert is_hermes_bytecode(short) is False

    def test_nonexistent_file(self, tmp_path):
        assert is_hermes_bytecode(tmp_path / "nope") is False


# ── find_js_bundles ───────────────────────────────────────────────


class TestFindJsBundles:
    def test_finds_main_jsbundle(self, tmp_path):
        app = tmp_path / "Test.app"
        app.mkdir()
        bundle = app / "main.jsbundle"
        bundle.write_bytes(b"content" * 200)
        result = find_js_bundles(app)
        assert len(result) >= 1
        assert bundle in result

    def test_finds_index_ios_bundle(self, tmp_path):
        app = tmp_path / "Test.app"
        app.mkdir()
        bundle = app / "index.ios.bundle"
        bundle.write_bytes(b"content" * 200)
        result = find_js_bundles(app)
        assert bundle in result

    def test_recursive_search_for_jsbundle(self, tmp_path):
        app = tmp_path / "Test.app"
        nested = app / "assets" / "js"
        nested.mkdir(parents=True)
        bundle = nested / "app.jsbundle"
        bundle.write_bytes(b"x" * 2000)
        result = find_js_bundles(app)
        assert bundle in result

    def test_skips_tiny_bundles(self, tmp_path):
        app = tmp_path / "Test.app"
        app.mkdir()
        tiny = app / "tiny.jsbundle"
        tiny.write_bytes(b"x" * 100)  # under 1000 bytes
        result = find_js_bundles(app)
        # The tiny file was not found via candidate check, and the rglob
        # check filters by size > 1000
        found_via_rglob = [r for r in result if r == tiny]
        assert found_via_rglob == []

    def test_no_bundles_found(self, tmp_path):
        app = tmp_path / "Empty.app"
        app.mkdir()
        result = find_js_bundles(app)
        assert result == []

    def test_finds_hbc_extension(self, tmp_path):
        app = tmp_path / "Test.app"
        app.mkdir()
        hbc = app / "bundle.hbc"
        hbc.write_bytes(b"x" * 2000)
        result = find_js_bundles(app)
        assert hbc in result


# ── extract_strings_from_binary ───────────────────────────────────


class TestExtractStringsFromBinary:
    def test_extracts_null_separated_strings(self, tmp_path):
        hbc = tmp_path / "test.hbc"
        # Simulate a Hermes string table with null-separated entries
        data = b"hello world\x00api_key=abc123\x00https://example.com/api\x00"
        hbc.write_bytes(data)
        result = extract_strings_from_binary(hbc)
        assert "hello world" in result
        assert "api_key=abc123" in result

    def test_extracts_urls(self, tmp_path):
        hbc = tmp_path / "test.hbc"
        data = b"\x00\x00https://api.example.com/v1/users\x00\x00more data\x00"
        hbc.write_bytes(data)
        result = extract_strings_from_binary(hbc)
        assert any("https://api.example.com/v1/users" in s for s in result)

    def test_extracts_key_prefixes(self, tmp_path):
        hbc = tmp_path / "test.hbc"
        data = b"\x00sk_live_abcdef1234567890\x00pk_test_xyz789\x00AKIAIOSFODNN7EXAMPLE\x00"
        hbc.write_bytes(data)
        result = extract_strings_from_binary(hbc)
        assert any("sk_live_" in s for s in result)
        assert any("pk_test_" in s for s in result)
        assert any("AKIA" in s for s in result)

    def test_filters_short_strings(self, tmp_path):
        hbc = tmp_path / "test.hbc"
        data = b"ab\x00cd\x00hello world\x00"
        hbc.write_bytes(data)
        result = extract_strings_from_binary(hbc)
        # "ab" and "cd" are <4 chars, should be filtered
        assert "ab" not in result
        assert "cd" not in result

    def test_nonexistent_file_returns_empty(self, tmp_path):
        result = extract_strings_from_binary(tmp_path / "nonexistent")
        assert result == []

    def test_extracts_wss_urls(self, tmp_path):
        hbc = tmp_path / "test.hbc"
        data = b"\x00wss://socket.example.com/ws\x00"
        hbc.write_bytes(data)
        result = extract_strings_from_binary(hbc)
        assert any("wss://socket.example.com/ws" in s for s in result)


# ── extract_strings_from_js ───────────────────────────────────────


class TestExtractStringsFromJs:
    def test_double_quoted_strings(self, tmp_path):
        js = tmp_path / "bundle.js"
        js.write_text('var key = "sk_live_abc123def456";')
        result = extract_strings_from_js(js)
        assert "sk_live_abc123def456" in result

    def test_single_quoted_strings(self, tmp_path):
        js = tmp_path / "bundle.js"
        js.write_text("var url = 'https://api.example.com/v1';")
        result = extract_strings_from_js(js)
        assert "https://api.example.com/v1" in result

    def test_template_literals(self, tmp_path):
        js = tmp_path / "bundle.js"
        js.write_text("var tpl = `https://config.example.com`;")
        result = extract_strings_from_js(js)
        assert "https://config.example.com" in result

    def test_filters_short_strings(self, tmp_path):
        """Strings with fewer than 4 characters should not be extracted."""
        js = tmp_path / "bundle.js"
        # Use template literals (backticks) to avoid quote-greedy regex issues
        js.write_text("var longStr = `hello world`;\nvar shortStr = `ab`;\n")
        result = extract_strings_from_js(js)
        assert "hello world" in result
        assert "ab" not in result

    def test_nonexistent_file_returns_empty(self, tmp_path):
        result = extract_strings_from_js(tmp_path / "missing.js")
        assert result == []

    def test_deduplication(self, tmp_path):
        js = tmp_path / "bundle.js"
        js.write_text('var a = "duplicate"; var b = "duplicate";')
        result = extract_strings_from_js(js)
        assert result.count("duplicate") == 1


# ── scan_strings_for_secrets ──────────────────────────────────────


class TestScanStringsForSecrets:
    def test_detects_stripe_key(self):
        strings = ['"sk_live_abcdefghijklmnopqrstuvwxyz"']
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "STRIPE_KEY" in types

    def test_detects_aws_key(self):
        strings = ['"AKIAIOSFODNN7EXAMPLE"']
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "AWS_ACCESS_KEY" in types

    def test_detects_google_api_key(self):
        # Pattern requires exactly 35 chars of [A-Za-z0-9_-] after "AIza"
        strings = ['"AIzaSyA1234567890abcdefghijklmnopqrstXY"']
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "GOOGLE_API_KEY" in types

    def test_detects_jwt(self):
        strings = ['"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"']
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "JWT" in types

    def test_detects_bearer_token(self):
        strings = ['"Bearer eyJhbGciOiJIUzI1NiJ9.test1234567890"']
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "BEARER_TOKEN" in types

    def test_detects_firebase_db(self):
        strings = ['"myapp-prod.firebaseio.com"']
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "FIREBASE_DB" in types

    def test_detects_api_endpoint(self):
        strings = ["https://api.mycompany.com/v2/data"]
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "API_ENDPOINT" in types

    def test_detects_cloud_endpoint(self):
        # Use a URL that matches CLOUD_ENDPOINT but not URL_WITH_SECRET
        # (URL_WITH_SECRET requires key|token|secret|auth|api in the URL)
        strings = ["https://mysite.herokuapp.com/data"]
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "CLOUD_ENDPOINT" in types

    def test_detects_sentry_dsn(self):
        strings = ["https://abc123@o12345.ingest.sentry.io/6789"]
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "SENTRY_DSN" in types

    def test_detects_interesting_prefixes(self):
        strings = ["sk_live_1234567890abcdef"]
        findings = scan_strings_for_secrets(strings)
        types = {f["type"] for f in findings}
        assert "INTERESTING_STRING" in types

    def test_no_false_positives_on_clean_strings(self):
        strings = [
            "Hello world",
            "UIViewController",
            "viewDidLoad",
            "12345",
        ]
        findings = scan_strings_for_secrets(strings)
        assert findings == []

    def test_deduplication_of_findings(self):
        """Same value should only appear once in findings."""
        strings = ['"AKIAIOSFODNN7EXAMPLE"', '"AKIAIOSFODNN7EXAMPLE"']
        findings = scan_strings_for_secrets(strings)
        aws_findings = [f for f in findings if f["type"] == "AWS_ACCESS_KEY"]
        assert len(aws_findings) == 1

    def test_findings_sorted_by_type(self):
        strings = [
            "https://api.backend.com/v1",
            '"sk_live_abcdefghijklmnopqrstuvwxyz"',
            '"AKIAIOSFODNN7EXAMPLE"',
        ]
        findings = scan_strings_for_secrets(strings)
        types = [f["type"] for f in findings]
        assert types == sorted(types)

    def test_value_truncated_at_500(self):
        """Very long values should be truncated in findings."""
        long_val = '"sk_live_' + "a" * 600 + '"'
        findings = scan_strings_for_secrets([long_val])
        for f in findings:
            assert len(f["value"]) <= 500


# ── SECRET_PATTERNS validation ────────────────────────────────────


class TestSecretPatterns:
    """Verify all SECRET_PATTERNS compile and have a label."""

    def test_all_patterns_compile(self):
        for pattern, label in SECRET_PATTERNS:
            compiled = re.compile(pattern)
            assert compiled is not None, f"Pattern {label} failed to compile"

    def test_all_patterns_have_labels(self):
        for _pattern, label in SECRET_PATTERNS:
            assert isinstance(label, str)
            assert len(label) > 0


class TestInterestingPrefixes:
    def test_prefixes_are_strings(self):
        for prefix in INTERESTING_PREFIXES:
            assert isinstance(prefix, str)
            assert len(prefix) >= 2
