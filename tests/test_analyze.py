"""Tests for sphinx.analyze — static analysis extractors."""

from __future__ import annotations

import json
from unittest.mock import patch

from sphinx.analyze import (
    analyze_bundle,
    extract_sdk_strings,
    extract_secrets,
    extract_urls,
)

# ── extract_urls ──────────────────────────────────────────────────


class TestExtractUrls:
    def test_basic_http_url(self):
        result = extract_urls(["http://example.com"])
        assert result == ["http://example.com"]

    def test_basic_https_url(self):
        result = extract_urls(["https://api.example.com/v1"])
        assert result == ["https://api.example.com/v1"]

    def test_case_insensitive_scheme(self):
        result = extract_urls(["HTTP://EXAMPLE.COM", "Https://Mixed.Case"])
        assert len(result) == 2
        assert "HTTP://EXAMPLE.COM" in result
        assert "Https://Mixed.Case" in result

    def test_non_url_strings_excluded(self):
        result = extract_urls(["just a string", "ftp://other", "ws://socket", "/path/to/file"])
        assert result == []

    def test_empty_list(self):
        result = extract_urls([])
        assert result == []

    def test_mixed_urls_and_non_urls(self):
        strings = [
            "https://api.stripe.com/v1/charges",
            "not a url",
            "http://localhost:3000",
            "some random text",
        ]
        result = extract_urls(strings)
        assert len(result) == 2
        assert "http://localhost:3000" in result
        assert "https://api.stripe.com/v1/charges" in result

    def test_result_is_sorted(self):
        strings = ["https://zebra.com", "http://alpha.com", "https://middle.com"]
        result = extract_urls(strings)
        assert result == sorted(result)

    def test_deduplication(self):
        strings = ["https://dup.com", "https://dup.com", "https://dup.com"]
        result = extract_urls(strings)
        assert result == ["https://dup.com"]

    def test_whitespace_stripping(self):
        result = extract_urls(["https://trimmed.com  "])
        assert result == ["https://trimmed.com"]

    def test_url_must_start_with_scheme(self):
        """Strings containing a URL mid-string should NOT match (re.match anchors at start)."""
        result = extract_urls(["prefix https://example.com"])
        assert result == []


# ── extract_secrets ───────────────────────────────────────────────


class TestExtractSecrets:
    def test_api_key_pattern(self):
        strings = ["X-API-KEY: abc123def456"]
        result = extract_secrets(strings)
        assert len(result) == 1
        assert "X-API-KEY: abc123def456" in result

    def test_api_key_underscore(self):
        result = extract_secrets(["api_key=sk_live_123456"])
        assert len(result) == 1

    def test_apikey_no_separator(self):
        result = extract_secrets(["apikey: something"])
        assert len(result) == 1

    def test_bearer_token(self):
        result = extract_secrets(["Bearer eyJhbGciOiJIUzI1NiJ9"])
        assert len(result) == 1

    def test_authorization_header(self):
        result = extract_secrets(["Authorization: Basic dXNlcjpwYXNz"])
        assert len(result) == 1

    def test_token_pattern(self):
        result = extract_secrets(["access_token=abcdef123456"])
        assert len(result) == 1

    def test_secret_pattern(self):
        result = extract_secrets(["client_secret=mysecretvalue"])
        assert len(result) == 1

    def test_password_pattern(self):
        result = extract_secrets(["password: hunter2"])
        assert len(result) == 1

    def test_credential_pattern(self):
        result = extract_secrets(["aws_credential_key=AKIAIOSFODNN7EXAMPLE"])
        assert len(result) == 1

    def test_no_match_on_clean_strings(self):
        strings = ["Hello world", "UIButton", "viewDidLoad", "1234567890"]
        result = extract_secrets(strings)
        assert result == []

    def test_empty_list(self):
        result = extract_secrets([])
        assert result == []

    def test_case_insensitive(self):
        result = extract_secrets(["API_KEY=test", "Api_Key=test2", "API_key=test3"])
        assert len(result) == 3

    def test_deduplication(self):
        strings = ["token=abc", "token=abc"]
        result = extract_secrets(strings)
        assert len(result) == 1

    def test_result_is_sorted(self):
        strings = ["zzz_token=1", "aaa_secret=2", "mmm_password=3"]
        result = extract_secrets(strings)
        assert result == sorted(result)

    def test_special_characters_in_string(self):
        result = extract_secrets(["api.key: s3cr3t!@#$%"])
        assert len(result) == 1


# ── extract_sdk_strings ──────────────────────────────────────────


class TestExtractSdkStrings:
    def test_firebase(self):
        result = extract_sdk_strings(["com.google.firebase.analytics"])
        assert len(result) == 1

    def test_aws_s3(self):
        result = extract_sdk_strings(["s3.amazonaws.com/bucket"])
        assert len(result) == 1

    def test_stripe(self):
        result = extract_sdk_strings(["Stripe/v1/charges"])
        assert len(result) == 1

    def test_sentry(self):
        result = extract_sdk_strings(["io.sentry.SentryClient"])
        assert len(result) == 1

    def test_multiple_sdks(self):
        strings = [
            "firebase-messaging",
            "com.amplitude.api",
            "stripe.publishable.key",
            "bugsnag-cocoa",
        ]
        result = extract_sdk_strings(strings)
        assert len(result) == 4

    def test_no_match(self):
        strings = ["UIKit", "Foundation", "CoreData", "SwiftUI"]
        result = extract_sdk_strings(strings)
        assert result == []

    def test_empty_list(self):
        result = extract_sdk_strings([])
        assert result == []

    def test_case_insensitive(self):
        result = extract_sdk_strings(["FIREBASE", "Firebase", "firebase"])
        # All three match, but after dedup there should be 3 (different strings)
        assert len(result) == 3

    def test_mixpanel(self):
        result = extract_sdk_strings(["mixpanel-swift"])
        assert len(result) == 1

    def test_datadog(self):
        result = extract_sdk_strings(["DatadogCore"])
        assert len(result) == 1

    def test_crashlytics(self):
        result = extract_sdk_strings(["Crashlytics.framework"])
        assert len(result) == 1

    def test_adjust_com(self):
        result = extract_sdk_strings(["app.adjust.com/tracking"])
        assert len(result) == 1

    def test_branch_io(self):
        result = extract_sdk_strings(["api.branch.io/v1/open"])
        assert len(result) == 1

    def test_auth0(self):
        result = extract_sdk_strings(["Auth0.swift"])
        assert len(result) == 1

    def test_cognito(self):
        result = extract_sdk_strings(["AWSCognitoIdentityProvider"])
        assert len(result) == 1

    def test_deduplication(self):
        result = extract_sdk_strings(["firebase", "firebase", "firebase"])
        assert len(result) == 1

    def test_result_is_sorted(self):
        strings = ["stripe-api", "aws-sdk", "firebase-core"]
        result = extract_sdk_strings(strings)
        assert result == sorted(result)


# ── analyze_bundle ────────────────────────────────────────────────


class TestAnalyzeBundle:
    """Test the full analyze_bundle pipeline with mocked subprocess calls."""

    def test_analyze_bundle_produces_output_files(self, tmp_path):
        """analyze_bundle should create urls.txt, secrets.txt, sdks.txt, summary.json."""
        # Set up a minimal app bundle
        app = tmp_path / "Test.app"
        app.mkdir()
        import plistlib

        plist = {"CFBundleExecutable": "Test", "CFBundleIdentifier": "com.test.app"}
        (app / "Info.plist").write_bytes(plistlib.dumps(plist))
        (app / "Test").write_bytes(b"\x00" * 100)

        output_dir = tmp_path / "output"

        # Mock all subprocess calls
        from tests.conftest import make_completed_process

        plist_stdout = '{\n  "CFBundleExecutable" = "Test";\n}'

        responses = [
            # plutil -extract CFBundleExecutable
            make_completed_process(stdout="Test"),
            # otool -l (encryption check)
            make_completed_process(stdout="Load command 0\n  cmd LC_SEGMENT_64\n"),
            # lipo -info
            make_completed_process(stdout="Non-fat file: Test is architecture: arm64"),
            # otool -L (frameworks)
            make_completed_process(
                stdout="Test:\n\t/usr/lib/libSystem.B.dylib\n\t/System/Library/Frameworks/UIKit.framework/UIKit\n"
            ),
            # strings (binary strings)
            make_completed_process(
                stdout="https://api.example.com/v1\napi_key=sk_test_123\n"
                "firebase-analytics\nplain text\n"
            ),
            # codesign -d --entitlements
            make_completed_process(stdout="", stderr="Entitlements data"),
            # plutil -p for each plist found via rglob (Info.plist)
            make_completed_process(stdout=plist_stdout),
            # plutil -p for URL schemes / ATS analysis
            make_completed_process(stdout=plist_stdout),
        ]

        with patch("sphinx.analyze._run") as mock_run:
            mock_run.side_effect = responses
            results = analyze_bundle(app, output_dir)

        assert results["app"] == "Test"
        assert (output_dir / "urls.txt").exists()
        assert (output_dir / "secrets.txt").exists()
        assert (output_dir / "sdks.txt").exists()
        assert (output_dir / "summary.json").exists()

        summary = json.loads((output_dir / "summary.json").read_text())
        assert summary["app"] == "Test"

    def test_analyze_bundle_returns_empty_on_missing_executable(self, tmp_path):
        """If CFBundleExecutable cannot be read, analyze_bundle returns {}."""
        app = tmp_path / "Bad.app"
        app.mkdir()
        import plistlib

        plist = {"CFBundleIdentifier": "com.test.bad"}
        (app / "Info.plist").write_bytes(plistlib.dumps(plist))

        output_dir = tmp_path / "output"

        from tests.conftest import make_completed_process

        with patch("sphinx.analyze._run") as mock_run:
            mock_run.return_value = make_completed_process(returncode=1, stdout="")
            result = analyze_bundle(app, output_dir)

        assert result == {}
