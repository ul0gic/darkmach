"""Tests for darkmach.analyze — static analysis extractors."""

from __future__ import annotations

import json
from unittest.mock import patch

from darkmach.analyze import (
    analyze_bundle,
    bundle_plists,
    bundle_resource_names,
    extract_urls,
    plist_strings,
    scan_plist_credentials,
)
from darkmach.sdkfingerprint import detect_sdks, detect_swift_modules
from darkmach.secretscan import keyword_matches, rank_credentials, scan_credentials

# AssetLabField's two real credentials; neither contains an English keyword (ENH-007).
CLERK_KEY = "pk_live_Y2xlcmsuYXNzZXRsYWIuY2Ek"
SUPABASE_KEY = "sb_publishable_EEbSpQdmgGtsGBe3P7k6ig_QCL2OFKE"

# Blackjack's GoogleService-Info.plist key — well-formed, and invisible to a binary-only scan.
GOOGLE_KEY = "AIzaSyB35AOFO08JQBh-ScQ9j-hgEIrwgzgHgyE"
PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"

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


class TestScanCredentialsNamedShapes:
    def _shapes(self, strings):
        return {h.shape for h in scan_credentials(strings)}

    def test_clerk_publishable_key(self):
        hits = scan_credentials([CLERK_KEY])
        assert [(h.shape, h.confidence, h.value) for h in hits] == [
            ("clerk-publishable-key", "high", CLERK_KEY)
        ]

    def test_supabase_publishable_key(self):
        hits = scan_credentials([SUPABASE_KEY])
        assert [(h.shape, h.confidence, h.value) for h in hits] == [
            ("supabase-key", "high", SUPABASE_KEY)
        ]

    def test_both_assetlabfield_credentials_alongside_ui_copy(self):
        strings = [
            "Choose your password",
            "ClerkKitUI/SignInFactorOnePasswordView.swift",
            '@"UIWindow"24@0:8@"ASAuthorizationController"16',
            CLERK_KEY,
            SUPABASE_KEY,
        ]
        assert self._shapes(strings) == {"clerk-publishable-key", "supabase-key"}

    def test_stripe_publishable_key_not_relabelled_as_clerk(self):
        hits = scan_credentials(["pk_live_51H8xQrLkjhgfdsaMNBVCXZ0987"])
        assert [h.shape for h in hits] == ["stripe-publishable-key"]

    def test_stripe_secret_key(self):
        hits = scan_credentials(["sk_live_4eC39HqLyjWDarjtT1zdp7dc"])
        assert [h.shape for h in hits] == ["stripe-secret-key"]

    def test_aws_access_key_id(self):
        hits = scan_credentials(["aws_credential_key=AKIAIOSFODNN7EXAMPLE"])
        assert [(h.shape, h.value) for h in hits] == [("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE")]

    def test_google_api_key(self):
        hits = scan_credentials(["AIzaSyD-1234567890abcdefghijklmnopqrstu"])
        assert [h.shape for h in hits] == ["google-api-key"]

    def test_truncated_google_key_reported_as_partial(self):
        hits = scan_credentials(["AIzaSyB4G40IhwotnuD26vAV-0PAxOVr"])
        assert [(h.shape, h.confidence) for h in hits] == [("google-api-key-partial", "medium")]

    def test_jwt(self):
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        hits = scan_credentials([f"Bearer {token}"])
        assert [(h.shape, h.value) for h in hits] == [("jwt", token)]

    def test_github_token(self):
        hits = scan_credentials(["ghp_" + "a1b2c3d4e5" * 3 + "abcdef"])
        assert [h.shape for h in hits] == ["github-token"]

    def test_slack_token(self):
        hits = scan_credentials(["xoxb-123456789012-abcdefghijklmnop"])
        assert [h.shape for h in hits] == ["slack-token"]

    def test_basic_auth_in_url(self):
        hits = scan_credentials(["https://admin:hunter2@internal.example.com/v1"])
        assert [h.shape for h in hits] == ["basic-auth-url"]

    def test_recaptcha_site_key(self):
        hits = scan_credentials(["6Lcap3QrAAAAAI-vC0bqleEYDnBQxO29FduEKygn"])
        assert [h.shape for h in hits] == ["recaptcha-key"]

    def test_firebase_database_url(self):
        hits = scan_credentials(["https://my-app-42.firebaseio.com"])
        assert [h.shape for h in hits] == ["firebase-database-url"]

    def test_context_is_the_containing_string(self):
        hits = scan_credentials([f"  publishableKey = {CLERK_KEY}  "])
        assert hits[0].value == CLERK_KEY
        assert hits[0].context == f"publishableKey = {CLERK_KEY}"


class TestPemKeyMaterial:
    """ISSUE-020: a PEM delimiter with no base64 body is a format string, not a key."""

    def _hits(self, strings):
        return [(h.shape, h.confidence) for h in scan_credentials(strings)]

    def test_bare_begin_marker_is_not_reported_as_a_key(self):
        assert self._hits(["-----BEGIN RSA PRIVATE KEY-----"]) == [
            ("pem-marker-no-key-material", "low")
        ]

    def test_unityframework_delimiter_block_yields_no_high_hit(self):
        hits = scan_credentials(
            [
                "-----BEGIN PUBLIC KEY-----",
                "-----END PUBLIC KEY-----",
                "-----BEGIN PRIVATE KEY-----",
                "-----END PRIVATE KEY-----",
                '@?0@"NSString"8@"NSDictionary"16',
            ]
        )
        assert [h.shape for h in hits] == ["pem-marker-no-key-material"]
        assert hits[0].confidence == "low"

    def test_body_on_the_next_line_is_a_key(self):
        hits = scan_credentials(
            ["-----BEGIN PRIVATE KEY-----", PEM_BODY, "-----END PRIVATE KEY-----"]
        )
        assert ("private-key-pem", "high") in [(h.shape, h.confidence) for h in hits]

    def test_body_inline_after_the_marker_is_a_key(self):
        hits = scan_credentials(
            [f"-----BEGIN PRIVATE KEY-----\\n{PEM_BODY}\\n-----END PRIVATE KEY-----"]
        )
        assert [(h.shape, h.confidence) for h in hits] == [("private-key-pem", "high")]

    def test_encrypted_pem_headers_precede_the_body(self):
        hits = scan_credentials(
            [
                "-----BEGIN RSA PRIVATE KEY-----",
                "Proc-Type: 4,ENCRYPTED",
                "DEK-Info: AES-128-CBC,7A9B2C",
                PEM_BODY,
            ]
        )
        assert ("private-key-pem", "high") in [(h.shape, h.confidence) for h in hits]

    def test_base64_further_down_the_binary_is_not_the_key_body(self):
        hits = scan_credentials(
            [
                "-----BEGIN PRIVATE KEY-----",
                '@?0@"NSString"8@"NSDictionary"16',
                PEM_BODY,
            ]
        )
        assert ("private-key-pem", "high") not in [(h.shape, h.confidence) for h in hits]

    def test_public_key_marker_is_not_scanned(self):
        assert scan_credentials(["-----BEGIN PUBLIC KEY-----", PEM_BODY]) == []

    def test_key_body_is_the_reported_evidence(self):
        hits = scan_credentials(["-----BEGIN PRIVATE KEY-----", PEM_BODY])
        assert hits[0].value == "-----BEGIN PRIVATE KEY-----"
        assert hits[0].context == PEM_BODY


class TestNamedShapeTemplates:
    """A shape satisfied by a shipped constant is documentation, not an issued credential."""

    def _graded(self, string):
        return [(h.shape, h.confidence) for h in scan_credentials([string])]

    def test_aws_documentation_example_key_demoted(self):
        assert self._graded("AKIAIOSFODNN7EXAMPLE") == [("aws-access-key-id", "medium")]

    def test_issued_aws_key_stays_high(self):
        assert self._graded("AKIA3XKQP7ZL2MDN4RVT") == [("aws-access-key-id", "high")]

    def test_basic_auth_template_demoted(self):
        assert self._graded("https://username:password@api.internal.net/v1") == [
            ("basic-auth-url", "medium")
        ]

    def test_issued_basic_auth_url_stays_high(self):
        assert self._graded("https://admin:hunter2@internal.corp.net/v1") == [
            ("basic-auth-url", "high")
        ]

    def test_filler_character_token_demoted(self):
        assert self._graded("AC" + "0" * 32) == [("twilio-account-sid", "medium")]

    def test_jwt_with_undecodable_header_demoted(self):
        assert self._graded("eyJzzzzzzzzzzzzz.eyJzzzzzzzzzzzzz") == [("jwt", "medium")]

    def test_jwt_with_real_header_stays_high(self):
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        assert self._graded(token) == [("jwt", "high")]

    def test_placeholder_google_key_demoted(self):
        assert self._graded("AIzaSyYOUR_API_KEY_HERE_0123456789abcde") == [
            ("google-api-key", "medium")
        ]


class TestOverlappingHitSuppression:
    def test_truncated_prefix_of_a_full_key_is_not_reported_twice(self):
        hits = scan_credentials(["AIzaSyB35AOFO08JQBh-ScQ9j-hgEIrwgzgHgyE"])
        assert [h.shape for h in hits] == ["google-api-key"]

    def test_keyword_anchor_does_not_duplicate_a_named_hit(self):
        hits = scan_credentials(["API_KEY = AIzaSyB35AOFO08JQBh-ScQ9j-hgEIrwgzgHgyE"])
        assert [h.shape for h in hits] == ["google-api-key"]

    def test_unrelated_partial_key_still_reported(self):
        hits = scan_credentials(["AIzaSyB4G40IhwotnuD26vAV-0PAxOVr"])
        assert [h.shape for h in hits] == ["google-api-key-partial"]


class TestCredentialSource:
    def test_source_defaults_to_empty(self):
        assert scan_credentials([CLERK_KEY])[0].source == ""

    def test_source_is_carried_onto_every_hit(self):
        hits = scan_credentials([CLERK_KEY, "7Kq2Wf9Zx4Lm8Bv3Nc6Rt1Yh5Jd0Pg"], source="Info.plist")
        assert {h.source for h in hits} == {"Info.plist"}

    def test_same_value_from_two_sources_is_kept(self):
        merged = rank_credentials(
            scan_credentials([CLERK_KEY], source="App") + scan_credentials([CLERK_KEY], source="p")
        )
        assert [h.source for h in merged] == ["App", "p"]

    def test_rank_credentials_orders_high_before_low(self):
        merged = rank_credentials(
            scan_credentials(["7Kq2Wf9Zx4Lm8Bv3Nc6Rt1Yh5Jd0Pg"], source="a")
            + scan_credentials([SUPABASE_KEY], source="b")
        )
        assert [h.confidence for h in merged] == ["high", "low"]

    def test_rank_credentials_dedupes_repeats(self):
        hits = scan_credentials([CLERK_KEY], source="App")
        assert rank_credentials(hits + hits) == hits

    def test_rank_credentials_on_empty_input(self):
        assert rank_credentials([]) == []


class TestScanCredentialsNoise:
    def test_keyword_only_strings_are_not_credentials(self):
        strings = [
            "Choose your password",
            "Confirm password",
            "Forgot password?",
            "Failed to save device token to keychain",
            "ClerkKit/TokenResource.swift",
            "Access-Control-Allow-Credentials",
            "ASAuthorizationControllerDelegate",
            "client_secret",
        ]
        assert scan_credentials(strings) == []

    def test_swift_mangled_symbols_are_not_credentials(self):
        strings = [
            "$s7SwiftUI29UIViewControllerRepresentableP",
            "_TtC8ClerkKit19SessionTokenFetcher",
            "G_A157_Qo_A152_G_A170_Qo_A217_GG_A59_ySaySiA210__So7UIImageC",
            "10IronSource23ISNHealthCheckConfigApi_p",
            "So26AVCaptureVideoPreviewLayerCSg",
        ]
        assert scan_credentials(strings) == []

    def test_english_prose_is_not_a_credential(self):
        assert scan_credentials(["Hello world", "viewDidLoad", "1234567890"]) == []

    def test_empty_list(self):
        assert scan_credentials([]) == []


class TestScanCredentialsGenericTiers:
    def test_high_entropy_standalone_string(self):
        hits = scan_credentials(["7Kq2Wf9Zx4Lm8Bv3Nc6Rt1Yh5Jd0Pg"])
        assert [(h.shape, h.confidence) for h in hits] == [("high-entropy-string", "low")]

    def test_keyword_anchored_random_value(self):
        hits = scan_credentials(['"apiKey": "9Xk2Lp7Qz4Vn8Bt3Mc6Rw1Y"'])
        assert [(h.shape, h.confidence) for h in hits] == [("keyword-anchored-value", "medium")]

    def test_keyword_anchored_placeholder_ignored(self):
        assert scan_credentials(['"api_key": "your_api_key_here_xxxx"']) == []

    def test_named_shape_suppresses_duplicate_entropy_hit(self):
        hits = scan_credentials([CLERK_KEY])
        assert [h.shape for h in hits] == ["clerk-publishable-key"]

    def test_ranked_high_before_low(self):
        hits = scan_credentials([SUPABASE_KEY, "7Kq2Wf9Zx4Lm8Bv3Nc6Rt1Yh5Jd0Pg"])
        assert [h.confidence for h in hits] == ["high", "low"]

    def test_deduplication_across_repeated_strings(self):
        assert len(scan_credentials([CLERK_KEY, CLERK_KEY, CLERK_KEY])) == 1

    def test_result_is_deterministic(self):
        strings = [SUPABASE_KEY, CLERK_KEY, "sk_live_4eC39HqLyjWDarjtT1zdp7dc"]
        assert scan_credentials(strings) == scan_credentials(list(reversed(strings)))


class TestKeywordMatches:
    def test_keeps_every_keyword_bearing_string(self):
        strings = ["Choose your password", "access_token=abc", "UIButton"]
        assert keyword_matches(strings) == ["Choose your password", "access_token=abc"]

    def test_case_insensitive(self):
        assert len(keyword_matches(["API_KEY=1", "Api_Key=2", "API_key=3"])) == 3

    def test_deduplicated_and_sorted(self):
        result = keyword_matches(["zzz_token=1", "aaa_secret=2", "aaa_secret=2"])
        assert result == ["aaa_secret=2", "zzz_token=1"]

    def test_empty_list(self):
        assert keyword_matches([]) == []

    def test_no_match_on_clean_strings(self):
        assert keyword_matches(["Hello world", "UIButton", "viewDidLoad"]) == []


class TestDetectSdksAnchoring:
    def _names(self, strings, resources=None):
        return [d.sdk for d in detect_sdks(strings, resources)]

    def test_segment_substrings_do_not_detect_segment(self):
        strings = [
            "AssignSegments",
            "SetSegmentAlphas",
            "SmoothSegmentMap",
            "VP8SetSegmentParams",
            "pathSegments",
            "setSelectedSegmentTintColor:",
        ]
        assert detect_sdks(strings) == []

    def test_segment_detected_from_real_identifier(self):
        assert self._names(["SEGAnalyticsConfiguration"]) == ["Segment"]

    def test_bare_vendor_word_is_not_evidence(self):
        assert detect_sdks(["firebase", "FIREBASE", "stripe", "sentry"]) == []

    def test_mangled_auth0_protocol_symbol_is_not_evidence(self):
        assert detect_sdks(["$s4Auth0A12LocalStorageP"]) == []

    def test_case_folding_does_not_widen_class_prefixes(self):
        assert detect_sdks(["ICMT", "Icmotlwz"]) == []

    def test_empty_list(self):
        assert detect_sdks([]) == []


class TestDetectSdksEvidence:
    def test_evidence_names_the_kind_and_the_match(self):
        result = detect_sdks(["com.google.firebase.analytics"])
        assert result[0].sdk == "Firebase"
        assert result[0].evidence == ("bundle-id:com.google.firebase",)

    def test_host_evidence(self):
        result = detect_sdks(["https://ksirnjovowpvamgcnapt.supabase.co"])
        assert result[0].evidence == ("host:ksirnjovowpvamgcnapt.supabase.co",)

    def test_class_evidence(self):
        result = detect_sdks(["SupabaseClientOptions"])
        assert result == [("Supabase", ("class:SupabaseClientOptions",))]

    def test_evidence_capped_at_three_samples(self):
        strings = ["FIRApp", "FIRAnalytics", "FIRAuth", "FIRMessaging", "com.google.firebase"]
        assert len(detect_sdks(strings)[0].evidence) == 3

    def test_multiple_sdks_sorted_by_name(self):
        strings = [
            "com.google.firebase",
            "api.mixpanel.com",
            "ADJConfig",
            "api.stripe.com",
        ]
        assert self._sdk_names(strings) == ["Adjust", "Firebase", "Mixpanel", "Stripe"]

    def _sdk_names(self, strings):
        return [d.sdk for d in detect_sdks(strings)]

    def test_pure_swift_package_found_only_in_resource_names(self):
        result = detect_sdks([], ["swift-crypto_Crypto.bundle", "Clerk_ClerkKitUI.bundle"])
        assert [d.sdk for d in result] == ["Clerk", "swift-crypto"]

    def test_resources_default_to_none(self):
        assert detect_sdks(["PhoneNumberKit"]) == [("PhoneNumberKit", ("package:PhoneNumberKit",))]

    def test_crashlytics_framework(self):
        assert self._sdk_names(["Crashlytics.framework"]) == ["Crashlytics"]

    def test_datadog_class(self):
        assert self._sdk_names(["DatadogCore"]) == ["Datadog"]

    def test_adjust_host(self):
        assert self._sdk_names(["app.adjust.com/tracking"]) == ["Adjust"]

    def test_branch_host(self):
        assert self._sdk_names(["api.branch.io/v1/open"]) == ["Branch"]

    def test_auth0_package(self):
        assert self._sdk_names(["Auth0.swift"]) == ["Auth0"]

    def test_aws_cognito_class(self):
        assert self._sdk_names(["AWSCognitoIdentityProvider"]) == ["AWS Cognito"]

    def test_aws_s3_host(self):
        assert self._sdk_names(["s3.amazonaws.com/bucket"]) == ["AWS S3"]

    def test_sentry_bundle_id(self):
        assert self._sdk_names(["io.sentry.SentryClient"]) == ["Sentry"]

    def test_mixpanel_package(self):
        assert self._sdk_names(["mixpanel-swift"]) == ["Mixpanel"]

    def test_google_mobile_ads_class(self):
        assert self._sdk_names(["GADMobileAds"]) == ["Google Mobile Ads"]

    def test_applovin_class(self):
        assert self._sdk_names(["ALSdkConfiguration"]) == ["AppLovin"]

    def test_ironsource_symbol(self):
        assert self._sdk_names(["IronSourceMediationAdapter"]) == ["IronSource"]

    def test_unity_ads_host(self):
        assert self._sdk_names(["scar.unityads.unity3d.com"]) == ["Unity Ads"]

    def test_mintegral_resource_bundle(self):
        assert [d.sdk for d in detect_sdks([], ["MTGSDK.bundle"])] == ["Mintegral"]

    def test_react_native_class(self):
        assert self._sdk_names(["RCTBundleURLProvider"]) == ["React Native"]

    def test_meta_audience_network_separate_from_facebook_sdk(self):
        assert self._sdk_names(["FBAdView", "FBSDKCoreKit"]) == [
            "Facebook SDK",
            "Meta Audience Network",
        ]


class TestDetectSwiftModules:
    def test_extracts_spm_checkout_names(self):
        strings = [
            "/Users/dev/Library/Developer/Xcode/DerivedData/App-abc/"
            "SourcePackages/checkouts/supabase-swift/Sources/Supabase/SupabaseClient.swift",
            "SourcePackages/checkouts/swift-clocks/Sources/Clocks/Timer.swift",
        ]
        assert detect_swift_modules(strings) == ["supabase-swift", "swift-clocks"]

    def test_extracts_concise_file_literal_modules(self):
        strings = ["ClerkKit/Auth.swift", "ClerkKitUI/SignInView.swift", "Nuke/ImagePipeline.swift"]
        assert detect_swift_modules(strings) == ["ClerkKit", "ClerkKitUI", "Nuke"]

    def test_merges_both_leak_forms(self):
        strings = ["SourcePackages/checkouts/swift-clocks/x", "ClerkKit/Auth.swift"]
        assert detect_swift_modules(strings) == ["ClerkKit", "swift-clocks"]

    def test_partial_path_is_not_a_module(self):
        assert (
            detect_swift_modules(["Sources/ClerkKit/Auth.swift", "prefix ClerkKit/A.swift"]) == []
        )

    def test_deduplicated_and_sorted(self):
        strings = ["SourcePackages/checkouts/zeta/a", "SourcePackages/checkouts/alpha/b"] * 3
        assert detect_swift_modules(strings) == ["alpha", "zeta"]

    def test_no_modules(self):
        assert detect_swift_modules(["UIKit", "Foundation"]) == []


class TestBundleResourceNames:
    def test_collects_bundles_and_frameworks(self, tmp_path):
        app = tmp_path / "Test.app"
        (app / "Clerk_ClerkKitUI.bundle").mkdir(parents=True)
        (app / "swift-crypto_Crypto.bundle").mkdir()
        (app / "Frameworks" / "Alamofire.framework").mkdir(parents=True)
        assert bundle_resource_names(app) == [
            "Alamofire.framework",
            "Clerk_ClerkKitUI.bundle",
            "swift-crypto_Crypto.bundle",
        ]

    def test_missing_frameworks_dir(self, tmp_path):
        app = tmp_path / "Test.app"
        app.mkdir()
        assert bundle_resource_names(app) == []


class TestBundlePlists:
    def test_collects_nested_plists(self, tmp_path):
        app = tmp_path / "Test.app"
        (app / "Frameworks" / "Unity.framework").mkdir(parents=True)
        (app / "Info.plist").touch()
        (app / "GoogleService-Info.plist").touch()
        (app / "Frameworks" / "Unity.framework" / "Info.plist").touch()
        assert [p.relative_to(app).as_posix() for p in bundle_plists(app)] == [
            "Frameworks/Unity.framework/Info.plist",
            "GoogleService-Info.plist",
            "Info.plist",
        ]

    def test_localisation_plists_excluded(self, tmp_path):
        app = tmp_path / "Test.app"
        (app / "en.lproj").mkdir(parents=True)
        (app / "en.lproj" / "InfoPlist.plist").touch()
        (app / "Info.plist").touch()
        assert [p.name for p in bundle_plists(app)] == ["Info.plist"]

    def test_no_plists(self, tmp_path):
        app = tmp_path / "Test.app"
        app.mkdir()
        assert bundle_plists(app) == []


class TestPlistStrings:
    def _with_run(self, response):
        return patch("darkmach.analyze._run", return_value=response)

    def test_string_values_are_paired_with_their_key(self, tmp_path):
        from tests.conftest import make_completed_process

        payload = json.dumps({"API_KEY": GOOGLE_KEY})
        with self._with_run(make_completed_process(stdout=payload)):
            assert plist_strings(tmp_path / "x.plist") == [GOOGLE_KEY, f"API_KEY = {GOOGLE_KEY}"]

    def test_nested_containers_are_walked(self, tmp_path):
        from tests.conftest import make_completed_process

        payload = json.dumps({"outer": {"inner": ["a-value"]}, "n": 3, "flag": True})
        with self._with_run(make_completed_process(stdout=payload)):
            assert plist_strings(tmp_path / "x.plist") == ["a-value", "inner = a-value"]

    def test_conversion_failure_falls_back_to_the_dump(self, tmp_path):
        from tests.conftest import make_completed_process

        dump = make_completed_process(stdout='{\n  "K" => "V"\n}')
        with patch(
            "darkmach.analyze._run", side_effect=[make_completed_process(returncode=1), dump]
        ):
            assert plist_strings(tmp_path / "x.plist") == ["{", '  "K" => "V"', "}"]

    def test_malformed_json_yields_no_strings(self, tmp_path):
        from tests.conftest import make_completed_process

        with self._with_run(make_completed_process(stdout="not json")):
            assert plist_strings(tmp_path / "x.plist") == []


class TestScanPlistCredentials:
    """ISSUE-020: a credential in a standard config file must be visible to the scanner."""

    def _scan(self, tmp_path, payload):
        from tests.conftest import make_completed_process

        plist = tmp_path / "GoogleService-Info.plist"
        with patch(
            "darkmach.analyze._run",
            return_value=make_completed_process(stdout=json.dumps(payload)),
        ):
            return scan_plist_credentials(tmp_path, [plist])

    def test_google_api_key_in_googleservice_info(self, tmp_path):
        hits = self._scan(
            tmp_path,
            {"API_KEY": GOOGLE_KEY, "PROJECT_ID": "blackjack-1e91b", "IS_ADS_ENABLED": True},
        )
        assert [(h.shape, h.confidence, h.value) for h in hits] == [
            ("google-api-key", "high", GOOGLE_KEY)
        ]

    def test_hit_is_labelled_with_the_plist_it_came_from(self, tmp_path):
        hits = self._scan(tmp_path, {"API_KEY": GOOGLE_KEY})
        assert hits[0].source == "GoogleService-Info.plist"

    def test_plist_key_name_becomes_the_context(self, tmp_path):
        hits = self._scan(tmp_path, {"API_KEY": GOOGLE_KEY})
        assert hits[0].context == f"API_KEY = {GOOGLE_KEY}"

    def test_no_credentials_in_an_ordinary_plist(self, tmp_path):
        assert self._scan(tmp_path, {"CFBundleExecutable": "Test"}) == []

    def test_no_plists_to_scan(self, tmp_path):
        assert scan_plist_credentials(tmp_path, []) == []


# ── analyze_bundle ────────────────────────────────────────────────


def _fake_tool(binary_strings: str, plist_json: dict):
    """Dispatch on the command so the mock survives changes to the call order."""
    from tests.conftest import make_completed_process

    def run(cmd, **kwargs):
        tool, args = cmd[0], cmd[1:]
        if tool == "plutil" and "-extract" in args:
            return make_completed_process(stdout="Test")
        if tool == "plutil" and "json" in args:
            payload = plist_json if "GoogleService" in args[-1] else {"CFBundleExecutable": "Test"}
            return make_completed_process(stdout=json.dumps(payload))
        if tool == "plutil":
            return make_completed_process(stdout='{\n  "CFBundleExecutable" => "Test"\n}')
        if tool == "strings":
            return make_completed_process(stdout=binary_strings)
        if tool == "otool" and args[0] == "-l":
            return make_completed_process(stdout="Load command 0\n  cmd LC_SEGMENT_64\n")
        if tool == "otool":
            return make_completed_process(stdout="Test:\n\t/usr/lib/libSystem.B.dylib\n")
        if tool == "lipo":
            return make_completed_process(stdout="Non-fat file: Test is architecture: arm64")
        return make_completed_process(stdout="", stderr="Entitlements data")

    return run


class TestAnalyzeBundle:
    """Test the full analyze_bundle pipeline with mocked subprocess calls."""

    def _bundle(self, tmp_path):
        import plistlib

        app = tmp_path / "Test.app"
        app.mkdir()
        plist = {"CFBundleExecutable": "Test", "CFBundleIdentifier": "com.test.app"}
        (app / "Info.plist").write_bytes(plistlib.dumps(plist))
        (app / "GoogleService-Info.plist").write_bytes(plistlib.dumps({"API_KEY": GOOGLE_KEY}))
        (app / "Test").write_bytes(b"\x00" * 100)
        return app

    def _analyze(self, tmp_path, binary_strings="plain text\n", plist_json=None):
        app = self._bundle(tmp_path)
        output_dir = tmp_path / "output"
        payload = {"API_KEY": GOOGLE_KEY} if plist_json is None else plist_json
        with patch("darkmach.analyze._run", side_effect=_fake_tool(binary_strings, payload)):
            return app, output_dir, analyze_bundle(app, output_dir)

    def test_analyze_bundle_produces_output_files(self, tmp_path):
        strings = "https://api.example.com/v1\napi_key=sk_test_123\nfirebase-analytics\n"
        _, output_dir, results = self._analyze(tmp_path, strings)

        assert results["app"] == "Test"
        for name in ("urls.txt", "secrets.txt", "sdks.txt", "summary.json"):
            assert (output_dir / name).exists()
        assert json.loads((output_dir / "summary.json").read_text())["app"] == "Test"

    def test_plist_credential_reaches_secrets_file(self, tmp_path):
        _, output_dir, results = self._analyze(tmp_path)
        rows = [line.split("\t") for line in (output_dir / "secrets.txt").read_text().splitlines()]

        assert ["high", "google-api-key", "GoogleService-Info.plist", GOOGLE_KEY] in [
            row[:4] for row in rows
        ]
        assert results["plist_secret_count"] == 1

    def test_binary_hit_is_labelled_with_the_executable(self, tmp_path):
        _, output_dir, results = self._analyze(tmp_path, f"{CLERK_KEY}\n", plist_json={})
        rows = (output_dir / "secrets.txt").read_text().splitlines()

        assert rows[0].split("\t")[:4] == ["high", "clerk-publishable-key", "Test", CLERK_KEY]
        assert results["plist_secret_count"] == 0

    def test_analyze_bundle_returns_empty_on_missing_executable(self, tmp_path):
        """If CFBundleExecutable cannot be read, analyze_bundle returns {}."""
        app = tmp_path / "Bad.app"
        app.mkdir()
        import plistlib

        plist = {"CFBundleIdentifier": "com.test.bad"}
        (app / "Info.plist").write_bytes(plistlib.dumps(plist))

        output_dir = tmp_path / "output"

        from tests.conftest import make_completed_process

        with patch("darkmach.analyze._run") as mock_run:
            mock_run.return_value = make_completed_process(returncode=1, stdout="")
            result = analyze_bundle(app, output_dir)

        assert result == {}
