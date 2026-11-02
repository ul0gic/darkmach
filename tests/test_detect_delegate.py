"""Tests for src/patch/delegate.py -- AppDelegate auto-detection.

Covers:
  - 5-tier detection: Swift mangled, Swift variant, Swift any, ObjC, SwiftUI
  - SDK delegate filtering (GoogleUtilities, Firebase, etc.)
  - Module name resolution from Info.plist and binary filename
  - nm symbol table parsing (Strategy 4)
  - Edge cases: empty symbols, multiple candidates, no match
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Import the standalone script via importlib (filename contains hyphens)
# ---------------------------------------------------------------------------

_DETECT_SCRIPT = (
    Path(__file__).resolve().parent.parent / "src" / "patch" / "delegate.py"
)


@pytest.fixture(scope="module")
def dd():
    """Import detect-delegate.py as a module."""
    spec = importlib.util.spec_from_file_location("detect_delegate", str(_DETECT_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_subprocess_calls(strings_output="", nm_output="", plist_output="", plist_rc=0):
    """Create a side_effect function that routes calls based on command."""

    def _side_effect(cmd, **kwargs):
        if cmd[0] == "/usr/libexec/PlistBuddy":
            return subprocess.CompletedProcess(
                args=cmd, returncode=plist_rc, stdout=plist_output, stderr=""
            )
        if cmd[0] == "strings":
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=strings_output, stderr=""
            )
        if cmd[0] == "nm":
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=nm_output, stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    return _side_effect


# ===================================================================
# Helper function tests
# ===================================================================


class TestGetBundleExecutable:
    """Test get_bundle_executable Info.plist parsing."""

    def test_returns_executable_name(self, tmp_path, dd):
        """Should extract CFBundleExecutable from plist."""
        app_dir = tmp_path / "Test.app"
        app_dir.mkdir()
        (app_dir / "Info.plist").write_bytes(b"dummy plist")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["PlistBuddy"], returncode=0, stdout="MyApp\n", stderr=""
            )
            result = dd.get_bundle_executable(str(app_dir))

        assert result == "MyApp"

    def test_returns_none_when_no_plist(self, dd):
        """Should return None when Info.plist doesn't exist."""
        result = dd.get_bundle_executable("/nonexistent/path/App.app")
        assert result is None

    def test_returns_none_on_failure(self, tmp_path, dd):
        """Should return None when PlistBuddy fails."""
        app_dir = tmp_path / "Bad.app"
        app_dir.mkdir()
        (app_dir / "Info.plist").write_bytes(b"corrupt")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["PlistBuddy"], returncode=1, stdout="", stderr="error"
            )
            result = dd.get_bundle_executable(str(app_dir))

        assert result is None


class TestGetStrings:
    """Test get_strings binary string extraction."""

    def test_returns_string_list(self, dd):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["strings"], returncode=0, stdout="line1\nline2\nline3\n", stderr=""
            )
            result = dd.get_strings("/fake/binary")

        assert "line1" in result
        assert "line2" in result

    def test_returns_empty_on_failure(self, dd):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = dd.get_strings("/fake/binary")
        assert result == []


class TestGetNmSymbols:
    """Test get_nm_symbols symbol table extraction."""

    def test_returns_symbol_lines(self, dd):
        nm_output = "0000000100001234 T _main\n0000000100005678 t _helper\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["nm"], returncode=0, stdout=nm_output, stderr=""
            )
            result = dd.get_nm_symbols("/fake/binary")

        assert any("_main" in line for line in result)

    def test_returns_empty_on_failure(self, dd):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = dd.get_nm_symbols("/fake/binary")
        assert result == []


# ===================================================================
# Strategy 1: Swift mangled name matching module exactly
# ===================================================================


class TestStrategy1SwiftExactModule:
    """Detect _TtC<N><module>11AppDelegate matching the binary's module name."""

    def test_exact_match(self, dd):
        """Should find _TtC11AccuWeather11AppDelegate for module AccuWeather."""
        strings_out = "_TtC11AccuWeather11AppDelegate\nsome_other_string\n"
        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
        ):
            name, method, confidence = dd.detect_delegate("/fake/AccuWeather", app_path=None)

        assert name == "_TtC11AccuWeather11AppDelegate"
        assert "Swift mangled" in method
        assert "exact module match" in method
        assert confidence == "high"

    def test_module_from_plist(self, tmp_path, dd):
        """Module name should come from CFBundleExecutable in Info.plist."""
        app_path = tmp_path / "WeatherApp.app"
        app_path.mkdir()
        (app_path / "Info.plist").write_bytes(b"dummy")

        strings_out = "_TtC10WeatherApp11AppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(
                strings_output=strings_out,
                plist_output="WeatherApp\n",
                plist_rc=0,
            ),
        ):
            name, _method, confidence = dd.detect_delegate(
                str(app_path / "WeatherApp"), app_path=str(app_path)
            )

        assert name == "_TtC10WeatherApp11AppDelegate"
        assert confidence == "high"

    def test_module_name_from_binary_filename(self, dd):
        """When no .app path, module name should be binary filename."""
        strings_out = "_TtC7TestApp11AppDelegate\n"

        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
        ):
            name, _method, confidence = dd.detect_delegate("/some/path/TestApp")

        assert name == "_TtC7TestApp11AppDelegate"
        assert confidence == "high"


# ===================================================================
# Strategy 1b: Swift variant delegate name
# ===================================================================


class TestStrategy1bSwiftVariant:
    """Detect Swift delegate with variant names (e.g., MyAppCustomAppDelegate)."""

    def test_variant_name(self, dd):
        """Should match _TtC<N><module><N><variant>AppDelegate."""
        strings_out = "_TtC7TestApp19CustomAppDelegate\nother_stuff\n"

        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
        ):
            name, method, confidence = dd.detect_delegate("/path/TestApp")

        assert name == "_TtC7TestApp19CustomAppDelegate"
        assert "variant" in method.lower()
        assert confidence == "high"


# ===================================================================
# Strategy 2: Any Swift mangled AppDelegate
# ===================================================================


class TestStrategy2SwiftAny:
    """Detect any Swift mangled AppDelegate, filtering SDK modules."""

    def test_single_non_sdk_candidate(self, dd):
        """Single non-SDK Swift AppDelegate should be detected with high confidence."""
        strings_out = "_TtC8MyModule11AppDelegate\n"

        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
        ):
            # Use a different binary name to avoid Strategy 1 match
            name, method, confidence = dd.detect_delegate("/path/DifferentName")

        assert name == "_TtC8MyModule11AppDelegate"
        assert "Swift mangled" in method
        assert confidence == "high"

    def test_multiple_candidates_picks_best(self, dd):
        """Multiple candidates should pick the one closest to the binary name."""
        strings_out = "_TtC8MyModule11AppDelegate\n_TtC10OtherThing11AppDelegate\n"

        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
        ):
            name, _method, confidence = dd.detect_delegate("/path/MyModuleApp")

        # "MyModule" is closer to "MyModuleApp" than "OtherThing"
        assert name == "_TtC8MyModule11AppDelegate"
        assert confidence == "medium"

    def test_sdk_delegates_filtered(self, dd):
        """SDK delegates should be excluded from candidates."""
        sdk_modules = [
            "GoogleUtilities",
            "Firebase",
            "AirshipCore",
            "FBSDKCoreKit",
            "Branch",
            "Adjust",
            "AppsFlyerLib",
            "Singular",
            "Kochava",
            "MoEngage",
            "CleverTap",
            "OneSignal",
            "Braze",
            "Leanplum",
        ]

        for sdk in sdk_modules:
            n = len(sdk)
            mangled = f"_TtC{n}{sdk}11AppDelegate"
            strings_out = f"{mangled}\n"

            with patch(
                "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
            ):
                name, _method, _confidence = dd.detect_delegate("/path/SomeApp")

            # SDK delegate should be filtered -- name should NOT be the SDK delegate
            if name is not None:
                assert sdk not in name, f"SDK module {sdk} was not filtered"

    def test_sdk_filtered_real_app_found(self, dd):
        """When SDK delegates are present alongside a real one, the real one wins."""
        strings_out = (
            "_TtC15GoogleUtilities28GULAppDelegateSwizzlerHelper\n"
            "_TtC8Firebase20FirebaseAppDelegate\n"
            "_TtC10MyRealApp11AppDelegate\n"
        )

        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
        ):
            name, _method, _confidence = dd.detect_delegate("/path/SomethingElse")

        assert name == "_TtC10MyRealApp11AppDelegate"


# ===================================================================
# Strategy 3: ObjC-style AppDelegate
# ===================================================================


class TestStrategy3ObjC:
    """Detect ObjC AppDelegate class names from strings output.

    Note: The ObjC regex ``^[A-Z][A-Za-z0-9]*AppDelegate$`` requires at least
    one character prefix before "AppDelegate" (e.g., "MyAppDelegate"). Plain
    "AppDelegate" does NOT match because after consuming the first [A-Z] ("A"),
    the greedy ``[A-Za-z0-9]*`` leaves no room for the literal "AppDelegate"
    suffix. This is a known limitation of the current implementation.
    """

    def test_prefixed_appdelegate(self, dd):
        """A prefixed AppDelegate like 'MyAppDelegate' should be found."""
        strings_out = "MyAppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, method, _confidence = dd.detect_delegate("/path/NoSwift")

        assert name == "MyAppDelegate"
        assert "ObjC" in method

    def test_single_objc_candidate(self, dd):
        """Single ObjC candidate should be medium confidence."""
        strings_out = "CustomAppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, _method, confidence = dd.detect_delegate("/path/NoSwift")

        assert name == "CustomAppDelegate"
        assert confidence == "medium"

    def test_multiple_objc_candidates(self, dd):
        """Multiple ObjC candidates should still return one (low confidence)."""
        strings_out = "FooAppDelegate\nBarAppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, _method, _confidence = dd.detect_delegate("/path/NoSwift")

        assert name is not None
        assert "AppDelegate" in name

    def test_gul_delegate_swizzler_filtered(self, dd):
        """GULAppDelegateSwizzler should be filtered out."""
        strings_out = "GULAppDelegateSwizzler\nRealAppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, _method, _confidence = dd.detect_delegate("/path/NoSwift")

        assert name == "RealAppDelegate"

    def test_plain_appdelegate_not_matched_by_regex(self, dd):
        """Plain 'AppDelegate' does NOT match the ObjC regex (known limitation).

        The regex ``^[A-Z][A-Za-z0-9]*AppDelegate$`` requires a prefix.
        """
        strings_out = "AppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, _method, _confidence = dd.detect_delegate("/path/NoSwift")

        # Plain "AppDelegate" falls through ObjC to nm/SwiftUI and eventually no match
        assert name is None

    def test_lowercase_start_rejected(self, dd):
        """Strings starting with lowercase should not match ObjC pattern."""
        strings_out = "myAppDelegate\nanotherAppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, _method, _confidence = dd.detect_delegate("/path/NoSwift")

        # lowercase-starting names don't match ^[A-Z] pattern
        if name is not None:
            assert name[0].isupper() or "_TtC" in name

    def test_long_name_rejected(self, dd):
        """Names >= 60 chars should be rejected."""
        long_name = "A" * 50 + "AppDelegate"  # 61 chars
        strings_out = f"{long_name}\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, _method, _confidence = dd.detect_delegate("/path/NoSwift")

        # Should not match the overly long name via ObjC pattern
        if name is not None:
            assert len(name) < 60


# ===================================================================
# Strategy 4: nm symbol table
# ===================================================================


class TestStrategy4NmSymbols:
    """Detect AppDelegate from nm symbol table output."""

    def test_swift_in_nm(self, dd):
        """Swift mangled AppDelegate in nm output should be found."""
        nm_output = (
            "0000000100001234 T _TtC8MyModule11AppDelegate\n0000000100005678 t _helper_function\n"
        )

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(
                strings_output="no_match_here\n",
                nm_output=nm_output,
            ),
        ):
            name, method, confidence = dd.detect_delegate("/path/NoMatch")

        assert name is not None
        assert "_TtC" in name
        assert "AppDelegate" in name
        assert "nm symbol table" in method
        assert confidence == "high"

    def test_plain_in_nm(self, dd):
        """Plain AppDelegate reference in nm output should be found."""
        nm_output = "0000000100001234 S _AppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(
                strings_output="no_match_here\n",
                nm_output=nm_output,
            ),
        ):
            name, method, _confidence = dd.detect_delegate("/path/NoMatch")

        # The nm fallback should find _AppDelegate
        assert name is not None
        assert "AppDelegate" in name
        assert "nm symbol table" in method


# ===================================================================
# Strategy 5: SwiftUI @main detection
# ===================================================================


class TestStrategy5SwiftUI:
    """Detect SwiftUI @main apps that have no AppDelegate."""

    def test_swiftui_protocol_detected(self, dd):
        """SwiftUI App protocol presence without AppDelegate should be reported."""
        strings_out = "$s7SwiftUI3AppP\nsome_other_string\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, method, confidence = dd.detect_delegate("/path/SwiftUIApp")

        assert name is None
        assert "SwiftUI" in method
        assert confidence is None

    def test_swiftui_with_main_symbol(self, dd):
        """SwiftUI app with $s...V5$mainyyFZ symbol should report the entry."""
        strings_out = "$s7SwiftUI3AppP\n$s7TestApp0A0V5$mainyyFZ\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, method, _confidence = dd.detect_delegate("/path/TestApp")

        assert name is None
        assert "SwiftUI @main" in method
        # The method string should mention the entry symbol
        assert "$mainyyFZ" in method

    def test_swiftui_main_in_nm(self, dd):
        """SwiftUI main symbol found in nm should be reported."""
        nm_output = "0000000100001234 T $s7TestApp0A0V5$mainyyFZ\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(
                strings_output="no_matches\n",
                nm_output=nm_output,
            ),
        ):
            name, method, _confidence = dd.detect_delegate("/path/TestApp")

        assert name is None
        assert "$mainyyFZ" in method


# ===================================================================
# Strategy 6: __objc_classlist walk (encrypted-symbol fallback)
# ===================================================================


class TestStrategy6ClasslistWalk:
    """Walk __objc_classlist when symbol-table tiers find nothing.

    Tier 6 fires when tiers 1-5 all return None. We mock
    `_walk_classlist_for_appdelegate` to simulate the Mach-O walk so we
    don't need a synthetic chained-fixup binary.
    """

    def _strings_no_match(self):
        # Strings output that doesn't trigger tiers 1-3 (no AppDelegate
        # patterns, no SwiftUI). Tier 4 (nm) is also empty so we land at
        # tier 6 cleanly.
        return "random_string\nplain_text\n"

    def test_swift_match_from_classlist(self, dd):
        """A Swift mangled name returned by the classlist walk should win."""
        with (
            patch(
                "subprocess.run",
                side_effect=_mock_subprocess_calls(
                    strings_output=self._strings_no_match(), nm_output=""
                ),
            ),
            patch.object(
                dd,
                "_walk_classlist_for_appdelegate",
                return_value=([("_TtC8MyModule11AppDelegate", 2)], 200, 198),
            ),
        ):
            name, method, confidence = dd.detect_delegate("/path/MyModule")

        assert name == "_TtC8MyModule11AppDelegate"
        assert "__objc_classlist walk" in method
        assert "198 names skipped" in method
        # Single candidate -> medium confidence.
        assert confidence == "medium"

    def test_objc_match_from_classlist(self, dd):
        """An ObjC class name returned by the classlist walk should win."""
        with (
            patch(
                "subprocess.run",
                side_effect=_mock_subprocess_calls(
                    strings_output=self._strings_no_match(), nm_output=""
                ),
            ),
            patch.object(
                dd,
                "_walk_classlist_for_appdelegate",
                return_value=([("MyAppDelegate", 1)], 50, 0),
            ),
        ):
            name, method, confidence = dd.detect_delegate("/path/Whatever")

        assert name == "MyAppDelegate"
        assert "__objc_classlist walk" in method
        assert confidence == "medium"

    def test_classlist_prefers_swift_over_objc(self, dd):
        """Among multiple matches, Swift mangled (score=2) beats plain ObjC (score=1)."""
        with (
            patch(
                "subprocess.run",
                side_effect=_mock_subprocess_calls(
                    strings_output=self._strings_no_match(), nm_output=""
                ),
            ),
            patch.object(
                dd,
                "_walk_classlist_for_appdelegate",
                return_value=(
                    [("FooAppDelegate", 1), ("_TtC8RealMod11AppDelegate", 2)],
                    100,
                    90,
                ),
            ),
        ):
            name, _method, confidence = dd.detect_delegate("/path/RealMod")

        assert name == "_TtC8RealMod11AppDelegate"
        # >1 candidate -> low confidence.
        assert confidence == "low"

    def test_classlist_prefers_module_match(self, dd):
        """Among same-score matches, prefers names containing the module."""
        with (
            patch(
                "subprocess.run",
                side_effect=_mock_subprocess_calls(
                    strings_output=self._strings_no_match(), nm_output=""
                ),
            ),
            patch.object(
                dd,
                "_walk_classlist_for_appdelegate",
                return_value=(
                    [("OtherAppDelegate", 1), ("CoupangAppDelegate", 1)],
                    500,
                    498,
                ),
            ),
        ):
            name, _method, _confidence = dd.detect_delegate("/path/Coupang_New")

        assert name == "CoupangAppDelegate"

    def test_all_names_in_crypt_returns_none_with_hint(self, dd):
        """When all class names live in the crypt region, return None with a guess hint."""
        with (
            patch(
                "subprocess.run",
                side_effect=_mock_subprocess_calls(
                    strings_output=self._strings_no_match(), nm_output=""
                ),
            ),
            patch.object(
                dd,
                "_walk_classlist_for_appdelegate",
                return_value=([], 7951, 7951),
            ),
        ):
            name, method, confidence = dd.detect_delegate("/path/Coupang_New")

        assert name is None
        assert confidence is None
        # Should hint at the convention-based delegate name.
        assert "Coupang_New" in method
        assert "_TtC11Coupang_New11AppDelegate" in method
        # Reason should reference the crypt region.
        assert "crypt" in method.lower()


class TestClasslistHelpers:
    """Direct tests of the tier 6 helper functions."""

    def test_decode_chained_ptr64_rebase(self, dd):
        """A rebase entry decodes target/high8/next/bind correctly."""
        # target=0x1234, next=0x10, bind=0
        raw = (0x10 << 51) | 0x1234
        target, _high8, nxt, bind = dd._decode_chained_ptr64(raw)
        assert target == 0x1234
        assert nxt == 0x10
        assert bind == 0

    def test_decode_chained_ptr64_bind(self, dd):
        """A bind entry sets bind=1."""
        raw = 1 << 63
        _t, _h, _n, bind = dd._decode_chained_ptr64(raw)
        assert bind == 1

    def test_read_cstring_basic(self, dd):
        data = b"\x00hello\x00world\x00"
        # Read at offset 1 (skip the leading null).
        assert dd._read_cstring(1, data) == "hello"
        # Read at offset 7 (after the second null).
        assert dd._read_cstring(7, data) == "world"

    def test_read_cstring_empty_returns_none(self, dd):
        # A zero-length string (nul at the start) returns None.
        data = b"\x00abc"
        assert dd._read_cstring(0, data) is None

    def test_read_cstring_too_long_returns_none(self, dd):
        # A string longer than max_len returns None.
        data = b"A" * 300 + b"\x00"
        assert dd._read_cstring(0, data, max_len=200) is None

    def test_walk_classlist_handles_missing_file(self, dd):
        """A nonexistent binary returns ([], 0, 0) — never raises."""
        result = dd._walk_classlist_for_appdelegate("/nonexistent/binary/path")
        assert result == ([], 0, 0)

    def test_walk_classlist_handles_bad_magic(self, dd, tmp_path):
        """A non-Mach-O file returns ([], 0, 0) instead of raising."""
        bad = tmp_path / "not_macho.bin"
        bad.write_bytes(b"\x00" * 64)  # zeros — wrong magic
        result = dd._walk_classlist_for_appdelegate(str(bad))
        assert result == ([], 0, 0)


# ===================================================================
# No match at all
# ===================================================================


class TestNoMatch:
    """When no detection strategy succeeds."""

    def test_no_delegate_found(self, dd):
        """Should return (None, reason, None) when nothing matches."""
        strings_out = "random_string\nanother_string\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, method, confidence = dd.detect_delegate("/path/Unknown")

        assert name is None
        assert confidence is None
        assert "manual investigation" in method.lower() or "no" in method.lower()

    def test_empty_strings_output(self, dd):
        """Empty strings output should gracefully return no match."""
        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output="", nm_output="")
        ):
            name, _method, confidence = dd.detect_delegate("/path/Empty")

        assert name is None
        assert confidence is None


# ===================================================================
# Priority ordering
# ===================================================================


class TestDetectionPriority:
    """Verify detection strategies run in the correct priority order."""

    def test_swift_exact_beats_objc(self, dd):
        """Strategy 1 (Swift exact) should take priority over Strategy 3 (ObjC)."""
        strings_out = "_TtC7TestApp11AppDelegate\nMyAppDelegate\n"

        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
        ):
            name, method, _confidence = dd.detect_delegate("/path/TestApp")

        assert name == "_TtC7TestApp11AppDelegate"
        assert "Swift mangled" in method

    def test_swift_exact_beats_swift_any(self, dd):
        """Strategy 1 (exact module) should beat Strategy 2 (any module)."""
        strings_out = "_TtC7TestApp11AppDelegate\n_TtC10OtherMod11AppDelegate\n"

        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
        ):
            name, method, _confidence = dd.detect_delegate("/path/TestApp")

        assert name == "_TtC7TestApp11AppDelegate"
        assert "exact module match" in method

    def test_objc_beats_nm(self, dd):
        """Strategy 3 (ObjC strings) should take priority over Strategy 4 (nm)."""
        strings_out = "MyAppDelegate\n"
        nm_output = "0000000100001234 T _TtC8SomeLib11AppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=nm_output),
        ):
            name, method, _confidence = dd.detect_delegate("/path/NoSwift")

        assert name == "MyAppDelegate"
        assert "ObjC" in method

    def test_nm_beats_swiftui(self, dd):
        """Strategy 4 (nm) should take priority over Strategy 5 (SwiftUI)."""
        nm_output = "0000000100001234 T _TtC8SomeApp11AppDelegate\n"
        strings_out = "$s7SwiftUI3AppP\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=nm_output),
        ):
            name, _method, _confidence = dd.detect_delegate("/path/SomeApp")

        assert name is not None
        assert "AppDelegate" in name


# ===================================================================
# Edge cases
# ===================================================================


class TestEdgeCases:
    """Edge cases and robustness tests."""

    def test_whitespace_in_strings(self, dd):
        """Strings with leading/trailing whitespace should be stripped."""
        strings_out = "  _TtC7TestApp11AppDelegate  \n  MyAppDelegate  \n"

        with patch(
            "subprocess.run", side_effect=_mock_subprocess_calls(strings_output=strings_out)
        ):
            name, _method, _confidence = dd.detect_delegate("/path/TestApp")

        assert name == "_TtC7TestApp11AppDelegate"

    def test_duplicate_strings(self, dd):
        """Duplicate strings should not cause double-counting."""
        strings_out = "MyAppDelegate\nMyAppDelegate\nMyAppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, method, confidence = dd.detect_delegate("/path/NoSwift")

        assert name == "MyAppDelegate"
        assert "ObjC" in method
        # Should be single match (after dedup), medium confidence
        assert confidence == "medium"

    def test_binary_name_with_special_chars(self, dd):
        """Binary name with dots or hyphens should still work for module detection."""
        strings_out = "MyAppDelegate\n"

        with patch(
            "subprocess.run",
            side_effect=_mock_subprocess_calls(strings_output=strings_out, nm_output=""),
        ):
            name, _method, _confidence = dd.detect_delegate("/path/My-App.v2")

        assert name == "MyAppDelegate"

    def test_subprocess_exception_handled(self, dd):
        """If subprocess throws, should gracefully return no match."""
        with patch("subprocess.run", side_effect=OSError("broken")):
            name, _method, confidence = dd.detect_delegate("/path/Broken")

        assert name is None
        assert confidence is None
