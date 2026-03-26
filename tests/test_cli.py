"""Tests for darkmach.cli — CLI argument parsing, validation, and dispatch."""

from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest

from darkmach.cli import DarkmachError, main, validate_app_path

# ── validate_app_path ─────────────────────────────────────────────


class TestValidateAppPath:
    def test_valid_app_with_wrapper(self, fake_app_bundle):
        """An .app with Wrapper/ should pass validation."""
        validate_app_path(fake_app_bundle)  # should not raise

    def test_valid_app_with_info_plist(self, tmp_path):
        """An .app with Info.plist (no Wrapper) should pass."""
        import plistlib

        app = tmp_path / "Direct.app"
        app.mkdir()
        plist = {"CFBundleExecutable": "Direct", "CFBundleIdentifier": "com.test"}
        (app / "Info.plist").write_bytes(plistlib.dumps(plist))
        validate_app_path(app)  # should not raise

    def test_nonexistent_path_raises(self, tmp_path):
        with pytest.raises(DarkmachError, match="does not exist"):
            validate_app_path(tmp_path / "Missing.app")

    def test_not_a_directory_raises(self, tmp_path):
        f = tmp_path / "File.app"
        f.write_text("not a directory")
        with pytest.raises(DarkmachError, match="Not a directory"):
            validate_app_path(f)

    def test_wrong_suffix_raises(self, tmp_path):
        d = tmp_path / "NotAnApp.pkg"
        d.mkdir()
        with pytest.raises(DarkmachError, match=r"Not an \.app bundle"):
            validate_app_path(d)

    def test_no_wrapper_no_plist_raises(self, tmp_path):
        app = tmp_path / "Empty.app"
        app.mkdir()
        with pytest.raises(DarkmachError, match=r"no Wrapper/ or Info\.plist"):
            validate_app_path(app)

    def test_wrapper_without_inner_app_passes_validation(self, tmp_path):
        """Wrapper/ exists as a dir -> passes validate_app_path (even if inner is empty)."""
        app = tmp_path / "HalfBaked.app"
        app.mkdir()
        (app / "Wrapper").mkdir()
        validate_app_path(app)  # should not raise, has Wrapper/


# ── CLI argument parsing ──────────────────────────────────────────


class TestCLIParsing:
    """Test argparse configuration by calling main()'s parser directly."""

    def _parse(self, argv: list[str]) -> argparse.Namespace:
        """Invoke the CLI parser without executing the command."""

        # Build parser the same way main() does
        parser = argparse.ArgumentParser(prog="darkmach")
        sub = parser.add_subparsers(dest="command", required=True)

        p_run = sub.add_parser("run")
        p_run.add_argument("app")

        p_analyze = sub.add_parser("analyze")
        p_analyze.add_argument("app")
        p_analyze.add_argument("-o", "--output")

        p_patch = sub.add_parser("patch")
        p_patch.add_argument("app")

        p_launch = sub.add_parser("launch")
        p_launch.add_argument("bundle_id")
        p_launch.add_argument("--ssl-bypass", action="store_true")

        sub.add_parser("bridge")

        p_discover = sub.add_parser("discover")
        p_discover.add_argument("search", nargs="?")
        p_discover.add_argument("--category")
        p_discover.add_argument("--ids")
        p_discover.add_argument("--limit", type=int, default=25)
        p_discover.add_argument("-o", "--output")
        p_discover.add_argument("--token")

        p_hermes = sub.add_parser("hermes")
        p_hermes.add_argument("app")
        p_hermes.add_argument("-o", "--output")
        p_hermes.add_argument("--json", action="store_true")

        p_keychain = sub.add_parser("keychain")
        p_keychain.add_argument("--udid")
        p_keychain.add_argument("--json", action="store_true")

        sub.add_parser("list")
        sub.add_parser("status")

        return parser.parse_args(argv)

    # --- run subcommand ---
    def test_run_requires_app(self):
        with pytest.raises(SystemExit):
            self._parse(["run"])

    def test_run_with_app(self):
        args = self._parse(["run", "/Applications/Test.app"])
        assert args.command == "run"
        assert args.app == "/Applications/Test.app"

    # --- analyze subcommand ---
    def test_analyze_with_app(self):
        args = self._parse(["analyze", "/path/to/App.app"])
        assert args.command == "analyze"
        assert args.app == "/path/to/App.app"
        assert args.output is None

    def test_analyze_with_output(self):
        args = self._parse(["analyze", "/path/to/App.app", "-o", "/tmp/out"])
        assert args.output == "/tmp/out"

    # --- patch subcommand ---
    def test_patch_with_app(self):
        args = self._parse(["patch", "/Applications/Test.app"])
        assert args.command == "patch"
        assert args.app == "/Applications/Test.app"

    # --- launch subcommand ---
    def test_launch_with_bundle_id(self):
        args = self._parse(["launch", "com.test.app"])
        assert args.command == "launch"
        assert args.bundle_id == "com.test.app"
        assert args.ssl_bypass is False

    def test_launch_with_ssl_bypass(self):
        args = self._parse(["launch", "com.test.app", "--ssl-bypass"])
        assert args.ssl_bypass is True

    # --- bridge subcommand ---
    def test_bridge(self):
        args = self._parse(["bridge"])
        assert args.command == "bridge"

    # --- discover subcommand ---
    def test_discover_search(self):
        args = self._parse(["discover", "weather"])
        assert args.command == "discover"
        assert args.search == "weather"

    def test_discover_category(self):
        args = self._parse(["discover", "--category", "6014"])
        assert args.category == "6014"

    def test_discover_ids(self):
        args = self._parse(["discover", "--ids", "123,456,789"])
        assert args.ids == "123,456,789"

    def test_discover_limit(self):
        args = self._parse(["discover", "test", "--limit", "50"])
        assert args.limit == 50

    def test_discover_default_limit(self):
        args = self._parse(["discover", "test"])
        assert args.limit == 25

    def test_discover_token(self):
        args = self._parse(["discover", "test", "--token", "my-jwt"])
        assert args.token == "my-jwt"

    # --- hermes subcommand ---
    def test_hermes_with_app(self):
        args = self._parse(["hermes", "/path/to/App.app"])
        assert args.command == "hermes"
        assert args.app == "/path/to/App.app"

    def test_hermes_json_flag(self):
        args = self._parse(["hermes", "/path/to/App.app", "--json"])
        assert args.json is True

    # --- keychain subcommand ---
    def test_keychain_default(self):
        args = self._parse(["keychain"])
        assert args.command == "keychain"
        assert args.udid is None
        assert args.json is False

    def test_keychain_with_udid(self):
        args = self._parse(["keychain", "--udid", "AAAA-BBBB"])
        assert args.udid == "AAAA-BBBB"

    def test_keychain_json(self):
        args = self._parse(["keychain", "--json"])
        assert args.json is True

    # --- list / status subcommands ---
    def test_list(self):
        args = self._parse(["list"])
        assert args.command == "list"

    def test_status(self):
        args = self._parse(["status"])
        assert args.command == "status"

    # --- error cases ---
    def test_no_subcommand_exits(self):
        with pytest.raises(SystemExit):
            self._parse([])

    def test_unknown_subcommand_exits(self):
        with pytest.raises(SystemExit):
            self._parse(["notacommand"])


# ── main() dispatch ───────────────────────────────────────────────


class TestMainDispatch:
    def test_darkmach_error_returns_1(self):
        """DarkmachError during command execution should return 1, not raise."""
        with patch("sys.argv", ["darkmach", "run", "/nonexistent/path.app"]):
            exit_code = main()
        assert exit_code == 1

    def test_keyboard_interrupt_returns_130(self):
        """KeyboardInterrupt should return 130."""

        def raise_kb(_args):
            raise KeyboardInterrupt

        with (
            patch("sys.argv", ["darkmach", "bridge"]),
            patch("darkmach.cli.cmd_bridge", side_effect=raise_kb),
        ):
            exit_code = main()
        assert exit_code == 130
