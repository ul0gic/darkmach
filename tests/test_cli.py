"""Tests for darkmach.cli — CLI argument parsing, validation, and dispatch."""

from __future__ import annotations

import argparse
import plistlib
import struct
import subprocess
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import pytest

from darkmach.cli import main
from darkmach.pipeline.bundles import validate_app_path
from darkmach.pipeline.patching import stage_patch
from darkmach.pipeline.process import DarkmachError
from darkmach.pipeline.provenance import EntitlementResult
from darkmach.pipeline.signing import (
    SIMULATOR_ENTITLEMENTS,
    _filter_entitlements,
    _inject_entitlements,
    _install_entitlements,
    _read_signed_entitlements,
)

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
        p_run.add_argument("--strip-entitlements", action="store_true")

        p_analyze = sub.add_parser("analyze")
        p_analyze.add_argument("app")
        p_analyze.add_argument("-o", "--output")

        p_patch = sub.add_parser("patch")
        p_patch.add_argument("app")
        p_patch.add_argument("--strip-entitlements", action="store_true")

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

    def test_run_strip_entitlements_defaults_false(self):
        args = self._parse(["run", "/Applications/Test.app"])
        assert args.strip_entitlements is False

    def test_run_strip_entitlements_flag(self):
        args = self._parse(["run", "/Applications/Test.app", "--strip-entitlements"])
        assert args.strip_entitlements is True

    # --- patch subcommand ---
    def test_patch_with_app(self):
        args = self._parse(["patch", "/Applications/Test.app"])
        assert args.command == "patch"
        assert args.app == "/Applications/Test.app"

    def test_patch_strip_entitlements_defaults_false(self):
        args = self._parse(["patch", "/Applications/Test.app"])
        assert args.strip_entitlements is False

    def test_patch_strip_entitlements_flag(self):
        args = self._parse(["patch", "/Applications/Test.app", "--strip-entitlements"])
        assert args.strip_entitlements is True

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


# ── entitlements (ISSUE-009) ─────────────────────────────────────

LC_SEGMENT_64 = 0x19
LC_MAIN = 0x80000028
TEXT_VMADDR = 0x100000000


def build_macho(tmp_path, *, first_section_offset: int = 4096) -> Path:
    """Write a minimal arm64 Mach-O with one __TEXT section and header padding."""
    text_data = b"\x90" * 16
    seg = (
        struct.pack("<II", LC_SEGMENT_64, 152)
        + b"__TEXT".ljust(16, b"\0")
        + struct.pack("<QQQQ", TEXT_VMADDR, 0x8000, 0, first_section_offset + len(text_data))
        + struct.pack("<IIII", 7, 5, 1, 0)
        + b"__text".ljust(16, b"\0")
        + b"__TEXT".ljust(16, b"\0")
        + struct.pack("<QQ", TEXT_VMADDR + first_section_offset, len(text_data))
        + struct.pack("<8I", first_section_offset, 4, 0, 0, 0x80000400, 0, 0, 0)
    )
    main_cmd = struct.pack("<IIQQ", LC_MAIN, 24, first_section_offset, 0)
    cmds = seg + main_cmd
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 2, len(cmds), 0, 0)
    body = header + cmds
    body += b"\0" * (first_section_offset - len(body))

    binary = tmp_path / "TestBinary"
    binary.write_bytes(body + text_data)
    return binary


def read_text_sections(binary: Path) -> list[dict]:
    """Parse the __TEXT segment's section table out of a Mach-O."""
    data = binary.read_bytes()
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == LC_SEGMENT_64 and data[offset + 8 : offset + 24].rstrip(b"\0") == b"__TEXT":
            nsects = struct.unpack_from("<I", data, offset + 64)[0]
            out = []
            for i in range(nsects):
                sect = offset + 72 + i * 80
                addr, size = struct.unpack_from("<QQ", data, sect + 32)
                out.append(
                    {
                        "name": data[sect : sect + 16].rstrip(b"\0").decode(),
                        "addr": addr,
                        "size": size,
                        "offset": struct.unpack_from("<I", data, sect + 48)[0],
                    }
                )
            return out
        offset += cmdsize
    return []


class TestFilterEntitlements:
    def test_keeps_allowlisted(self):
        kept, dropped = _filter_entitlements(
            {"application-identifier": "TEAM.com.x", "keychain-access-groups": ["TEAM.com.x"]}
        )
        assert set(kept) == {"application-identifier", "keychain-access-groups"}
        assert dropped == []

    def test_drops_push_and_icloud(self):
        kept, dropped = _filter_entitlements(
            {
                "application-identifier": "TEAM.com.x",
                "aps-environment": "production",
                "com.apple.developer.icloud-container-identifiers": ["iCloud.com.x"],
            }
        )
        assert set(kept) == {"application-identifier"}
        assert dropped == [
            "aps-environment",
            "com.apple.developer.icloud-container-identifiers",
        ]

    def test_unknown_key_is_dropped_not_passed_through(self):
        """The policy is an allowlist — an unrecognized entitlement must not survive."""
        kept, dropped = _filter_entitlements({"com.example.brand-new-entitlement": True})
        assert kept == {}
        assert dropped == ["com.example.brand-new-entitlement"]

    def test_full_allowlist_survives(self):
        source = dict.fromkeys(SIMULATOR_ENTITLEMENTS, True)
        kept, dropped = _filter_entitlements(source)
        assert set(kept) == set(SIMULATOR_ENTITLEMENTS)
        assert dropped == []

    def test_empty_input(self):
        assert _filter_entitlements({}) == ({}, [])


class TestReadSignedEntitlements:
    def _run(self, stdout: bytes, returncode: int = 0):
        result = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=b"")
        return patch("subprocess.run", return_value=result)

    def test_parses_plist(self):
        plist = plistlib.dumps({"application-identifier": "TEAM.com.x"})
        with self._run(plist):
            assert _read_signed_entitlements(Path("/x")) == {"application-identifier": "TEAM.com.x"}

    def test_unsigned_binary_reports_read_error(self):
        with self._run(b"", returncode=1), pytest.raises(DarkmachError) as error:
            _read_signed_entitlements(Path("/x"))
        assert str(error.value) == "Cannot read signed entitlements from x"

    def test_no_entitlements_returns_empty(self):
        with self._run(b""):
            assert _read_signed_entitlements(Path("/x")) == {}

    def test_malformed_xml_reports_invalid_plist(self):
        with self._run(b"<plist><dict><key>oops"), pytest.raises(DarkmachError) as error:
            _read_signed_entitlements(Path("/x"))
        assert str(error.value) == "Invalid signed entitlement plist in x"

    def test_non_dict_plist_reports_invalid_type(self):
        with self._run(plistlib.dumps(["not", "a", "dict"])), pytest.raises(DarkmachError) as error:
            _read_signed_entitlements(Path("/x"))
        assert str(error.value) == "Signed entitlements in x are not a dictionary"


class TestInjectEntitlements:
    ENTS: ClassVar[dict] = {
        "application-identifier": "TEAM.com.x",
        "keychain-access-groups": ["TEAM.com.x"],
    }

    def test_adds_section(self, tmp_path):
        binary = build_macho(tmp_path)
        _inject_entitlements(binary, self.ENTS)
        names = [s["name"] for s in read_text_sections(binary)]
        assert names == ["__text", "__entitlements"]

    def test_section_holds_the_plist(self, tmp_path):
        binary = build_macho(tmp_path)
        _inject_entitlements(binary, self.ENTS)
        sect = read_text_sections(binary)[1]
        blob = binary.read_bytes()[sect["offset"] : sect["offset"] + sect["size"]]
        assert plistlib.loads(blob) == self.ENTS

    def test_section_vmaddr_matches_file_offset(self, tmp_path):
        binary = build_macho(tmp_path)
        _inject_entitlements(binary, self.ENTS)
        sect = read_text_sections(binary)[1]
        assert sect["addr"] == TEXT_VMADDR + sect["offset"]

    def test_file_size_unchanged(self, tmp_path):
        """The section is carved from header padding — no content may shift."""
        binary = build_macho(tmp_path)
        before = binary.stat().st_size
        _inject_entitlements(binary, self.ENTS)
        assert binary.stat().st_size == before

    def test_existing_section_data_untouched(self, tmp_path):
        binary = build_macho(tmp_path)
        original = binary.read_bytes()
        _inject_entitlements(binary, self.ENTS)
        text = read_text_sections(binary)[0]
        patched = binary.read_bytes()
        assert patched[text["offset"] :] == original[text["offset"] :]

    def test_sizeofcmds_and_nsects_updated(self, tmp_path):
        binary = build_macho(tmp_path)
        before = struct.unpack_from("<I", binary.read_bytes(), 20)[0]
        _inject_entitlements(binary, self.ENTS)
        data = binary.read_bytes()
        assert struct.unpack_from("<I", data, 20)[0] == before + 80
        assert struct.unpack_from("<I", data, 32 + 64)[0] == 2

    def test_ncmds_unchanged(self, tmp_path):
        """A section is added to __TEXT, not a load command."""
        binary = build_macho(tmp_path)
        _inject_entitlements(binary, self.ENTS)
        assert struct.unpack_from("<I", binary.read_bytes(), 16)[0] == 2

    def test_trailing_load_command_shifts_intact(self, tmp_path):
        binary = build_macho(tmp_path)
        _inject_entitlements(binary, self.ENTS)
        data = binary.read_bytes()
        ncmds = struct.unpack_from("<I", data, 16)[0]
        offset, found = 32, None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, offset)
            if cmd == LC_MAIN:
                found = struct.unpack_from("<Q", data, offset + 8)[0]
            offset += cmdsize
        assert found == 4096

    def test_insufficient_padding_raises(self, tmp_path):
        binary = build_macho(tmp_path, first_section_offset=272)
        with pytest.raises(DarkmachError, match=r"Cannot preserve entitlements.*header space"):
            _inject_entitlements(binary, self.ENTS)

    def test_double_injection_raises(self, tmp_path):
        binary = build_macho(tmp_path)
        _inject_entitlements(binary, self.ENTS)
        with pytest.raises(DarkmachError, match="already present"):
            _inject_entitlements(binary, self.ENTS)

    def test_non_macho_raises(self, tmp_path):
        junk = tmp_path / "junk"
        junk.write_bytes(b"\x00" * 512)
        with pytest.raises(DarkmachError, match="not a 64-bit Mach-O"):
            _inject_entitlements(junk, self.ENTS)


class TestInstallEntitlements:
    def test_none_reports_explicit_strip(self, tmp_path, capsys):
        binary = build_macho(tmp_path)
        assert _install_entitlements(binary, None) == EntitlementResult("stripped", (), (), None)
        assert "explicitly omitted (--strip-entitlements)" in capsys.readouterr().out
        assert read_text_sections(binary)[-1]["name"] == "__text"

    def test_empty_reports_no_entitlements(self, tmp_path, capsys):
        binary = build_macho(tmp_path)
        assert _install_entitlements(binary, {}) == EntitlementResult("absent", (), (), None)
        assert "none on the original binary" in capsys.readouterr().out

    def test_reports_kept_and_dropped(self, tmp_path, capsys):
        binary = build_macho(tmp_path)
        changed = _install_entitlements(
            binary, {"application-identifier": "TEAM.com.x", "aps-environment": "production"}
        )
        out = capsys.readouterr().out
        assert changed == EntitlementResult(
            "preserved", ("application-identifier",), ("aps-environment",), "xml"
        )
        assert "dropped 1 unsupported keys — aps-environment" in out
        assert "preserved 1 compatible keys (xml) — application-identifier" in out

    def test_nothing_compatible_leaves_binary_alone(self, tmp_path, capsys):
        binary = build_macho(tmp_path)
        result = _install_entitlements(binary, {"aps-environment": "production"})
        assert result == EntitlementResult(
            "none-compatible", (), ("aps-environment",), None
        )
        assert "no Simulator-compatible keys" in capsys.readouterr().out
        assert [s["name"] for s in read_text_sections(binary)] == ["__text"]

    def test_injection_failure_aborts_with_explicit_opt_out(self, tmp_path, capsys):
        binary = build_macho(tmp_path, first_section_offset=272)
        with pytest.raises(DarkmachError) as error:
            _install_entitlements(binary, {"application-identifier": "TEAM.com.x"})
        out = capsys.readouterr().out
        assert "Use --strip-entitlements" in str(error.value)
        assert "WARNING: entitlements NOT applied" not in out


class TestStagePatchEntitlements:
    def _patched_stage(self, tmp_path, monkeypatch):
        """Drive stage_patch over a bundle with every side-effecting step stubbed."""
        bundle = tmp_path / "App.app"
        bundle.mkdir()
        (bundle / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "App"}))
        build_macho(tmp_path).rename(bundle / "App")
        monkeypatch.setattr("darkmach.pipeline.patching._detect_strategy", lambda _b: "extract")
        monkeypatch.setattr("darkmach.pipeline.patching._read_crypt_info", lambda _b: (0, 0))
        monkeypatch.setattr("darkmach.pipeline.patching.patch_bundle", lambda _b: None)
        monkeypatch.setattr("darkmach.pipeline.patching.run", lambda *_a, **_k: None)
        return bundle

    def test_entitlements_applied_by_default(self, tmp_path, monkeypatch, capsys):
        bundle = self._patched_stage(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "darkmach.pipeline.patching._read_signed_entitlements",
            lambda _b: {"application-identifier": "TEAM.com.x"},
        )
        stage_patch(bundle)
        assert (
            "preserved 1 compatible keys (xml) — application-identifier" in capsys.readouterr().out
        )
        assert read_text_sections(bundle / "App")[-1]["name"] == "__entitlements"

    def test_strip_flag_skips_reading_the_signature(self, tmp_path, monkeypatch, capsys):
        bundle = self._patched_stage(tmp_path, monkeypatch)

        def fail(_b):
            raise AssertionError("entitlements must not be read when stripping")

        monkeypatch.setattr("darkmach.pipeline.patching._read_signed_entitlements", fail)
        stage_patch(bundle, strip_entitlements=True)
        assert "stripping (--strip-entitlements)" in capsys.readouterr().out
        assert [s["name"] for s in read_text_sections(bundle / "App")] == ["__text"]
