from __future__ import annotations

import argparse
import sys

from darkmach.commands import (
    cmd_analyze,
    cmd_bridge,
    cmd_discover,
    cmd_hermes,
    cmd_keychain,
    cmd_launch,
    cmd_list,
    cmd_patch,
    cmd_run,
    cmd_status,
)
from darkmach.pipeline.process import DarkmachError, log


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="darkmach",
        description="iOS reverse engineering pipeline for Apple Silicon",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    strip_help = "Re-sign with no entitlements (unprivileged control baseline)"

    p_run = sub.add_parser("run", help="Full pipeline: analyze → patch → install → launch → bridge")
    p_run.add_argument("app", help="Path to .app (e.g., /Applications/AppName.app)")
    p_run.add_argument("--strip-entitlements", action="store_true", help=strip_help)

    p_analyze = sub.add_parser("analyze", help="Static analysis only")
    p_analyze.add_argument("app", help="Path to .app")
    p_analyze.add_argument("-o", "--output", help="Output directory")

    p_patch = sub.add_parser("patch", help="Patch bundle for Simulator")
    p_patch.add_argument("app", help="Path to .app")
    p_patch.add_argument("--strip-entitlements", action="store_true", help=strip_help)

    p_launch = sub.add_parser("launch", help="Launch installed app with interceptors")
    p_launch.add_argument("bundle_id", help="Bundle ID (e.g., com.oddsjam.app)")
    p_launch.add_argument("--ssl-bypass", action="store_true", help="Bypass SSL pinning")

    sub.add_parser("bridge", help="Connect to running bridge (interactive)")

    p_discover = sub.add_parser("discover", help="Find iOS apps available on Mac")
    p_discover.add_argument("search", nargs="?", help="Search term")
    p_discover.add_argument("--category", help="Category ID or 'all'")
    p_discover.add_argument("--ids", help="Comma-separated app IDs")
    p_discover.add_argument("--limit", type=int, default=25, help="Max results (default: 25)")
    p_discover.add_argument("-o", "--output", help="Output file path")
    p_discover.add_argument(
        "--token", help="amp-api Bearer token (overrides DARKMACH_AMP_TOKEN env var)"
    )

    p_hermes = sub.add_parser("hermes", help="Extract secrets from Hermes bytecode")
    p_hermes.add_argument("app", help="Path to .app or .jsbundle")
    p_hermes.add_argument("-o", "--output", help="Output directory")
    p_hermes.add_argument("--json", action="store_true", help="JSON output")

    p_keychain = sub.add_parser("keychain", help="Read Simulator keychain (host-side)")
    p_keychain.add_argument("--udid", help="Simulator UDID (auto-detects booted)")
    p_keychain.add_argument("--json", action="store_true", help="JSON output")

    sub.add_parser("list", help="List installed iOS apps")

    sub.add_parser("status", help="System pre-flight check")

    args = parser.parse_args()

    commands = {
        "run": cmd_run,
        "analyze": cmd_analyze,
        "patch": cmd_patch,
        "launch": cmd_launch,
        "bridge": cmd_bridge,
        "discover": cmd_discover,
        "hermes": cmd_hermes,
        "keychain": cmd_keychain,
        "list": cmd_list,
        "status": cmd_status,
    }

    try:
        return commands[args.command](args)
    except DarkmachError as e:
        log(f"ERROR: {e}")
        return 1
    except KeyboardInterrupt:
        print()
        return 130


def entrypoint() -> None:
    """Entry point for pipx/console_scripts."""
    sys.exit(main())


if __name__ == "__main__":
    entrypoint()
