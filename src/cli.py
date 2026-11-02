from __future__ import annotations

import argparse
import functools
import shutil
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
    formatter = functools.partial(
        argparse.RawDescriptionHelpFormatter,
        width=min(shutil.get_terminal_size((88, 24)).columns, 100),
        max_help_position=28,
    )
    parser = argparse.ArgumentParser(
        prog="darkmach",
        description="Inspect Mac App Store iOS apps and run patched copies in Simulator.",
        formatter_class=formatter,
        epilog=(
            "Examples:\n"
            "  darkmach list\n"
            "  darkmach run /Applications/Example.app\n"
            "  darkmach bridge\n\n"
            "Use 'darkmach <command> --help' for options and examples.\n"
            "Replace example paths, bundle IDs and UDIDs with your target's values.\n"
            "DARKMACH_OUTPUT sets the output root; default: ./output."
        ),
    )
    sub = parser.add_subparsers(title="commands", dest="command", metavar="COMMAND", required=True)

    strip_help = "Omit app-specific entitlements instead of preserving compatible ones"
    entitlement_note = (
        "Entitlements:\n"
        "  Preserves the original Simulator-compatible keys using XML or binary plist.\n"
        "  A preservation/read/signing failure stops patching before installation.\n"
        "  --strip-entitlements explicitly omits these app capabilities.\n"
        "  Encoded keys do not guarantee every original Apple capability."
    )

    p_run = sub.add_parser(
        "run",
        help="Analyze, patch, install, launch and check the bridge",
        description="Run the complete pipeline on a Mac App Store iOS app.",
        formatter_class=formatter,
        epilog=(
            "Examples:\n"
            "  darkmach run /Applications/Example.app\n"
            "  DARKMACH_OUTPUT=./output/demo darkmach run /Applications/Example.app\n\n"
            "The original app is copied before patching. Results are grouped under\n"
            "<output>/<app>/ as static/, dynamic/ and bundle/. The crypt cache is\n"
            "<output>/.cache/crypt/; a cache hit is not a fresh extraction.\n\n"
            "Selects the only booted device; ambiguous selection requires --udid.\n"
            "With none booted, exactly one available iPhone can be auto-selected.\n"
            "Requires full Xcode, an iOS runtime and built interceptor dylibs.\n"
            "Each run writes a stage receipt under <output>/<app>/runs/.\n\n" + entitlement_note
        ),
    )
    p_run.add_argument("app", help="Path to the outer Mac App Store .app or inner iOS .app")
    p_run.add_argument("--strip-entitlements", action="store_true", help=strip_help)

    p_analyze = sub.add_parser(
        "analyze",
        help="Write static analysis reports without launching the app",
        description="Inspect bundle metadata, binary strings, SDKs and candidate secrets.",
        formatter_class=formatter,
        epilog=(
            "Examples:\n"
            "  darkmach analyze /Applications/Example.app\n"
            "  darkmach analyze ./Example.app -o ./reports/example\n\n"
            "Default reports: <output>/<app>/static/. No Simulator launch or patching.\n"
            "Encrypted code and detector limitations can leave findings incomplete.\n"
            "Treat extracted credentials and application data as private evidence."
        ),
    )
    p_analyze.add_argument("app", help="Path to an outer or inner iOS .app bundle")
    p_analyze.add_argument("-o", "--output", help="Report directory (overrides the default)")

    p_patch = sub.add_parser(
        "patch",
        help="Transform an iOS bundle for Simulator without installing it",
        description="Recover encrypted bytes when needed, patch the bundle and re-sign it.",
        formatter_class=formatter,
        epilog=(
            "Examples:\n"
            "  darkmach patch /Applications/Example.app\n"
            "  darkmach patch ./working-copy/Example.app --strip-entitlements\n\n"
            "Apps under /Applications are copied to <output>/<app>/bundle/ first.\n"
            "Other paths are patched in place: supply a disposable copy.\n"
            "Extraction may boot a Simulator and reuse <output>/.cache/crypt/.\n"
            "This command does not install or launch the final patched app.\n\n" + entitlement_note
        ),
    )
    p_patch.add_argument("app", help="Path to the outer Mac App Store .app or inner iOS .app")
    p_patch.add_argument("--strip-entitlements", action="store_true", help=strip_help)

    p_launch = sub.add_parser(
        "launch",
        help="Relaunch an installed patched app with interceptors",
        description="Launch an already-installed bundle and wait for its runtime bridge.",
        formatter_class=formatter,
        epilog=(
            "Examples:\n"
            "  darkmach launch com.example.app\n"
            "  darkmach launch com.example.app --ssl-bypass\n\n"
            "Install the patched bundle first, normally with 'darkmach run'.\n"
            "Selects the only booted device; ambiguous selection requires --udid.\n"
            "With none booted, exactly one available iPhone can be auto-selected.\n"
            "Logs go to <output>/<bundle-id-suffix>/dynamic/. This is a relaunch,\n"
            "not a new extraction. SSL bypass is an explicit opt-in."
        ),
    )
    p_launch.add_argument("bundle_id", help="Installed bundle identifier, such as com.example.app")
    p_launch.add_argument(
        "--ssl-bypass", action="store_true", help="Enable SSL-pinning bypass hooks"
    )

    p_bridge = sub.add_parser(
        "bridge",
        help="Use the runtime REPL or list its commands offline",
        description="Inspect a running instrumented app through the interactive JSON bridge.",
        formatter_class=formatter,
        epilog=(
            "Examples:\n"
            "  darkmach bridge --commands\n"
            "  darkmach bridge\n\n"
            "At the prompt:\n"
            "  info\n"
            "  net_tap limit=5\n"
            '  raw {"cmd":"info"}\n'
            "  help\n"
            "  quit\n\n"
            "Use the endpoint printed by run/launch or choose --udid/--socket.\n"
            "The only booted device is selected when neither option is given.\n"
            "With no booted device, the legacy /tmp/darkmach-bridge.sock is used.\n"
            "--commands is offline and never connects.\n"
            "Replies and captures can contain sensitive application data."
        ),
    )
    p_bridge.add_argument(
        "--commands",
        action="store_true",
        help="Print bridge commands and examples without connecting",
    )

    p_discover = sub.add_parser(
        "discover",
        help="Search App Store availability for iOS apps on Mac",
        description="Query Apple APIs by search term, category or app IDs.",
        formatter_class=formatter,
        epilog=(
            "Examples:\n"
            '  darkmach discover "maintenance" --limit 10\n'
            "  darkmach discover --category all -o ./reports/discovery.json\n"
            "  darkmach discover --ids 123456789,987654321\n\n"
            "Requires network access. Results default to <output>/discover/.\n"
            "Use DARKMACH_AMP_TOKEN for an API token; avoid placing secrets in\n"
            "shell history. This command finds apps; it does not download them."
        ),
    )
    p_discover.add_argument("search", nargs="?", help="App Store search term")
    p_discover.add_argument("--category", help="Category ID or 'all'")
    p_discover.add_argument("--ids", help="Comma-separated app IDs")
    p_discover.add_argument("--limit", type=int, default=25, help="Max results (default: 25)")
    p_discover.add_argument("-o", "--output", help="Results JSON file (overrides the default)")
    p_discover.add_argument(
        "--token", help="API token override; prefer the DARKMACH_AMP_TOKEN environment variable"
    )

    p_hermes = sub.add_parser(
        "hermes",
        help="Inspect JavaScript/Hermes bundles for candidate secrets",
        description="Find JavaScript bundles in an app or inspect one bundle file.",
        formatter_class=formatter,
        epilog=(
            "Examples:\n"
            "  darkmach hermes /Applications/Example.app\n"
            "  darkmach hermes ./main.jsbundle -o ./reports/hermes\n"
            "  darkmach hermes ./main.jsbundle --json > ./hermes.json\n\n"
            "--json writes results to stdout; progress and errors go to stderr.\n"
            "-o retains decompiler artifacts when available; it does not redirect\n"
            "JSON stdout. Default artifacts: <output>/<app>/static/hermes/.\n"
            "Findings are candidates for review, not verified credentials."
        ),
    )
    p_hermes.add_argument("app", help="Path to a .app, JavaScript bundle or Hermes bytecode file")
    p_hermes.add_argument("-o", "--output", help="Directory for available decompiler artifacts")
    p_hermes.add_argument(
        "--json", action="store_true", help="Write result records as JSON to stdout"
    )

    p_keychain = sub.add_parser(
        "keychain",
        help="Read a Simulator keychain database from the host",
        description="Inspect the selected Simulator's keychain database in read-only mode.",
        formatter_class=formatter,
        epilog=(
            "Examples:\n"
            "  darkmach keychain --udid SIMULATOR-UDID\n"
            "  darkmach keychain --udid SIMULATOR-UDID --json > ./keychain.json\n\n"
            "Replace SIMULATOR-UDID with the selected device identifier.\n"
            "Prefer an explicit UDID; otherwise the first booted device is selected.\n"
            "This host-side database view can include data from other apps on that\n"
            "device. Use a dedicated research Simulator and keep output private.\n"
            "No runtime bridge is required."
        ),
    )
    p_keychain.add_argument("--udid", help="Simulator identifier (default: first booted device)")
    p_keychain.add_argument(
        "--json", action="store_true", help="Write database records as JSON to stdout"
    )

    sub.add_parser(
        "list",
        help="List Mac-installed iOS apps in /Applications",
        description="Show each discovered iOS app's name, bundle identifier and version.",
        formatter_class=formatter,
        epilog=(
            "Example:\n"
            "  darkmach list\n\n"
            "Reads local /Applications wrappers; this is not a list of Simulator\n"
            "installs and it does not contact the App Store."
        ),
    )

    sub.add_parser(
        "status",
        help="Check host tools, SDK, Simulator state and default dylibs",
        description="Report host prerequisites before attempting a runtime workflow.",
        formatter_class=formatter,
        epilog=(
            "Example:\n"
            "  darkmach status\n\n"
            "Shows architecture, SIP, required developer tools, Simulator SDK,\n"
            "selected device and default interceptor files. Does not boot a\n"
            "device or validate extraction, bridge capture or app functionality."
        ),
    )

    for name in ("run", "patch", "launch", "status", "bridge"):
        sub.choices[name].add_argument(
            "--udid", metavar="UUID", help="Select an explicit iOS Simulator UUID"
        )
    for name in ("run", "launch", "bridge"):
        target_parser = sub.choices[name]
        target_parser.add_argument(
            "--socket", metavar="PATH", help="Absolute bridge socket path (under 104 UTF-8 bytes)"
        )
        target_parser.epilog += (
            "\n\nSession selection:\n"
            "  darkmach bridge --udid UUID\n"
            "  darkmach bridge --socket /tmp/darkmach-example.sock\n"
            "  The default endpoint is /tmp/darkmach-bridge-UUID.sock.\n"
            "  Live endpoints are not replaced; choose a different --socket."
        )

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
