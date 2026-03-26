"""Static analysis of decrypted iOS app bundles.

Runs against a .app bundle and extracts:
  - URLs, API keys, secrets, tokens from the binary
  - Entitlements, URL schemes, ATS config
  - Linked frameworks, Mach-O structure
  - Plist contents, embedded JSON files
  - SDK fingerprinting (Firebase, AWS, analytics, etc.)

Output goes to output/<app>/static/.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, capture output, don't raise on failure."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False, **kwargs)


def _strings(binary: Path) -> list[str]:
    """Extract printable strings from a Mach-O binary."""
    r = _run(["strings", str(binary)])
    return r.stdout.splitlines() if r.returncode == 0 else []


def _plist_read(plist: Path) -> str:
    """Pretty-print a plist file."""
    r = _run(["plutil", "-p", str(plist)])
    return r.stdout if r.returncode == 0 else ""


# ── Extractors ─────────────────────────────────────────────────────


def extract_urls(strings: list[str]) -> list[str]:
    """Extract all HTTP/HTTPS URLs."""
    urls = set()
    for s in strings:
        if re.match(r"^https?://", s, re.IGNORECASE):
            urls.add(s.strip())
    return sorted(urls)


def extract_secrets(strings: list[str]) -> list[str]:
    """Extract potential API keys, tokens, secrets."""
    patterns = [
        r"api.key",
        r"api_key",
        r"apikey",
        r"secret",
        r"token",
        r"bearer",
        r"authorization",
        r"password",
        r"credential",
    ]
    combined = re.compile("|".join(patterns), re.IGNORECASE)
    return sorted({s.strip() for s in strings if combined.search(s)})


def extract_sdk_strings(strings: list[str]) -> list[str]:
    """Extract SDK/service fingerprints."""
    patterns = [
        r"firebase",
        r"cognito",
        r"aws",
        r"s3\.amazonaws",
        r"auth0",
        r"mixpanel",
        r"amplitude",
        r"segment",
        r"appsflyer",
        r"adjust\.com",
        r"branch\.io",
        r"stripe",
        r"braintree",
        r"rudderstack",
        r"sentry",
        r"datadog",
        r"newrelic",
        r"bugsnag",
        r"crashlytics",
    ]
    combined = re.compile("|".join(patterns), re.IGNORECASE)
    return sorted({s.strip() for s in strings if combined.search(s)})


# ── Full analysis ──────────────────────────────────────────────────


def analyze_bundle(app_path: Path, output_dir: Path) -> dict:
    """Run full static analysis on an iOS .app bundle."""
    info_plist = app_path / "Info.plist"

    # Get executable name
    r = _run(["plutil", "-extract", "CFBundleExecutable", "raw", str(info_plist)])
    exe_name = r.stdout.strip() if r.returncode == 0 else None
    if not exe_name:
        print(f"ERROR: Could not read CFBundleExecutable from {info_plist}")
        return {}

    binary = app_path / exe_name
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 50)
    print(f"  Static Analysis — {exe_name}")
    print("=" * 50)

    results = {"app": exe_name, "binary": str(binary)}

    # 1. Encryption check
    print("\n[1] Encryption check...")
    r = _run(["otool", "-l", str(binary)])
    lc_output = r.stdout
    if "LC_ENCRYPTION_INFO" in lc_output:
        # Parse cryptid
        for line in lc_output.splitlines():
            if "cryptid" in line:
                print(f"  {line.strip()}")
                results["cryptid"] = line.strip()
    else:
        print("  NO ENCRYPTION — binary is fully decrypted on disk")
        results["cryptid"] = "none"

    # 2. Architecture
    print("\n[2] Architecture...")
    r = _run(["lipo", "-info", str(binary)])
    print(f"  {r.stdout.strip()}")
    results["arch"] = r.stdout.strip()

    # 3. Linked frameworks
    print("\n[3] Linked frameworks...")
    r = _run(["otool", "-L", str(binary)])
    frameworks = [line.strip() for line in r.stdout.splitlines()[1:] if line.strip()]
    for fw in frameworks[:30]:
        print(f"  {fw}")
    if len(frameworks) > 30:
        print(f"  ... {len(frameworks)} total")
    results["frameworks"] = frameworks

    # 4. Extract strings
    print("\n[4] Extracting strings from binary...")
    all_strings = _strings(binary)
    print(f"  {len(all_strings)} strings extracted")

    # 5. URLs
    print("\n[5] URLs...")
    urls = extract_urls(all_strings)
    (output_dir / "urls.txt").write_text("\n".join(urls))
    for u in urls[:30]:
        print(f"  {u}")
    print(f"  ... {len(urls)} total URLs saved")
    results["url_count"] = len(urls)

    # 6. Secrets/keys
    print("\n[6] API keys, tokens, secrets...")
    secrets = extract_secrets(all_strings)
    (output_dir / "secrets.txt").write_text("\n".join(secrets))
    for s in secrets[:20]:
        print(f"  {s[:120]}")
    print(f"  ... {len(secrets)} matches saved")
    results["secret_count"] = len(secrets)

    # 7. SDK fingerprints
    print("\n[7] SDK fingerprints...")
    sdks = extract_sdk_strings(all_strings)
    (output_dir / "sdks.txt").write_text("\n".join(sdks))
    for s in sdks[:20]:
        print(f"  {s[:120]}")
    print(f"  ... {len(sdks)} SDK strings saved")
    results["sdk_count"] = len(sdks)

    # 8. Entitlements
    print("\n[8] Entitlements...")
    r = _run(["codesign", "-d", "--entitlements", "-", str(app_path)])
    ent_output = r.stdout + r.stderr
    (output_dir / "entitlements.txt").write_text(ent_output)
    for line in ent_output.splitlines()[:30]:
        print(f"  {line}")

    # 9. Plists
    print("\n[9] Plist files...")
    plists = list(app_path.rglob("*.plist"))
    plist_output = []
    for p in plists:
        if "lproj" in str(p):
            continue
        content = _plist_read(p)
        plist_output.append(f"--- {p.relative_to(app_path)} ---\n{content[:500]}\n")
    (output_dir / "plists.txt").write_text("\n".join(plist_output))
    print(f"  {len(plists)} plist files found")

    # 10. URL schemes
    print("\n[10] URL schemes...")
    plist_content = _plist_read(info_plist)
    for line in plist_content.splitlines():
        if "CFBundleURLSchemes" in line or "CFBundleURLTypes" in line:
            print(f"  {line.strip()}")

    # 11. ATS config
    print("\n[11] App Transport Security...")
    in_ats = False
    for line in plist_content.splitlines():
        if "NSAppTransportSecurity" in line:
            in_ats = True
        if in_ats:
            print(f"  {line.strip()}")
            if line.strip() == "}":
                in_ats = False

    # 12. Embedded JSON
    print("\n[12] Embedded JSON files...")
    json_files = list(app_path.rglob("*.json"))
    for jf in json_files[:20]:
        print(f"  {jf.relative_to(app_path)}")
    if len(json_files) > 20:
        print(f"  ... {len(json_files)} total")

    # 13. Frameworks
    print("\n[13] Embedded frameworks...")
    fw_dir = app_path / "Frameworks"
    if fw_dir.exists():
        for fw in sorted(fw_dir.iterdir()):
            print(f"  {fw.name}")

    # 14. Mach-O load commands summary
    print("\n[14] Load commands summary...")
    if lc_output:
        cmds: dict[str, int] = {}
        for line in lc_output.splitlines():
            if line.strip().startswith("cmd "):
                cmd_name = line.strip().split()[1]
                cmds[cmd_name] = cmds.get(cmd_name, 0) + 1
        for cmd_name, count in sorted(cmds.items(), key=lambda x: -x[1]):
            print(f"  {count:4d}  {cmd_name}")

    # Save summary
    (output_dir / "summary.json").write_text(json.dumps(results, indent=2))

    print()
    print("=" * 50)
    print(f"  Analysis complete. Files saved to: {output_dir}")
    print("=" * 50)

    return results


def main():
    """CLI entry point for standalone use."""
    if len(sys.argv) < 2:
        print("Usage: sphinx analyze /path/to/App.app [-o output_dir]")
        sys.exit(1)

    app_path = Path(sys.argv[1]).resolve()
    output_dir = None
    if "-o" in sys.argv:
        idx = sys.argv.index("-o")
        if idx + 1 < len(sys.argv):
            output_dir = Path(sys.argv[idx + 1])

    if not output_dir:
        output_dir = Path(f"analysis-{app_path.stem}")

    analyze_bundle(app_path, output_dir)


if __name__ == "__main__":
    main()
