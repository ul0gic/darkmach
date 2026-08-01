from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from darkmach.sdkfingerprint import detect_sdks, detect_swift_modules
from darkmach.secretscan import keyword_matches, scan_credentials


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """`errors="replace"` survives non-UTF-8 bytes — `strings` over a binary
    carrying CJK text or raw payload data decodes to garbage otherwise."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=60,
        check=False,
        **kwargs,
    )


def _strings(binary: Path) -> list[str]:
    r = _run(["strings", str(binary)])
    return r.stdout.splitlines() if r.returncode == 0 else []


def _plist_read(plist: Path) -> str:
    r = _run(["plutil", "-p", str(plist)])
    return r.stdout if r.returncode == 0 else ""


def extract_urls(strings: list[str]) -> list[str]:
    urls = set()
    for s in strings:
        if re.match(r"^https?://", s, re.IGNORECASE):
            urls.add(s.strip())
    return sorted(urls)


def bundle_resource_names(app_path: Path) -> list[str]:
    """Resource-bundle and framework names — the only trace pure-Swift packages leave."""
    names = [p.name for p in app_path.glob("*.bundle")]
    fw_dir = app_path / "Frameworks"
    if fw_dir.is_dir():
        names += [p.name for p in fw_dir.iterdir()]
    return sorted(names)


def analyze_bundle(app_path: Path, output_dir: Path) -> dict:
    info_plist = app_path / "Info.plist"

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

    print("\n[1] Encryption check...")
    r = _run(["otool", "-l", str(binary)])
    lc_output = r.stdout
    if "LC_ENCRYPTION_INFO" in lc_output:
        for line in lc_output.splitlines():
            if "cryptid" in line:
                print(f"  {line.strip()}")
                results["cryptid"] = line.strip()
    else:
        print("  NO ENCRYPTION — binary is fully decrypted on disk")
        results["cryptid"] = "none"

    print("\n[2] Architecture...")
    r = _run(["lipo", "-info", str(binary)])
    print(f"  {r.stdout.strip()}")
    results["arch"] = r.stdout.strip()

    print("\n[3] Linked frameworks...")
    r = _run(["otool", "-L", str(binary)])
    frameworks = [line.strip() for line in r.stdout.splitlines()[1:] if line.strip()]
    for fw in frameworks[:30]:
        print(f"  {fw}")
    if len(frameworks) > 30:
        print(f"  ... {len(frameworks)} total")
    results["frameworks"] = frameworks

    print("\n[4] Extracting strings from binary...")
    all_strings = _strings(binary)
    print(f"  {len(all_strings)} strings extracted")

    print("\n[5] URLs...")
    urls = extract_urls(all_strings)
    (output_dir / "urls.txt").write_text("\n".join(urls))
    for u in urls[:30]:
        print(f"  {u}")
    print(f"  ... {len(urls)} total URLs saved")
    results["url_count"] = len(urls)

    print("\n[6] Credentials matching a known format...")
    credentials = scan_credentials(all_strings)
    (output_dir / "secrets.txt").write_text(
        "\n".join(f"{c.confidence}\t{c.shape}\t{c.value}\t{c.context}" for c in credentials)
    )
    for c in credentials[:20]:
        print(f"  [{c.confidence}] {c.shape}: {c.value[:100]}")
    print(f"  ... {len(credentials)} format-matched credentials saved to secrets.txt")
    results["secret_count"] = len(credentials)
    results["secret_shapes"] = sorted({c.shape for c in credentials})

    keywords = keyword_matches(all_strings)
    (output_dir / "secrets-keyword.txt").write_text("\n".join(keywords))
    print(f"  {len(keywords)} keyword-only matches — UNRANKED, mostly UI copy and symbol names")
    print("  (not counted as credentials; saved to secrets-keyword.txt for manual review)")
    results["keyword_hit_count"] = len(keywords)

    print("\n[7] SDK fingerprints...")
    detections = detect_sdks(all_strings, bundle_resource_names(app_path))
    (output_dir / "sdks.txt").write_text(
        "\n".join(f"{d.sdk}\t{', '.join(d.evidence)}" for d in detections)
    )
    for d in detections:
        print(f"  {d.sdk}  <-  {', '.join(d.evidence)[:100]}")
    print(f"  ... {len(detections)} SDKs identified, with evidence, saved to sdks.txt")
    results["sdk_count"] = len(detections)
    results["sdks"] = [d.sdk for d in detections]

    modules = detect_swift_modules(all_strings)
    (output_dir / "swift-modules.txt").write_text("\n".join(modules))
    if modules:
        print(f"  {len(modules)} Swift modules from leaked source paths: {', '.join(modules)}")
    results["swift_modules"] = modules

    print("\n[8] Entitlements...")
    r = _run(["codesign", "-d", "--entitlements", "-", str(app_path)])
    ent_output = r.stdout + r.stderr
    (output_dir / "entitlements.txt").write_text(ent_output)
    for line in ent_output.splitlines()[:30]:
        print(f"  {line}")

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

    print("\n[10] URL schemes...")
    plist_content = _plist_read(info_plist)
    for line in plist_content.splitlines():
        if "CFBundleURLSchemes" in line or "CFBundleURLTypes" in line:
            print(f"  {line.strip()}")

    print("\n[11] App Transport Security...")
    in_ats = False
    for line in plist_content.splitlines():
        if "NSAppTransportSecurity" in line:
            in_ats = True
        if in_ats:
            print(f"  {line.strip()}")
            if line.strip() == "}":
                in_ats = False

    print("\n[12] Embedded JSON files...")
    json_files = list(app_path.rglob("*.json"))
    for jf in json_files[:20]:
        print(f"  {jf.relative_to(app_path)}")
    if len(json_files) > 20:
        print(f"  ... {len(json_files)} total")

    print("\n[13] Embedded frameworks...")
    fw_dir = app_path / "Frameworks"
    if fw_dir.exists():
        for fw in sorted(fw_dir.iterdir()):
            print(f"  {fw.name}")

    print("\n[14] Load commands summary...")
    if lc_output:
        cmds: dict[str, int] = {}
        for line in lc_output.splitlines():
            if line.strip().startswith("cmd "):
                cmd_name = line.strip().split()[1]
                cmds[cmd_name] = cmds.get(cmd_name, 0) + 1
        for cmd_name, count in sorted(cmds.items(), key=lambda x: -x[1]):
            print(f"  {count:4d}  {cmd_name}")

    (output_dir / "summary.json").write_text(json.dumps(results, indent=2))

    print()
    print("=" * 50)
    print(f"  Analysis complete. Files saved to: {output_dir}")
    print("=" * 50)

    return results


def main():
    if len(sys.argv) < 2:
        print("Usage: darkmach analyze /path/to/App.app [-o output_dir]")
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
