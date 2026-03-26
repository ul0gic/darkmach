#!/usr/bin/env python3
"""
Auto-detect the AppDelegate class name from an iOS Mach-O binary.

Detection strategies (in priority order):
1. Swift mangled name matching binary module name: _TtC<N><module><N>AppDelegate
2. Swift mangled name with any module: _TtC*AppDelegate
3. ObjC-style AppDelegate in symbol table
4. Pure SwiftUI @main detection (no AppDelegate — different entry strategy needed)

Returns the class name suitable for passing to make-main-patch.py --delegate
"""
import subprocess
import re
import os
import sys


def get_bundle_executable(app_path):
    """Get CFBundleExecutable from Info.plist."""
    plist = os.path.join(app_path, "Info.plist")
    if not os.path.isfile(plist):
        return None
    try:
        result = subprocess.run(
            ["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleExecutable", plist],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def get_strings(binary_path):
    """Run strings on a binary, return as list."""
    try:
        result = subprocess.run(
            ["strings", binary_path], capture_output=True, text=True
        )
        return result.stdout.split('\n')
    except Exception:
        return []


def get_nm_symbols(binary_path):
    """Run nm on binary, return lines."""
    try:
        result = subprocess.run(
            ["nm", binary_path], capture_output=True, text=True
        )
        return result.stdout.split('\n')
    except Exception:
        return []


def detect_delegate(binary_path, app_path=None):
    """
    Detect the AppDelegate class name from an iOS binary.

    Returns:
        tuple: (class_name, detection_method, confidence)
        class_name: string like '_TtC11AccuWeather11AppDelegate' or 'AppDelegate'
        detection_method: string describing how it was found
        confidence: 'high', 'medium', or 'low'

    If no delegate found, returns (None, reason, None)
    """
    # Determine the module name from the .app bundle
    module_name = None
    if app_path:
        module_name = get_bundle_executable(app_path)
    if not module_name:
        # Guess module name from binary filename
        module_name = os.path.basename(binary_path)

    print(f"  Module name: {module_name}")

    # Get all strings from binary
    all_strings = get_strings(binary_path)

    # ── Strategy 1: Swift mangled name matching module ──
    # Pattern: _TtC<len><module><len>AppDelegate
    # Example: _TtC11AccuWeather11AppDelegate
    expected_swift = f"_TtC{len(module_name)}{module_name}11AppDelegate"
    for s in all_strings:
        if s.strip() == expected_swift:
            return (expected_swift, "Swift mangled (exact module match)", "high")

    # Also check with different delegate name lengths (SceneDelegate pattern etc)
    swift_module_pattern = re.compile(
        rf"^_TtC{len(module_name)}{re.escape(module_name)}\d+\w*AppDelegate\w*$"
    )
    for s in all_strings:
        s = s.strip()
        if swift_module_pattern.match(s):
            return (s, "Swift mangled (module match, variant name)", "high")

    # ── Strategy 2: Any Swift mangled AppDelegate ──
    # _TtC followed by digits, then a module name, then digits, then *AppDelegate*
    swift_any_pattern = re.compile(r"^_TtC(\d+)(\w+?)(\d+)(.*AppDelegate.*)$")
    candidates = []
    for s in all_strings:
        s = s.strip()
        m = swift_any_pattern.match(s)
        if m:
            mod_len, mod_name, cls_len, cls_rest = m.groups()
            # Skip known SDK delegates
            sdk_modules = {
                'GoogleUtilities', 'Firebase', 'AirshipCore', 'AirshipAutomation',
                'Pulse', 'PulseUI', 'FBSDKCoreKit', 'Branch', 'Adjust',
                'AppsFlyerLib', 'Singular', 'Kochava', 'MoEngage',
                'CleverTap', 'OneSignal', 'Braze', 'Leanplum'
            }
            if mod_name not in sdk_modules:
                candidates.append((s, mod_name))

    if len(candidates) == 1:
        name, mod = candidates[0]
        return (name, f"Swift mangled (module: {mod})", "high")
    elif len(candidates) > 1:
        # Prefer the one whose module name is closest to the binary name
        # (case-insensitive, longest common prefix)
        best = None
        best_score = -1
        for name, mod in candidates:
            score = 0
            for a, b in zip(mod.lower(), module_name.lower()):
                if a == b:
                    score += 1
                else:
                    break
            if score > best_score:
                best_score = score
                best = name
        if best:
            return (best, f"Swift mangled (best match from {len(candidates)} candidates)", "medium")

    # ── Strategy 3: ObjC-style AppDelegate in strings ──
    # Look for class names like "AppDelegate", "XXXAppDelegate"
    objc_pattern = re.compile(r"^[A-Z][A-Za-z0-9]*AppDelegate$")
    objc_candidates = []
    for s in all_strings:
        s = s.strip()
        if objc_pattern.match(s) and len(s) < 60:
            # Filter out SDK references
            if s not in ('GULAppDelegateSwizzler',):
                objc_candidates.append(s)

    # Deduplicate
    objc_candidates = list(dict.fromkeys(objc_candidates))

    # Prefer plain "AppDelegate" or one matching the module name
    for c in objc_candidates:
        if c == "AppDelegate":
            return (c, "ObjC class name (plain AppDelegate)", "high")

    if len(objc_candidates) == 1:
        return (objc_candidates[0], "ObjC class name (single match)", "medium")
    elif len(objc_candidates) > 1:
        # Try to match module prefix
        for c in objc_candidates:
            if c.startswith(module_name[:3]):
                return (c, f"ObjC class name (prefix match from {len(objc_candidates)} candidates)", "medium")
        return (objc_candidates[0], f"ObjC class name (first of {len(objc_candidates)} candidates)", "low")

    # ── Strategy 4: nm symbol table ──
    nm_lines = get_nm_symbols(binary_path)
    for line in nm_lines:
        if "AppDelegate" in line and "_TtC" in line:
            parts = line.split()
            for p in parts:
                if p.startswith("_TtC") and "AppDelegate" in p:
                    return (p, "nm symbol table (Swift)", "high")

    for line in nm_lines:
        if "AppDelegate" in line:
            parts = line.split()
            for p in parts:
                if "AppDelegate" in p and not p.startswith("_OBJC"):
                    return (p, "nm symbol table", "medium")

    # ── Strategy 5: Check for SwiftUI @main (no AppDelegate) ──
    has_swiftui_app = False
    swiftui_main_symbol = None
    for s in all_strings:
        s = s.strip()
        if s == "$s7SwiftUI3AppP":
            has_swiftui_app = True
        # Look for the App.main() entry: $s<N><Module><N><AppName>V5$mainyyFZ
        m = re.match(r"^\$s(\d+)(\w+?)(\d+)(\w+?)V5\$mainyyFZ$", s)
        if m:
            swiftui_main_symbol = s

    # Also check nm for @main entry
    for line in nm_lines:
        m = re.search(r"(\$s\d+\w+\d+\w+V5\$mainyyFZ)", line)
        if m:
            swiftui_main_symbol = m.group(1)

    if has_swiftui_app and swiftui_main_symbol is None:
        return (None, "SwiftUI @main app detected but no App.main() symbol found — may need alternative entry strategy", None)

    if swiftui_main_symbol:
        return (None, f"SwiftUI @main app — entry is {swiftui_main_symbol}, not UIApplicationMain. Need alternative shellcode path.", None)

    return (None, "No AppDelegate or SwiftUI @main detected — manual investigation needed", None)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Auto-detect AppDelegate class name from iOS binary"
    )
    parser.add_argument("binary", help="Path to Mach-O binary")
    parser.add_argument("--app", help="Path to .app bundle (for Info.plist)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Only output the class name (for scripting)")
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"Not a file: {args.binary}", file=sys.stderr)
        sys.exit(1)

    # Auto-detect .app path if not provided
    app_path = args.app
    if not app_path:
        # Walk up from binary to find .app bundle
        path = os.path.dirname(os.path.abspath(args.binary))
        while path and path != "/":
            if path.endswith(".app"):
                app_path = path
                break
            path = os.path.dirname(path)

    if not args.quiet:
        print(f"Detecting AppDelegate for: {args.binary}")
        if app_path:
            print(f"  App bundle: {app_path}")

    class_name, method, confidence = detect_delegate(args.binary, app_path)

    if args.quiet:
        if class_name:
            print(class_name)
            sys.exit(0)
        else:
            sys.exit(1)

    print()
    if class_name:
        print(f"  Detected: {class_name}")
        print(f"  Method:   {method}")
        print(f"  Confidence: {confidence}")
        print(f"\n  Use with: python3 make-main-patch.py <binary> --delegate '{class_name}'")
    else:
        print(f"  NOT FOUND")
        print(f"  Reason: {method}")
        sys.exit(1)


if __name__ == "__main__":
    main()
