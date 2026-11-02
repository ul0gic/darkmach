from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HBCTOOL = shutil.which("hbctool")
HBC_DECOMPILER = shutil.which("hbc-decompiler")

HERMES_MAGIC = b"\xc6\x1f\xbc"  # 3 bytes — 4th byte is version number

SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API_KEY"),
    (r'["\'](?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}["\']', "STRIPE_KEY"),
    (r'["\']AKIA[A-Z0-9]{16}["\']', "AWS_ACCESS_KEY"),
    (r'["\']AIza[A-Za-z0-9_\-]{35}["\']', "GOOGLE_API_KEY"),
    (r'["\']ghp_[A-Za-z0-9]{36}["\']', "GITHUB_TOKEN"),
    (r'["\']xox[bpsa]-[A-Za-z0-9\-]{10,}["\']', "SLACK_TOKEN"),
    (r'["\']Bearer\s+[A-Za-z0-9\._\-]{20,}["\']', "BEARER_TOKEN"),
    (r'(?:secret|password|token|auth)\s*[:=]\s*["\']([A-Za-z0-9_\-]{8,})["\']', "SECRET"),
    (r'["\']eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+["\']', "JWT"),
    (r'https?://[^\s"\'<>]{10,}(?:key|token|secret|auth|api)[^\s"\'<>]*', "URL_WITH_SECRET"),
    (
        r"https?://(?:api|backend|auth|gateway|graphql|ws|socket)"
        r'[.\-][A-Za-z0-9.\-]+\.[a-z]{2,}[^\s"\'<>]*',
        "API_ENDPOINT",
    ),
    (
        r"https?://[A-Za-z0-9.\-]+\."
        r"(?:execute-api|amazonaws|firebase|firebaseio|appspot|herokuapp|vercel|netlify|cloudflare)"
        r'\.[a-z.]+[^\s"\'<>]*',
        "CLOUD_ENDPOINT",
    ),
    (r'["\'][A-Za-z0-9\-]+\.firebaseio\.com["\']', "FIREBASE_DB"),
    (r'["\'][A-Za-z0-9\-]+\.firebaseapp\.com["\']', "FIREBASE_APP"),
    (r"https?://[a-f0-9]+@[a-z0-9.\-]+\.ingest\.sentry\.io/[0-9]+", "SENTRY_DSN"),
    (r'["\']appl_[A-Za-z0-9]{20,}["\']', "REVENUECAT_KEY"),
    (r'["\']sandbox_[a-z0-9]{20,}["\']', "BRAINTREE_SANDBOX"),
    (r'["\']production_[a-z0-9]{20,}["\']', "BRAINTREE_PROD"),
    (r'["\'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']', "UUID"),
    (r'["\'](?:https?://[^\s"\']+)?/graphql["\']', "GRAPHQL_ENDPOINT"),
    (r'wss?://[A-Za-z0-9.\-]+\.[a-z]{2,}[^\s"\'<>]*', "WEBSOCKET"),
]

INTERESTING_PREFIXES = [
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "pk_test_",
    "AKIA",
    "AIza",
    "ghp_",
    "gho_",
    "xox",
    "eyJ",  # JWT
    "appl_",  # RevenueCat
    "Bearer ",
    "Basic ",
    "sandbox_",
    "production_",
]


def find_js_bundles(app_path):
    app = Path(app_path)
    bundles = []

    candidates = [
        "main.jsbundle",
        "index.ios.bundle",
        "index.bundle",
        "assets/index.android.bundle",
    ]

    for candidate in candidates:
        path = app / candidate
        if path.exists():
            bundles.append(path)

    if app.is_dir():
        for ext in ("*.jsbundle", "*.bundle", "*.hbc"):
            for f in app.rglob(ext):
                if f not in bundles and f.stat().st_size > 1000:
                    bundles.append(f)

    return bundles


def is_hermes_bytecode(filepath):
    try:
        with Path(filepath).open("rb") as f:
            magic = f.read(3)
            return magic == HERMES_MAGIC
    except OSError:
        return False


def decompile_hermes(hbc_path, output_dir):
    js_out = Path(output_dir) / "decompiled.js"

    # Try hermes-dec first (supports more versions, produces JS pseudo-code)
    if HBC_DECOMPILER:
        try:
            result = subprocess.run(
                [str(HBC_DECOMPILER), str(hbc_path), str(js_out)],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            if result.returncode == 0 and js_out.exists():
                return js_out, None
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    # Fallback to hbctool (only works with older HBC versions)
    if HBCTOOL:
        hasm_dir = Path(output_dir) / "hasm"
        try:
            result = subprocess.run(
                [str(HBCTOOL), "disasm", str(hbc_path), str(hasm_dir)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if result.returncode == 0:
                return hasm_dir, None
        except Exception:
            pass

    return None, "No Hermes decompiler available — install hermes-dec or hbctool"


def extract_strings_from_hasm(hasm_dir):
    strings = []
    str_file = hasm_dir / "metadata.json"
    if str_file.exists():
        try:
            with str_file.open() as f:
                json.load(f)
        except Exception:
            pass

    for hasm_file in Path(hasm_dir).rglob("*.hasm"):
        try:
            content = hasm_file.read_text(errors="replace")
            # Hermes assembly uses String(N) "value" notation
            for match in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', content):
                s = match.group(1)
                if len(s) >= 4:
                    strings.append(s)
        except Exception:
            continue

    inst_file = hasm_dir / "instruction.hasm"
    if inst_file.exists():
        try:
            content = inst_file.read_text(errors="replace")
            for match in re.finditer(r'"([^"\\]*(?:\\.[^"\\]*)*)"', content):
                s = match.group(1)
                if len(s) >= 4:
                    strings.append(s)
        except Exception:
            pass

    return list(set(strings))


def extract_strings_from_binary(filepath):
    """Splits on nulls rather than scanning ASCII runs — the Hermes string table
    is null-separated UTF-8, so raw runs concatenate adjacent entries."""
    strings = []
    try:
        with Path(filepath).open("rb") as f:
            data = f.read()
    except OSError:
        return strings

    parts = data.split(b"\x00")
    for part in parts:
        try:
            s = part.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(s) < 4:
            continue
        printable = sum(1 for c in s if 32 <= ord(c) < 127)
        if printable < len(s) * 0.8:
            continue
        has_alpha = any(c.isalpha() for c in s)
        if not has_alpha:
            continue
        if len(s) > 5000:
            continue
        strings.append(s)

    # Scanned separately from raw bytes: packed strings run URLs together.
    url_chars = set(
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%"
    )
    for prefix in (b"https://", b"http://", b"wss://", b"ws://"):
        start = 0
        while True:
            idx = data.find(prefix, start)
            if idx == -1:
                break
            end = idx + len(prefix)
            while end < len(data) and data[end] in url_chars:
                end += 1
            url = data[idx:end].decode("ascii", errors="replace")
            if len(url) > 10:
                strings.append(url)
            start = idx + 1

    for prefix in (
        b"sk_live_",
        b"sk_test_",
        b"pk_live_",
        b"pk_test_",
        b"AKIA",
        b"AIza",
        b"ghp_",
        b"appl_",
        b"Bearer ",
        b"sandbox_",
        b"production_",
        b"eyJ",
    ):
        start = 0
        while True:
            idx = data.find(prefix, start)
            if idx == -1:
                break
            end = idx
            while end < len(data) and 33 <= data[end] < 127:
                end += 1
            s = data[idx:end].decode("ascii", errors="replace")
            if len(s) >= len(prefix) + 4:
                strings.append(s)
            start = idx + 1

    return list(set(strings))


def extract_strings_from_js(filepath):
    strings = []
    try:
        content = Path(filepath).read_text(errors="replace")
    except Exception:
        return strings

    dq_pat = r'"([^"\\]{4,}(?:\\.[^"\\]*)*)"'
    sq_pat = r"'([^'\\]{4,}(?:\\.[^'\\]*)*)'"
    strings.extend(match.group(1) for match in re.finditer(dq_pat, content))
    strings.extend(match.group(1) for match in re.finditer(sq_pat, content))

    strings.extend(match.group(1) for match in re.finditer(r"`([^`]{4,})`", content))

    return list(set(strings))


def scan_strings_for_secrets(strings):
    findings = []
    seen = set()

    for s in strings:
        for pattern, label in SECRET_PATTERNS:
            for match in re.finditer(pattern, s):
                value = match.group(0)
                if value not in seen:
                    seen.add(value)
                    findings.append(
                        {
                            "type": label,
                            "value": value[:500],
                            "context": s[:200] if s != value else "",
                        }
                    )

        for prefix in INTERESTING_PREFIXES:
            if s.startswith(prefix) and s not in seen:
                seen.add(s)
                findings.append(
                    {
                        "type": "INTERESTING_STRING",
                        "value": s[:500],
                        "context": f"starts with {prefix}",
                    }
                )

    findings.sort(key=lambda x: x["type"])
    return findings


def analyze_bundle(bundle_path, output_dir=None, as_json=False):
    bundle_path = Path(bundle_path)
    size = bundle_path.stat().st_size
    is_hermes = is_hermes_bytecode(bundle_path)

    result = {
        "file": str(bundle_path),
        "size": size,
        "format": "hermes_bytecode" if is_hermes else "javascript",
        "strings_extracted": 0,
        "findings": [],
        "errors": [],
    }

    strings = []

    if is_hermes:
        if output_dir:
            work_dir = output_dir
        else:
            work_dir = tempfile.mkdtemp(prefix="darkmach-hermes-")

        decompiled, err = decompile_hermes(bundle_path, work_dir)
        if decompiled:
            result["decompiled"] = True
            result["decompiled_path"] = str(decompiled)
            if decompiled.suffix == ".js":
                strings = extract_strings_from_js(decompiled)
            else:
                strings = extract_strings_from_hasm(decompiled)
        else:
            result["errors"].append(f"Decompilation failed: {err}")
            result["decompiled"] = False

        binary_strings = extract_strings_from_binary(bundle_path)
        strings = list(set(strings + binary_strings))

        if not output_dir:
            shutil.rmtree(work_dir, ignore_errors=True)
    else:
        strings = extract_strings_from_js(bundle_path)

    result["strings_extracted"] = len(strings)

    findings = scan_strings_for_secrets(strings)
    result["findings"] = findings

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: hermes-extract.py <app_bundle_or_jsbundle> [--json] [--output <dir>]")
        sys.exit(1)

    target = sys.argv[1]
    as_json = "--json" in sys.argv
    output_dir = None
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_dir = sys.argv[idx + 1]
            Path(output_dir).mkdir(parents=True, exist_ok=True)

    target_path = Path(target)

    if not target_path.exists():
        print(f"ERROR: {target} not found", file=sys.stderr)
        sys.exit(1)

    if target_path.is_dir() and (target_path.suffix == ".app" or target_path.is_dir()):
        bundles = find_js_bundles(target_path)
        if not bundles:
            print(f"No JS bundles found in {target}", file=sys.stderr)
            for f in target_path.rglob("*"):
                if f.is_file() and f.stat().st_size > 10000:
                    try:
                        with f.open("rb") as fh:
                            if fh.read(3) == HERMES_MAGIC:
                                bundles.append(f)
                    except Exception:
                        continue
            if not bundles:
                print("No Hermes bytecode files found either.", file=sys.stderr)
                sys.exit(1)
    else:
        bundles = [target_path]

    all_results = []
    for bundle in bundles:
        print(f"Analyzing: {bundle} ({bundle.stat().st_size:,} bytes)", file=sys.stderr)
        result = analyze_bundle(bundle, output_dir, as_json)
        all_results.append(result)

    if as_json:
        print(json.dumps(all_results, indent=2))
    else:
        for result in all_results:
            print(f"\n{'=' * 60}")
            print(f"File: {result['file']}")
            print(f"Size: {result['size']:,} bytes")
            print(f"Format: {result['format']}")
            if result.get("decompiled") is not None:
                print(f"Decompiled: {'Yes' if result['decompiled'] else 'No'}")
                if result.get("decompiled_path"):
                    print(f"Output: {result['decompiled_path']}")
            print(f"Strings extracted: {result['strings_extracted']}")

            if result["errors"]:
                for err in result["errors"]:
                    print(f"  WARNING: {err}")

            findings = result["findings"]
            if findings:
                print(f"\nFindings ({len(findings)}):")
                by_type = {}
                for f in findings:
                    by_type.setdefault(f["type"], []).append(f)
                for ftype, items in sorted(by_type.items()):
                    print(f"\n  [{ftype}] ({len(items)})")
                    for item in items[:20]:  # cap display at 20 per type
                        val = item["value"][:120]
                        print(f"    {val}")
                        if item.get("context") and item["context"] != val:
                            print(f"      context: {item['context'][:100]}")
                    if len(items) > 20:
                        print(f"    ... and {len(items) - 20} more")
            else:
                print("\nNo secrets or interesting patterns found in strings.")
            print()


if __name__ == "__main__":
    main()
