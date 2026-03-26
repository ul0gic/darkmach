"""App Store discovery — find iOS apps available on Apple Silicon Macs.

Two-step approach:
  1. iTunes Search/RSS API (free, no auth) → find apps by keyword or category
  2. amp-api per-app lookup (Bearer token) → check isIOSBinaryMacOSCompatible

The amp-api token is a JWT captured from the App Store web client.
To refresh: visit apps.apple.com in Safari, open Network tab, find any
amp-api-edge request, copy the Authorization: Bearer token.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from sphinx._paths import OUTPUT_DIR

# ── Token ──────────────────────────────────────────────────────────

# amp-api Bearer token (JWT, captured from App Store web client)
# Issued: 2025-06-12  Expires: 2026-09-02
# To refresh: Safari → apps.apple.com → DevTools Network → copy Bearer token
# Override: set SPHINX_AMP_TOKEN env var or pass --token to CLI
_DEFAULT_TOKEN = (
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlU4UlRZVjVaRFMifQ"
    ".eyJpc3MiOiI3TktaMlZQNDhaIiwiaWF0IjoxNzcwODcxMzg5LCJleHAiOjE3Nzgx"
    "Mjg5ODksInJvb3RfaHR0cHNfb3JpZ2luIjpbImFwcGxlLmNvbSJdfQ"
    ".Tewb7DQbQYYjwlyHRehBb7Ksjcrd6wtg1xIfazeUE5iLQNPWGgh650cGJBeDjRhz"
    "k7fKIp-QyPigT14bV98Epw"
)

TOKEN = os.environ.get("SPHINX_AMP_TOKEN", _DEFAULT_TOKEN)

CATEGORIES = {
    6001: "Weather",
    6002: "Utilities",
    6003: "Travel",
    6005: "Social Networking",
    6006: "Reference",
    6007: "Productivity",
    6008: "Photo & Video",
    6009: "News",
    6010: "Navigation",
    6011: "Music",
    6012: "Lifestyle",
    6013: "Health & Fitness",
    6014: "Games",
    6015: "Finance",
    6016: "Entertainment",
    6017: "Education",
    6018: "Books",
    6020: "Food & Drink",
    6023: "Shopping",
    6024: "Sports",
    6026: "Business",
}

SCAN_CATEGORIES = [
    6001,
    6002,
    6005,
    6007,
    6008,
    6012,
    6013,
    6014,
    6015,
    6016,
    6020,
    6023,
    6024,
    6026,
]


# ── Token check ────────────────────────────────────────────────────


def check_token() -> bool:
    """Check if the amp-api JWT is still valid. Returns True if ok."""
    try:
        payload = TOKEN.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        exp = data["exp"]
        now = int(time.time())
        if exp < now:
            print("WARNING: amp-api token has expired.")
            print("To refresh: visit apps.apple.com in Safari, open DevTools Network tab,")
            print("find any amp-api-edge request, copy the Authorization: Bearer token.")
            return False
        days_left = (exp - now) // 86400
        if days_left < 30:
            print(f"NOTE: Token expires in {days_left} days.")
        return True
    except Exception:
        print("WARNING: Could not parse token.")
        return False


# ── API calls ──────────────────────────────────────────────────────


def _get(url: str, headers: dict | None = None, retries: int = 3) -> dict | None:
    """GET a URL and parse JSON. Retries on 429 with exponential backoff."""
    req = urllib.request.Request(url, headers=headers or {})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                # Strip control chars that occasionally appear in iTunes API responses
                raw = re.sub(r"[\x00-\x1f\x7f]", " ", raw)
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  (rate limited, waiting {wait}s...)")
                time.sleep(wait)
                continue
            return None
        except Exception:
            return None
    return None


def itunes_search(term: str, limit: int = 25) -> list[dict]:
    """Search iTunes API by keyword. Returns list of {id, name, bundle, category}."""
    encoded = urllib.parse.quote(term)
    data = _get(
        f"https://itunes.apple.com/search?term={encoded}&country=us&media=software&entity=software&limit={limit}"
    )
    if not data:
        return []
    return [
        {
            "id": str(r["trackId"]),
            "name": r.get("trackName", "?"),
            "bundle": r.get("bundleId", "?"),
            "category": r.get("primaryGenreName", "?"),
        }
        for r in data.get("results", [])
        if "software" in r.get("kind", "")
    ]


def itunes_top_free(genre_id: int, limit: int = 20) -> list[dict]:
    """Get top free apps in a category via RSS feed."""
    data = _get(
        f"https://itunes.apple.com/us/rss/topfreeapplications/limit={limit}/genre={genre_id}/json"
    )
    if not data:
        return []
    return [
        {
            "id": e["id"]["attributes"]["im:id"],
            "name": e.get("im:name", {}).get("label", "?"),
            "bundle": e.get("id", {}).get("attributes", {}).get("im:bundleId", "?"),
            "category": e.get("category", {}).get("attributes", {}).get("label", "?"),
        }
        for e in data.get("feed", {}).get("entry", [])
    ]


def itunes_lookup(ids: list[str]) -> list[dict]:
    """Look up specific app IDs."""
    ids_str = ",".join(ids)
    data = _get(f"https://itunes.apple.com/lookup?id={ids_str}&country=us")
    if not data:
        return []
    return [
        {
            "id": str(r.get("trackId", "?")),
            "name": r.get("trackName", "?"),
            "bundle": r.get("bundleId", "?"),
            "category": r.get("primaryGenreName", "?"),
        }
        for r in data.get("results", [])
    ]


def check_mac_compatible(app: dict) -> dict:
    """Check a single app against the amp-api for Mac compatibility."""
    app_id = app["id"]
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Origin": "https://apps.apple.com",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
    }
    url = (
        f"https://amp-api-edge.apps.apple.com/v1/catalog/us/apps/{app_id}"
        f"?platform=iphone&additionalPlatforms=appletv,ipad,iphone,mac,realityDevice,watch"
        f"&extend=fileSizeByDevice,deviceFamilies&l=en-US"
    )
    data = _get(url, headers=headers)

    result = {**app, "status": "error"}

    if not data or "data" not in data or not data["data"]:
        result["error"] = "amp-api request failed"
        return result

    try:
        attrs = data["data"][0]["attributes"]
        families = attrs.get("deviceFamilies", [])
        sizes = attrs.get("fileSizeByDevice", {})
        mac_sizes = {k: v for k, v in sizes.items() if "Mac" in k}
        is_native_mac = "mac" in families
        is_mac_compatible = attrs.get("isIOSBinaryMacOSCompatible", False)

        if is_native_mac:
            result["status"] = "native_mac"
            result["size_mb"] = 0
        elif is_mac_compatible and mac_sizes:
            result["status"] = "available"
            result["size_mb"] = round(next(iter(mac_sizes.values())) / 1024 / 1024, 1)
        elif mac_sizes and not is_mac_compatible:
            result["status"] = "opted_out"
            result["size_mb"] = round(next(iter(mac_sizes.values())) / 1024 / 1024, 1)
        else:
            result["status"] = "unavailable"
            result["size_mb"] = 0
    except Exception as e:
        result["error"] = str(e)

    return result


# ── Display ────────────────────────────────────────────────────────

STATUS_LABELS = {
    "available": "YES",
    "opted_out": "OUT",
    "native_mac": "MAC",
    "unavailable": " --",
    "error": "ERR",
}


def display_result(r: dict) -> None:
    label = STATUS_LABELS.get(r["status"], "???")
    name = r.get("name", "?")[:40]
    bundle = r.get("bundle", "?")
    size = r.get("size_mb", 0)
    if r["status"] == "available":
        print(f"  {label}  {name:<40s} {size:6.1f} MB  {bundle}")
    else:
        print(f"  {label}  {name:<40s}          {bundle}")


# ── Modes ──────────────────────────────────────────────────────────


def process_apps(apps: list[dict]) -> list[dict]:
    """Check Mac compatibility for a list of apps. Returns results."""
    results = []
    available = 0
    for i, app in enumerate(apps):
        if i > 0:
            time.sleep(2.5)  # rate limit — amp-api throttles fast requests
        r = check_mac_compatible(app)
        display_result(r)
        results.append(r)
        if r["status"] == "available":
            available += 1

    print()
    print(f"  Checked: {len(results)}  |  Available on Mac: {available}")
    return results


def save_results(results: list[dict], outfile: Path) -> None:
    """Deduplicate and save results to JSON."""
    seen = set()
    unique = []
    for r in results:
        if r["id"] not in seen:
            seen.add(r["id"])
            unique.append(r)

    avail = [r for r in unique if r["status"] == "available"]
    opted = [r for r in unique if r["status"] == "opted_out"]

    output = {
        "available_count": len(avail),
        "opted_out_count": len(opted),
        "total_checked": len(unique),
        "apps": sorted(unique, key=lambda x: (x["status"] != "available", x["name"])),
    }

    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(json.dumps(output, indent=2))

    print(f"  Results saved: {outfile}")
    print(f"  Available: {len(avail)}  Opted out: {len(opted)}  Total: {len(unique)}")


# ── Main ───────────────────────────────────────────────────────────


def set_token(token: str) -> None:
    """Override the amp-api token at runtime."""
    global TOKEN
    TOKEN = token


def run_discover(
    search: str | None = None,
    category: str | None = None,
    ids: list[str] | None = None,
    limit: int = 25,
    output: str | None = None,
    token: str | None = None,
) -> int:
    """Run discovery. Called by CLI."""
    if token:
        set_token(token)
    results_dir = OUTPUT_DIR / "discover"
    date_str = datetime.now().strftime("%Y%m%d")

    print()
    print("  Sphinx — iOS App Discovery")
    print("  ─────────────────────────────────────")
    print("  YES = iOS app installable on Mac")
    print("  OUT = Binary exists, developer opted out")
    print("  MAC = Native Mac app (not iOS binary)")
    print("   -- = Not available on Mac")
    print()

    if not check_token():
        return 1

    all_results: list[dict] = []

    if category == "all":
        outfile = Path(output) if output else results_dir / f"all-categories-{date_str}.json"
        for gid in SCAN_CATEGORIES:
            gname = CATEGORIES.get(gid, f"Unknown ({gid})")
            print("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"  Category: {gname} ({gid})")
            print()
            apps = itunes_top_free(gid, 20)
            all_results.extend(process_apps(apps))
            print()
    elif category:
        gid = int(category)
        gname = CATEGORIES.get(gid, f"Unknown ({gid})")
        outfile = Path(output) if output else results_dir / f"category-{gid}-{date_str}.json"
        print(f"  Category: {gname} ({gid})")
        print()
        apps = itunes_top_free(gid, limit)
        all_results = process_apps(apps)
    elif ids:
        outfile = Path(output) if output else results_dir / f"ids-{date_str}.json"
        print(f"  Checking IDs: {','.join(ids)}")
        print()
        apps = itunes_lookup(ids)
        all_results = process_apps(apps)
    elif search:
        slug = search.replace(" ", "-").lower()
        outfile = Path(output) if output else results_dir / f"search-{slug}-{date_str}.json"
        print(f'  Searching: "{search}" (limit {limit})')
        print()
        apps = itunes_search(search, limit)
        all_results = process_apps(apps)
    else:
        print("ERROR: Specify a search term, --category, or --ids")
        return 1

    print()
    print("  ─────────────────────────────────────")
    if all_results:
        save_results(all_results, outfile)
    print()
    return 0


def main():
    """CLI entry point for standalone use."""
    args = sys.argv[1:]
    if not args or args[0] in ("--help", "-h"):
        print("Usage:")
        print("  sphinx discover <search term>")
        print("  sphinx discover --category <id|all>")
        print("  sphinx discover --ids <id1,id2,...>")
        print()
        print("Categories:")
        for gid in SCAN_CATEGORIES:
            print(f"  {gid:<6d} {CATEGORIES[gid]}")
        return

    search = None
    category = None
    ids = None
    limit = 25

    i = 0
    while i < len(args):
        if args[i] == "--category" and i + 1 < len(args):
            category = args[i + 1]
            i += 2
        elif args[i] == "--ids" and i + 1 < len(args):
            ids = args[i + 1].split(",")
            i += 2
        elif args[i] == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 2
        elif not args[i].startswith("--"):
            search = args[i]
            i += 1
        else:
            i += 1

    run_discover(search=search, category=category, ids=ids, limit=limit)


if __name__ == "__main__":
    main()
