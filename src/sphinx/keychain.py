"""Simulator keychain reader — reads keychain SQLite directly from host filesystem.

The iOS Simulator stores its keychain as a SQLite database at:
  ~/Library/Developer/CoreSimulator/Devices/<UDID>/data/Library/Keychains/keychain-2-debug.db
"""

from __future__ import annotations

import json
import plistlib
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

SIMDEVICES_DIR = Path.home() / "Library/Developer/CoreSimulator/Devices"


def get_booted_udid():
    """Find the UDID of the currently booted Simulator."""
    try:
        result = subprocess.run(
            ["xcrun", "simctl", "list", "devices", "booted", "-j"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        data = json.loads(result.stdout)
        for devices in data.get("devices", {}).values():
            for dev in devices:
                if dev.get("state") == "Booted":
                    return dev["udid"]
    except Exception:  # noqa: S110
        pass
    return None


def find_keychain_db(udid):
    """Locate the keychain SQLite file for a given Simulator UDID."""
    db_path = SIMDEVICES_DIR / udid / "data/Library/Keychains/keychain-2-debug.db"
    if db_path.exists():
        return db_path
    return None


def decode_blob(data):
    """Try to decode a blob column value into something readable."""
    if data is None:
        return None
    if isinstance(data, str):
        return data
    if isinstance(data, bytes):
        # Try UTF-8
        try:
            decoded = data.decode("utf-8")
            if decoded.isprintable() or len(decoded) < 200:
                return decoded
        except UnicodeDecodeError:
            pass
        # Try plist
        try:
            plist = plistlib.loads(data)
            return str(plist)
        except Exception:  # noqa: S110
            pass
        # Hex for short blobs, truncated hex for long
        if len(data) <= 64:
            return data.hex()
        return f"{data[:32].hex()}... ({len(data)} bytes)"
    return str(data)


def apple_timestamp_to_str(ts):
    """Convert Apple Core Data timestamp (seconds since 2001-01-01) to readable string."""
    if ts is None or ts == 0:
        return None
    try:
        # Apple epoch: 2001-01-01 00:00:00 UTC
        epoch = datetime(2001, 1, 1)
        from datetime import timedelta

        dt = epoch + timedelta(seconds=ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def read_keychain(db_path, as_json=False):
    """Read and display all keychain entries from the SQLite database."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    results = {"path": str(db_path), "tables": {}}

    # Table definitions:
    # genp = Generic Passwords (app-specific passwords, tokens)
    # inet = Internet Passwords (website/server credentials)
    # cert = Certificates
    # keys = Cryptographic Keys

    tables = {
        "genp": {
            "label": "Generic Passwords",
            "key_cols": [
                "svce",
                "acct",
                "agrp",
                "labl",
                "gena",
                "desc",
                "type",
                "pdmn",
                "sync",
                "cdat",
                "mdat",
            ],
            "desc_map": {
                "svce": "Service",
                "acct": "Account",
                "agrp": "AccessGroup",
                "labl": "Label",
                "gena": "GeneralAttr",
                "desc": "Description",
                "type": "Type",
                "pdmn": "Protection",
                "sync": "Synced",
                "cdat": "Created",
                "mdat": "Modified",
            },
        },
        "inet": {
            "label": "Internet Passwords",
            "key_cols": [
                "srvr",
                "acct",
                "agrp",
                "labl",
                "path",
                "port",
                "ptcl",
                "sdmn",
                "pdmn",
                "sync",
                "cdat",
                "mdat",
            ],
            "desc_map": {
                "srvr": "Server",
                "acct": "Account",
                "agrp": "AccessGroup",
                "labl": "Label",
                "path": "Path",
                "port": "Port",
                "ptcl": "Protocol",
                "sdmn": "SecurityDomain",
                "pdmn": "Protection",
                "sync": "Synced",
                "cdat": "Created",
                "mdat": "Modified",
            },
        },
        "cert": {
            "label": "Certificates",
            "key_cols": ["labl", "subj", "issr", "agrp", "ctyp", "cenc", "cdat", "mdat"],
            "desc_map": {
                "labl": "Label",
                "subj": "Subject",
                "issr": "Issuer",
                "agrp": "AccessGroup",
                "ctyp": "CertType",
                "cenc": "CertEncoding",
                "cdat": "Created",
                "mdat": "Modified",
            },
        },
        "keys": {
            "label": "Cryptographic Keys",
            "key_cols": [
                "labl",
                "agrp",
                "klbl",
                "kcls",
                "type",
                "bsiz",
                "esiz",
                "encr",
                "decr",
                "sign",
                "vrfy",
                "wrap",
                "unwp",
                "cdat",
                "mdat",
            ],
            "desc_map": {
                "labl": "Label",
                "agrp": "AccessGroup",
                "klbl": "AppLabel",
                "kcls": "KeyClass",
                "type": "KeyType",
                "bsiz": "KeySize",
                "esiz": "EffectiveSize",
                "encr": "CanEncrypt",
                "decr": "CanDecrypt",
                "sign": "CanSign",
                "vrfy": "CanVerify",
                "wrap": "CanWrap",
                "unwp": "CanUnwrap",
                "cdat": "Created",
                "mdat": "Modified",
            },
        },
    }

    for table_name, table_info in tables.items():
        try:
            # Get actual columns in this table
            cursor = conn.execute(f"PRAGMA table_info({table_name})")
            actual_cols = {row["name"] for row in cursor.fetchall()}

            # Filter to columns that exist
            cols = [c for c in table_info["key_cols"] if c in actual_cols]
            if not cols:
                continue

            cursor = conn.execute(f"SELECT {','.join(cols)} FROM {table_name}")
            rows = cursor.fetchall()

            entries = []
            for row in rows:
                entry = {}
                for col in cols:
                    val = row[col]
                    if col in ("cdat", "mdat") and isinstance(val, (int, float)):
                        val = apple_timestamp_to_str(val)
                    else:
                        val = decode_blob(val)
                    if val is not None:
                        friendly = table_info["desc_map"].get(col, col)
                        entry[friendly] = val
                entries.append(entry)

            results["tables"][table_name] = {
                "label": table_info["label"],
                "count": len(entries),
                "entries": entries,
            }
        except sqlite3.OperationalError:
            continue

    conn.close()

    if as_json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print(f"Keychain: {db_path}\n")
        for table_data in results["tables"].values():
            count = table_data["count"]
            if count == 0:
                continue
            print(f"=== {table_data['label']} ({count} items) ===\n")
            for i, entry in enumerate(table_data["entries"]):
                print(f"  [{i + 1}]")
                for key, val in entry.items():
                    val_str = str(val)[:200]
                    print(f"    {key}: {val_str}")
                print()

    return results


def main():
    udid = None
    as_json = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--udid" and i + 1 < len(args):
            udid = args[i + 1]
            i += 2
        elif args[i] == "--json":
            as_json = True
            i += 1
        else:
            i += 1

    if not udid:
        udid = get_booted_udid()
        if not udid:
            print(
                "ERROR: No booted Simulator found. Use --udid <UDID> to specify.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"Auto-detected booted Simulator: {udid}", file=sys.stderr)

    db_path = find_keychain_db(udid)
    if not db_path:
        print(f"ERROR: No keychain database found for UDID {udid}", file=sys.stderr)
        expected = SIMDEVICES_DIR / udid / "data/Library/Keychains/keychain-2-debug.db"
        print(f"Expected: {expected}", file=sys.stderr)
        sys.exit(1)

    read_keychain(db_path, as_json)


if __name__ == "__main__":
    main()
