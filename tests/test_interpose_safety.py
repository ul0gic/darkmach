"""Interpose safety tests — prevent duplicate DYLD_INTERPOSE symbols across co-loaded dylibs.

Background:
    Phase 13 Sprint 13.2 introduced a duplicate DYLD_INTERPOSE on CCCrypt in
    cmd-network.c (unity-built into darkmach-bridge.dylib) that conflicted with
    darkmach-crypto.dylib's existing CCCrypt interpose. When both dylibs were
    loaded via DYLD_INSERT_LIBRARIES, the duplicate caused infinite recursion
    and crashed the target app. The duplicate has been removed. These tests
    prevent this class of regression from ever happening again.

How DYLD_INTERPOSE conflicts cause crashes:
    When two dylibs both declare an interpose entry for the same symbol (e.g.,
    CCCrypt), dyld rewrites the symbol bindings for ALL loaded images. The
    last-loaded dylib's hook becomes the entry point, but it calls "orig_CCCrypt"
    which was resolved to the OTHER dylib's hook — creating infinite recursion.

Test strategy:
    1. Parse C source files for __DATA,__interpose sections (static analysis)
    2. Extract original symbol names from interpose_pairs arrays
    3. Verify no symbol appears in more than one co-loaded dylib's interpose table
    4. Verify hook functions call through orig_ pointers, not the raw symbol
"""

from __future__ import annotations

import re
import subprocess
import typing
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DYLIBS_DIR = PROJECT_ROOT / "src" / "dylibs"

# Subdirectories that contain C source files with potential interpose tables
DYLIB_SUBDIRS = [
    DYLIBS_DIR / "interceptors",
    DYLIBS_DIR / "bridge",
    DYLIBS_DIR / "compat",
    DYLIBS_DIR / "stealth",
]

# Co-loaded dylibs from cli.py INTERCEPTOR_DYLIBS — these are all injected
# together via DYLD_INSERT_LIBRARIES.  bridge/cmd-*.c files are unity-built
# into darkmach-bridge.dylib, so their interpose entries also participate.
CO_LOADED_DYLIBS = [
    "darkmach-metal-fix.dylib",
    "darkmach-net.dylib",
    "darkmach-keychain.dylib",
    "darkmach-crypto.dylib",
    "darkmach-storage.dylib",
    "darkmach-ssl.dylib",
    "darkmach-db.dylib",
    "darkmach-bridge.dylib",
]

# Map dylib name -> source files that contribute interpose entries.
# bridge/cmd-*.c and bridge/darkmach-bridge.c are unity-built into darkmach-bridge.dylib.
# Interceptors and compat files each produce their own dylib.
DYLIB_SOURCE_MAP: dict[str, list[str]] = {
    "darkmach-bridge.dylib": [
        "bridge/darkmach-bridge.c",
        "bridge/cmd-recon.c",
        "bridge/cmd-network.c",
        "bridge/cmd-trace.c",
        "bridge/cmd-ui.c",
        "bridge/cmd-inject.c",
        "bridge/cmd-analysis.c",
        "bridge/cmd-forensics.c",
        "bridge/cmd-events.c",
    ],
    "darkmach-crypto.dylib": ["interceptors/darkmach-crypto.c"],
    "darkmach-db.dylib": ["interceptors/darkmach-db.c"],
    "darkmach-keychain.dylib": ["interceptors/darkmach-keychain.c"],
    "darkmach-net.dylib": ["interceptors/darkmach-net.c"],
    "darkmach-ssl.dylib": ["interceptors/darkmach-ssl.c"],
    "darkmach-tls.dylib": ["interceptors/darkmach-tls.c"],
    "darkmach-storage.dylib": ["interceptors/darkmach-storage.c"],
    "darkmach-metal-fix.dylib": ["compat/darkmach-metal-fix.c"],
    "darkmach-stealth.dylib": ["stealth/darkmach-stealth.c"],
}


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def find_c_files_with_interpose(root: Path) -> list[Path]:
    """Find all C source files under root that contain __DATA,__interpose sections."""
    results = []
    for subdir in DYLIB_SUBDIRS:
        if not subdir.exists():
            continue
        for c_file in sorted(subdir.glob("*.c")):
            content = c_file.read_text(encoding="utf-8", errors="replace")
            if "__DATA,__interpose" in content:
                results.append(c_file)
    return results


def extract_interpose_symbols(c_file: Path) -> list[tuple[str, str]]:
    """Extract (hook_function, original_symbol) pairs from a C file's interpose table.

    Parses the interpose_pairs array entries like:
        { (const void *)hooked_CCCrypt, (const void *)CCCrypt },
        { (const void *)darkmach_sysctl, (const void *)sysctl },

    Returns a list of (hook_name, original_name) tuples.
    """
    content = c_file.read_text(encoding="utf-8", errors="replace")

    # Find the interpose array block(s) — may have different struct/array names
    # Pattern: look for lines between the array declaration and the closing };
    # that contain interpose pair entries.
    #
    # Matches entries like:
    #   { (const void *)hooked_foo, (const void *)foo },
    #   { (const void *)interposed_SSL_write, (const void *)SSL_write },
    pair_pattern = re.compile(
        r"\{\s*\(const\s+void\s*\*\)\s*(\w+)\s*,\s*\(const\s+void\s*\*\)\s*(\w+)\s*\}"
    )

    pairs = []

    # Only extract pairs that appear AFTER a __DATA,__interpose section marker
    # to avoid false positives from other struct arrays.
    marker_positions = [m.start() for m in re.finditer(r"__DATA,__interpose", content)]

    for marker_pos in marker_positions:
        # Find the array region: from marker to the next "};""
        region_start = marker_pos
        closing = content.find("};", region_start)
        if closing == -1:
            continue
        region = content[region_start : closing + 2]

        for match in pair_pattern.finditer(region):
            hook_name = match.group(1)
            original_name = match.group(2)
            pairs.append((hook_name, original_name))

    return pairs


def file_relative_to_dylibs(c_file: Path) -> str:
    """Return the file path relative to the dylibs directory."""
    return str(c_file.relative_to(DYLIBS_DIR))


def get_dylib_for_source(relative_path: str) -> str | None:
    """Determine which dylib a source file is unity-built into."""
    for dylib_name, sources in DYLIB_SOURCE_MAP.items():
        if relative_path in sources:
            return dylib_name
    return None


def extract_function_body(content: str, func_name: str) -> str | None:
    """Extract the body of a C function by name (brace-counting approach).

    Returns the text from the opening { to the matching closing }, or None
    if the function is not found.
    """
    # Find the function definition — name followed by ( with possible return type before
    # We search for the function name followed by an opening paren
    pattern = re.compile(
        r"(?:^|\n)[^\n]*?" + re.escape(func_name) + r"\s*\([^)]*\)\s*\{",
        re.MULTILINE,
    )
    match = pattern.search(content)
    if not match:
        return None

    # Find the opening brace
    brace_start = content.index("{", match.start())
    depth = 0
    i = brace_start
    while i < len(content):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return content[brace_start : i + 1]
        i += 1
    return None


# ---------------------------------------------------------------------------
# Test 1: No duplicate interpose targets across co-loaded dylibs
# ---------------------------------------------------------------------------


class TestNoDuplicateInterposeTargets:
    """Verify that no symbol is interposed by more than one co-loaded dylib.

    When two dylibs loaded via DYLD_INSERT_LIBRARIES both declare an interpose
    entry for the same symbol, dyld's interpose machinery creates a chain where
    one hook calls the other instead of the original — causing infinite recursion.

    This is the exact bug that occurred with CCCrypt in Sprint 13.2.
    """

    def test_dylibs_dir_exists(self):
        """Guard: the dylibs source directory must exist for these tests to be meaningful."""
        assert DYLIBS_DIR.exists(), (
            f"Dylibs directory not found at {DYLIBS_DIR}. "
            "Cannot perform interpose safety analysis."
        )

    def test_at_least_one_interpose_file_found(self):
        """Guard: we must find at least one C file with interpose tables.

        If this fails, the parsing logic may be broken or the codebase has
        changed in a way that invalidates these tests.
        """
        files = find_c_files_with_interpose(DYLIBS_DIR)
        assert len(files) >= 3, (
            f"Expected at least 3 files with interpose tables, found {len(files)}: "
            f"{[str(f.name) for f in files]}. "
            "The parsing logic may need updating."
        )

    def test_no_duplicate_symbols_across_all_interpose_files(self):
        """No original symbol should appear in more than one file's interpose table.

        This is the broadest check — catches duplicates regardless of whether
        the files are currently co-loaded.
        """
        files = find_c_files_with_interpose(DYLIBS_DIR)
        symbol_to_files: dict[str, list[str]] = {}

        for c_file in files:
            pairs = extract_interpose_symbols(c_file)
            rel_path = file_relative_to_dylibs(c_file)
            for _hook, original in pairs:
                symbol_to_files.setdefault(original, []).append(rel_path)

        duplicates = {
            sym: owners for sym, owners in symbol_to_files.items() if len(owners) > 1
        }

        assert not duplicates, (
            "INTERPOSE CONFLICT: The following symbols are interposed by multiple files. "
            "When these files are co-loaded as dylibs, this causes infinite recursion crashes.\n"
            + "\n".join(
                f"  {sym}: interposed in {', '.join(owners)}"
                for sym, owners in sorted(duplicates.items())
            )
        )

    def test_no_duplicate_symbols_in_co_loaded_dylibs(self):
        """No original symbol should appear in more than one co-loaded dylib.

        Uses the DYLIB_SOURCE_MAP to determine which source files contribute
        to which dylib, then checks for conflicts only among dylibs that are
        actually loaded together (INTERCEPTOR_DYLIBS from cli.py).
        """
        dylib_symbols: dict[str, list[str]] = {}  # dylib_name -> [original_symbols]

        for dylib_name in CO_LOADED_DYLIBS:
            sources = DYLIB_SOURCE_MAP.get(dylib_name, [])
            symbols = []
            for rel_source in sources:
                source_path = DYLIBS_DIR / rel_source
                if source_path.exists():
                    pairs = extract_interpose_symbols(source_path)
                    symbols.extend(original for _hook, original in pairs)
            if symbols:
                dylib_symbols[dylib_name] = symbols

        # Check for conflicts
        symbol_to_dylibs: dict[str, list[str]] = {}
        for dylib_name, symbols in dylib_symbols.items():
            for sym in symbols:
                symbol_to_dylibs.setdefault(sym, []).append(dylib_name)

        duplicates = {
            sym: dylibs for sym, dylibs in symbol_to_dylibs.items() if len(dylibs) > 1
        }

        assert not duplicates, (
            "INTERPOSE CONFLICT in co-loaded dylibs! "
            "These dylibs are all loaded via DYLD_INSERT_LIBRARIES and have "
            "duplicate interpose entries:\n"
            + "\n".join(
                f"  {sym}: interposed in {', '.join(dylibs)}"
                for sym, dylibs in sorted(duplicates.items())
            )
            + "\n\nFix: Remove the duplicate interpose entry from one of the files. "
            "Use dlsym(RTLD_DEFAULT, ...) to resolve the original function pointer "
            "instead of DYLD_INTERPOSE when a symbol is already interposed elsewhere."
        )

    def test_interpose_extraction_correctness_crypto(self):
        """Verify that interpose extraction correctly parses darkmach-crypto.c.

        This is a known-good file with 3 interpose entries. If this test fails,
        the regex parsing is broken.
        """
        crypto_file = DYLIBS_DIR / "interceptors" / "darkmach-crypto.c"
        if not crypto_file.exists():
            pytest.skip("darkmach-crypto.c not found")

        pairs = extract_interpose_symbols(crypto_file)
        originals = [orig for _hook, orig in pairs]

        assert "CCCrypt" in originals, "Expected CCCrypt in darkmach-crypto.c interpose table"
        assert "CC_SHA256" in originals, "Expected CC_SHA256 in darkmach-crypto.c interpose table"
        assert "CC_SHA1" in originals, "Expected CC_SHA1 in darkmach-crypto.c interpose table"

    def test_interpose_extraction_correctness_stealth(self):
        """Verify that interpose extraction correctly parses darkmach-stealth.c.

        Stealth has a differently-named struct (stealth_interpose_pair) and array
        (stealth_interpose_pairs). The parser must handle this.
        """
        stealth_file = DYLIBS_DIR / "stealth" / "darkmach-stealth.c"
        if not stealth_file.exists():
            pytest.skip("darkmach-stealth.c not found")

        pairs = extract_interpose_symbols(stealth_file)
        originals = [orig for _hook, orig in pairs]

        assert "sysctl" in originals, "Expected sysctl in darkmach-stealth.c interpose table"
        assert "getenv" in originals, "Expected getenv in darkmach-stealth.c interpose table"
        assert "ptrace" in originals, "Expected ptrace in darkmach-stealth.c interpose table"
        assert "fork" in originals, "Expected fork in darkmach-stealth.c interpose table"
        assert len(pairs) >= 10, (
            f"Expected at least 10 interpose pairs in stealth, got {len(pairs)}"
        )

    def test_interpose_extraction_correctness_metal_fix(self):
        """Verify extraction handles darkmach-metal-fix.c with its different naming.

        Metal fix uses 'interpose_tuple' struct and 'interpose_assert' array name.
        """
        metal_file = DYLIBS_DIR / "compat" / "darkmach-metal-fix.c"
        if not metal_file.exists():
            pytest.skip("darkmach-metal-fix.c not found")

        pairs = extract_interpose_symbols(metal_file)
        originals = [orig for _hook, orig in pairs]

        assert "__assert_rtn" in originals, (
            "Expected __assert_rtn in darkmach-metal-fix.c interpose table"
        )

    def test_bridge_cmd_files_have_no_interpose_tables(self):
        """Bridge cmd-*.c files should NOT contain interpose tables.

        These files are unity-built into darkmach-bridge.dylib. If any of them
        add an interpose table, the symbols will conflict with the standalone
        interceptor dylibs that are co-loaded.

        This is the specific pattern that caused the Sprint 13.2 crash:
        cmd-network.c had a CCCrypt interpose that conflicted with darkmach-crypto.dylib.
        """
        bridge_dir = DYLIBS_DIR / "bridge"
        if not bridge_dir.exists():
            pytest.skip("bridge/ directory not found")

        violations = []
        for cmd_file in sorted(bridge_dir.glob("cmd-*.c")):
            pairs = extract_interpose_symbols(cmd_file)
            if pairs:
                originals = [orig for _hook, orig in pairs]
                violations.append(f"  {cmd_file.name}: interposes {originals}")

        assert not violations, (
            "Bridge cmd-*.c files must NOT contain DYLD_INTERPOSE tables!\n"
            "These files are unity-built into darkmach-bridge.dylib, which is co-loaded\n"
            "with interceptor dylibs. Use dlsym() or fishhook-style runtime rebinding\n"
            "instead.\n\nViolations:\n" + "\n".join(violations)
        )


# ---------------------------------------------------------------------------
# Test 2: Hook functions call through orig_ pointers, not raw symbols
# ---------------------------------------------------------------------------


class TestHookFunctionsCallOriginals:
    """Verify that hook functions call through saved original pointers.

    In DYLD_INTERPOSE hooks, the hook function must NOT directly call the
    original symbol it interposes — that call would be redirected back to
    the hook, causing infinite recursion.

    Correct:   hooked_CCCrypt() calls orig_CCCrypt()
    Incorrect: hooked_CCCrypt() calls CCCrypt()

    Exception: In darkmach-tls.c, the interposing image calling SSL_write/SSL_read
    directly is actually safe with DYLD_INTERPOSE — the interposing image's own
    calls are not redirected. However, this is a subtle behavior that should be
    documented, so we flag it with a note rather than failing.
    """

    # Files where direct calls to the interposed symbol are known-safe.
    # DYLD_INTERPOSE does not redirect calls from within the interposing image
    # itself — the interposing image's own calls go through the real symbol.
    # This is safe by design, but we still flag it with notes for documentation.
    #
    # - darkmach-tls.c: calls SSL_write/SSL_read directly in hook bodies
    # - darkmach-stealth.c: calls sysctl/getenv/stat/lstat/access/fork/ptrace/
    #   _dyld_image_count/_dyld_get_image_name/_dyld_get_image_header directly
    # - darkmach-metal-fix.c: calls __assert_rtn directly in the non-Metal path
    #   (falls through to real assert when not in a Metal guard context)
    KNOWN_SAFE_DIRECT_CALLERS: typing.ClassVar[set[str]] = {
        "interceptors/darkmach-tls.c",
        "stealth/darkmach-stealth.c",
        "compat/darkmach-metal-fix.c",
    }

    def test_hooks_do_not_call_raw_symbol(self):
        """For each interpose pair, verify the hook calls orig_ not the raw symbol.

        Skips files in KNOWN_SAFE_DIRECT_CALLERS with a recorded note.
        """
        files = find_c_files_with_interpose(DYLIBS_DIR)
        violations = []
        notes = []

        for c_file in files:
            content = c_file.read_text(encoding="utf-8", errors="replace")
            rel_path = file_relative_to_dylibs(c_file)
            pairs = extract_interpose_symbols(c_file)

            for hook_name, original_name in pairs:
                body = extract_function_body(content, hook_name)
                if body is None:
                    # Function might be defined elsewhere or is a macro
                    continue

                # Check if the hook body contains a direct call to the original symbol.
                # We look for the pattern: original_name followed by ( but not preceded
                # by common prefixes like orig_, original_, or part of a longer identifier.
                #
                # Pattern: word boundary + original_name + (
                # But exclude: orig_original_name, original_original_name, etc.
                direct_call_pattern = re.compile(
                    r"(?<!\w)"  # not preceded by word char (avoids orig_foo matching)
                    + re.escape(original_name)
                    + r"\s*\("  # followed by optional space and open paren
                )

                matches = list(direct_call_pattern.finditer(body))
                if matches:
                    if rel_path in self.KNOWN_SAFE_DIRECT_CALLERS:
                        notes.append(
                            f"NOTE (safe): {rel_path}: {hook_name}() directly calls "
                            f"{original_name}() — this is safe because DYLD_INTERPOSE "
                            f"does not redirect calls from within the interposing image."
                        )
                    else:
                        violations.append(
                            f"  {rel_path}: {hook_name}() directly calls "
                            f"{original_name}() — should call through an orig_ pointer. "
                            f"Direct calls to the interposed symbol risk infinite "
                            f"recursion if called from a different loaded image."
                        )

        assert not violations, (
            "UNSAFE DIRECT CALLS in hook functions:\n"
            "Hook functions that interpose a symbol via DYLD_INTERPOSE must call\n"
            "through a saved original function pointer (e.g., orig_foo), not the\n"
            "raw symbol (foo). Direct calls may cause infinite recursion.\n\n"
            + "\n".join(violations)
            + (("\n\n" + "\n".join(notes)) if notes else "")
        )

    def test_each_interpose_file_declares_orig_pointers(self):
        """Files with interpose tables should declare orig_ function pointers.

        For files NOT in KNOWN_SAFE_DIRECT_CALLERS, each interposed symbol
        should have a corresponding orig_<symbol> or similar saved pointer.
        """
        files = find_c_files_with_interpose(DYLIBS_DIR)
        warnings = []

        for c_file in files:
            rel_path = file_relative_to_dylibs(c_file)
            if rel_path in self.KNOWN_SAFE_DIRECT_CALLERS:
                continue

            content = c_file.read_text(encoding="utf-8", errors="replace")
            pairs = extract_interpose_symbols(c_file)

            for _hook_name, original_name in pairs:
                # Check for a saved original pointer declaration.
                # Common patterns:
                #   static ... (*orig_CCCrypt)(...) = NULL;
                #   static ... (*orig_sqlite3_open)(...) = NULL;
                orig_pattern = re.compile(r"orig_" + re.escape(original_name))
                if not orig_pattern.search(content):
                    warnings.append(
                        f"  {rel_path}: no orig_{original_name} pointer found for "
                        f"interposed symbol {original_name}"
                    )

        assert not warnings, (
            "Missing orig_ function pointers for interposed symbols:\n"
            "Each interposed symbol should have a saved original pointer\n"
            "(e.g., orig_CCCrypt for CCCrypt) to call through.\n\n"
            + "\n".join(warnings)
        )


# ---------------------------------------------------------------------------
# Test 3: Build gate — verify make succeeds
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBuildGate:
    """Verify that the project builds successfully.

    This is a build gate: if the Makefile or C sources are broken, catch it
    here before runtime. Marked as integration because it requires Xcode
    command-line tools (clang, xcrun, etc.).
    """

    def test_makefile_exists(self):
        """Guard: the Makefile must exist."""
        makefile = PROJECT_ROOT / "Makefile"
        assert makefile.exists(), f"Makefile not found at {makefile}"

    def test_make_all_succeeds(self):
        """Run 'make -C <project_root> all' and verify exit code 0.

        Skips if:
        - Makefile doesn't exist
        - xcrun is not available (no Xcode CLI tools)
        """
        makefile = PROJECT_ROOT / "Makefile"
        if not makefile.exists():
            pytest.skip("Makefile not found")

        # Check that xcrun is available (needed for SDK path resolution)
        xcrun_check = subprocess.run(
            ["xcrun", "--find", "clang"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if xcrun_check.returncode != 0:
            pytest.skip("xcrun not available — Xcode CLI tools not installed")

        result = subprocess.run(
            ["make", "-C", str(PROJECT_ROOT), "all"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        assert result.returncode == 0, (
            f"'make all' failed with exit code {result.returncode}.\n"
            f"stdout:\n{result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout}\n"
            f"stderr:\n{result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr}"
        )


# ---------------------------------------------------------------------------
# Test 4: Completeness checks — ensure we're scanning everything
# ---------------------------------------------------------------------------


class TestInterposeScanCompleteness:
    """Verify the test infrastructure itself is correct and complete.

    These meta-tests ensure the safety checks above are actually scanning
    all relevant files. If a new C file is added with an interpose table
    and it's not in our source map, we want to know.
    """

    def test_all_interpose_files_are_in_source_map(self):
        """Every C file with an interpose table should map to a known dylib."""
        files = find_c_files_with_interpose(DYLIBS_DIR)
        unmapped = []

        for c_file in files:
            rel_path = file_relative_to_dylibs(c_file)
            dylib = get_dylib_for_source(rel_path)
            if dylib is None:
                unmapped.append(rel_path)

        assert not unmapped, (
            "C files with interpose tables not mapped to any dylib in DYLIB_SOURCE_MAP.\n"
            "Add these to DYLIB_SOURCE_MAP so they are included in duplicate checks:\n"
            + "\n".join(f"  {f}" for f in unmapped)
        )

    def test_source_map_files_exist(self):
        """All files referenced in DYLIB_SOURCE_MAP should exist on disk."""
        missing = []
        for dylib_name, sources in DYLIB_SOURCE_MAP.items():
            for rel_source in sources:
                full_path = DYLIBS_DIR / rel_source
                if not full_path.exists():
                    missing.append(f"  {dylib_name}: {rel_source}")

        assert not missing, (
            "Source files in DYLIB_SOURCE_MAP do not exist on disk:\n"
            + "\n".join(missing)
            + "\nUpdate DYLIB_SOURCE_MAP to match the current file layout."
        )

    def test_co_loaded_dylibs_match_cli(self):
        """CO_LOADED_DYLIBS should match INTERCEPTOR_DYLIBS from cli.py.

        If cli.py changes which dylibs are co-loaded, this test constant
        must be updated too.
        """
        cli_path = PROJECT_ROOT / "src" / "darkmach" / "cli.py"
        if not cli_path.exists():
            pytest.skip("cli.py not found")

        content = cli_path.read_text(encoding="utf-8")
        # Extract INTERCEPTOR_DYLIBS list from cli.py
        match = re.search(
            r"INTERCEPTOR_DYLIBS\s*=\s*\[(.*?)\]",
            content,
            re.DOTALL,
        )
        assert match, "Could not find INTERCEPTOR_DYLIBS in cli.py"

        # Extract quoted strings from the list
        cli_dylibs = re.findall(r'"([^"]+)"', match.group(1))
        assert set(cli_dylibs) == set(CO_LOADED_DYLIBS), (
            f"CO_LOADED_DYLIBS in test_interpose_safety.py is out of sync with "
            f"INTERCEPTOR_DYLIBS in cli.py.\n"
            f"  cli.py: {sorted(cli_dylibs)}\n"
            f"  test:   {sorted(CO_LOADED_DYLIBS)}\n"
            f"Update CO_LOADED_DYLIBS to match."
        )
