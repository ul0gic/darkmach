# ISSUE-003: fs_scan returns binary data causing UTF-8 decode error

**Severity**: MEDIUM
**Type**: Bug
**Discovered By**: lead (live testing)
**Discovered During**: AP News / Phase 13 live validation
**Affected Tool**: `src/dylibs/bridge/cmd-recon.c`, `src/darkmach/bridge.py`
**Assigned To**: mobile-engineer
**Status**: Resolved

---

## Description

The `fs_scan` bridge command returns raw binary data in its JSON response. When the Python bridge client (`bridge.py`) reads the response over the Unix domain socket, it attempts UTF-8 decoding which fails on non-UTF-8 byte sequences from scanned files.

## Reproduction

1. Launch app in Simulator with bridge dylib injected
2. Connect to bridge socket: `darkmach bridge`
3. Send: `fs_scan`
4. Python client crashes with `UnicodeDecodeError`

```bash
darkmach bridge
> fs_scan
# UnicodeDecodeError: 'utf-8' codec can't decode byte 0x... in position ...
```

## Binary Details (if applicable)

- **App**: AP News (reproduces on any app with binary files in sandbox)
- **Strategy attempted**: N/A

## Impact

Bridge client disconnects on `fs_scan`. The command is unusable from Python. The LLM autonomous loop (Phase 14) cannot use filesystem scanning.

## Suggested Fix

Two options:
1. **C-side**: Base64-encode any binary content before including in JSON response. Only include text-safe previews for non-UTF-8 files.
2. **Python-side**: Use `errors='replace'` or `errors='surrogateescape'` when decoding socket data. Less ideal — masks the real problem.

Recommended: option 1. The JSON-lines protocol requires valid UTF-8. The C side should sanitize before sending.

## Resolution

Fixed on the C side in `src/dylibs/bridge/cmd-recon.c` (option 1 from suggested fix). Changes:

1. Added `is_valid_utf8_text()` helper function that validates a byte buffer as legal UTF-8 text. Checks all multi-byte sequence rules (2/3/4-byte sequences, continuation bytes, overlong rejection) and rejects embedded NUL bytes. This runs before any file content is included in the JSON response.

2. Changed `fopen(full, "r")` to `fopen(full, "rb")` and buffer type from `char *` to `unsigned char *` for correct binary handling.

3. After reading file content, the validator decides the path:
   - **Valid UTF-8 text**: included as `"content":"..."` (existing behavior, unchanged)
   - **Binary content**: included as `"binary":true,"hex_preview":"<first 64 bytes as hex>"` instead of raw content. This gives the LLM enough to identify file format (magic bytes, headers) without corrupting the JSON protocol.

4. Updated `src/darkmach/bridge.py` format_response for fs_scan to display the new binary flag and hex_preview in the REPL output (shows `[binary]` marker and hex dump).

Root cause: `json_escape()` in darkmach-core.h passes through bytes >= 0x20 including 0x80-0xFF. Binary files (especially .p12, .cer, .key which are DER-encoded) contain arbitrary high bytes that form invalid UTF-8 sequences. The fix prevents binary content from reaching `json_escape` entirely.

Dylib compiles cleanly. All 581 tests pass.

---

*Filed: 2026-03-26*
*Resolved: 2026-03-26*
