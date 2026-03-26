# ISSUE-005: fs_scan produces leading comma in empty directory children arrays

**Severity**: MEDIUM
**Type**: Bug
**Discovered By**: lead (live testing)
**Discovered During**: ISSUE-003 fix validation, AP News live run
**Affected Tool**: `src/dylibs/bridge/cmd-recon.c`
**Assigned To**: mobile-engineer
**Status**: Resolved

---

## Description

The `fs_scan` command produces invalid JSON with leading commas in directory children arrays. When a directory has no interesting files but the code still emits a comma before the first real entry, the output contains `[,{...}]` instead of `[{...}]`. This occurs 65 times in a typical AP News scan.

## Reproduction

1. Launch app in Simulator with bridge dylib injected
2. Connect to bridge socket
3. Send: `fs_scan`
4. Parse response — JSON decode fails at positions where `[,` appears

```bash
darkmach bridge
> fs_scan
# json.decoder.JSONDecodeError: Expecting value: line 1 column 404 (char 403)
# Inspection shows "children":[,{"path":... pattern
```

## Binary Details (if applicable)

- **App**: AP News (reproduces on any app with directories in sandbox)
- **Strategy attempted**: N/A

## Impact

`fs_scan` returns unparseable JSON. The Python bridge client cannot `json.loads()` the response. Phase 14 LLM autonomous loop cannot use filesystem scanning.

## Suggested Fix

In `cmd-recon.c` `fs_scan_dir()`, the comma separator logic for the `children` array is incorrect. Likely a counter or first-entry flag that doesn't account for skipped/filtered entries. The pattern should only emit a comma *between* entries, not before the first one. Check the `resp_append(r, ",")` call that precedes child entries — it should be gated on whether a previous entry was actually written.

## Resolution

Fixed the comma separator logic in `fs_scan_dir()` in `src/dylibs/bridge/cmd-recon.c`. The root cause was that the comma emission was gated on the global `*file_count > 0` counter, which is shared across all recursive calls. When entering a new directory's `children` array, `file_count` was already positive from earlier entries, so the first child inside that directory would incorrectly emit a leading comma producing `[,{...}]`.

The fix replaces the global counter check with a local `first_entry` flag scoped to each invocation of `fs_scan_dir()`. The comma is only emitted when `first_entry` is false (i.e., a previous sibling entry was actually written at the current directory level). This ensures valid JSON regardless of nesting depth or filtered entries.

---

*Filed: 2026-03-26*
*Resolved: 2026-03-26*
