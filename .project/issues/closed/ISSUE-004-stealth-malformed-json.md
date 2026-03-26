# ISSUE-004: stealth_* commands return malformed JSON responses

**Severity**: MEDIUM
**Type**: Bug
**Discovered By**: lead (live testing)
**Discovered During**: AP News / Phase 13 live validation
**Affected Tool**: `src/dylibs/stealth/darkmach-stealth.c`
**Assigned To**: exploit-engineer
**Status**: Resolved

---

## Description

The `stealth_scan`, `stealth_enable`, and `stealth_status` bridge commands return JSON responses with an extra `{` brace, producing invalid JSON. The Python bridge client can still parse some responses but the structure is malformed.

## Reproduction

1. Launch app in Simulator with bridge + stealth dylibs injected
2. Connect to bridge socket: `darkmach bridge`
3. Send: `stealth_scan`
4. Response JSON has extra opening brace

```bash
darkmach bridge
> stealth_scan
# Response contains malformed JSON structure (extra '{')
> stealth_enable
# Same issue
> stealth_status
# Same issue
```

## Binary Details (if applicable)

- **App**: AP News (reproduces on any app)
- **Strategy attempted**: N/A

## Impact

JSON parsing may fail or produce incorrect results. The Python bridge client's `format_response` handler may misinterpret stealth data. Phase 14 LLM loop needs clean JSON to reason about stealth status.

## Suggested Fix

Audit the JSON construction in `darkmach-stealth.c` for the three stealth command handlers. Look for a duplicated `{` in the `snprintf`/response buffer construction — likely a copy-paste error where the opening brace appears both in a format string prefix and in a concatenated section.

## Resolution

**Fixed.** The root cause was a mismatch between the bridge dispatcher's JSON envelope and the stealth command handlers' response format.

The bridge dispatcher (`darkmach-bridge.c`, line 70) starts every response with:
```c
resp_append(&r, "{\"id\":%s,\"ok\":true,", id_str);
```
and closes it (line 150) with:
```c
resp_append(&r, "}\n");
```

All internal bridge commands (cmd-recon.c, cmd-network.c, etc.) write bare key-value pairs that fit inside this envelope. But the stealth functions in the separate `darkmach-stealth.dylib` were writing complete JSON objects with their own opening `{`, producing:
```
{"id":0,"ok":true,{"detections":[...],"total_detections":0}}
```

The fix: Changed the opening brace in all three stealth command handlers from `{` to `"data":{`, so their content is wrapped in a `"data"` key that fits inside the dispatcher's envelope:

1. `darkmach_stealth_scan`: `{\"detections\":[` -> `\"data\":{\"detections\":[`
2. `darkmach_stealth_enable`: `{\"active_bypasses\":[` -> `\"data\":{\"active_bypasses\":[`
3. `darkmach_stealth_status`: `{\"bypasses\":[` -> `\"data\":{\"bypasses\":[`

Each function's closing `}` now closes the `"data"` object, and the dispatcher's `}` closes the outer envelope. Result is valid JSON:
```
{"id":0,"ok":true,"data":{"detections":[...],"total_detections":0}}
```

---

*Filed: 2026-03-26*
*Resolved: 2026-03-26*
