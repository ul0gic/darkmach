# ISSUE-002: deeplink bridge command registered but not implemented

**Severity**: LOW
**Type**: Missing Feature
**Discovered By**: lead (live testing)
**Discovered During**: AP News / Phase 13 live validation
**Affected Tool**: `src/dylibs/bridge/cmd-inject.c`
**Assigned To**: mobile-engineer
**Status**: Resolved

---

## Description

The `deeplink` command is registered in the bridge dispatcher but has no implementation. Sending `{"id": 1, "cmd": "deeplink", "args": {"url": "apnews://"}}` returns an error response instead of triggering URL scheme handling.

## Reproduction

1. Launch app in Simulator with bridge dylib injected
2. Connect to bridge socket: `darkmach bridge`
3. Send: `deeplink apnews://`
4. Response: error — command not implemented

```bash
# Via bridge REPL
darkmach bridge
> deeplink apnews://
# Returns error
```

## Binary Details (if applicable)

- **App**: AP News (any app with URL schemes)
- **Strategy attempted**: N/A

## Impact

Cannot trigger deep links / URL schemes programmatically from the bridge. The LLM autonomous loop (Phase 14) will need this to test URL scheme handlers and navigate apps.

## Suggested Fix

Implement `cmd_deeplink` in `src/dylibs/bridge/cmd-inject.c`. Use `[[UIApplication sharedApplication] openURL:]` or dispatch to the app's scene delegate `scene:openURLContexts:`. Accept `{url}` arg. Dispatch to main thread.

## Resolution

Implemented `cmd_deeplink` in `src/dylibs/bridge/cmd-inject.c`. The command:
- Accepts `{"url": "..."}` argument
- Creates an NSURL from the string via the ObjC runtime
- Calls `[UIApplication sharedApplication] openURL:options:completionHandler:]` dispatched to the main thread
- Uses `dispatch_semaphore` with 2-second timeout when not already on main thread, calls directly if on main thread
- Returns the URL, scheme, and dispatch status in the response
- Validates input: rejects missing/empty URL arg, checks NSURL creation succeeds

Also updated:
- `src/dylibs/bridge/darkmach-bridge.c` -- added `deeplink` to the command dispatcher
- `src/darkmach/bridge.py` -- added `deeplink` to kv_cmds set, help text, and format_response handler

Dylib compiles cleanly. All 581 tests pass.

---

*Filed: 2026-03-26*
*Resolved: 2026-03-26*
