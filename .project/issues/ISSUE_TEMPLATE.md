# ISSUE-[XXX]: [Short descriptive title]

**Severity**: CRITICAL | HIGH | MEDIUM | LOW
**Type**: Bug | Edge Case | Enhancement | Missing Feature
**Discovered By**: [agent-name or human]
**Discovered During**: [App name / testing campaign / code review]
**Affected Tool**: [patch-macho-surgical.py / make-main-patch.py / patch-for-simulator.sh / etc.]
**Assigned To**: [agent-name or unassigned]
**Status**: Open | In Progress | Resolved | Won't Fix

---

## Description

[Clear, specific description of what was found. Include the app that triggered it if applicable.]

## Reproduction

[Steps to reproduce. Include the specific app bundle, binary characteristics, or command that fails.]

```bash
# Commands that demonstrate the issue
```

## Binary Details (if applicable)

- **App**: [name / bundle ID]
- **Binary format**: [thin arm64 / FAT / arm64e]
- **Crypt region**: [cryptoff / cryptsize / number of functions]
- **Load commands**: [relevant LC_* details]
- **Strategy attempted**: [A (shellcode) / B (bootstrap) / N/A]

## Impact

[What breaks — app won't patch, won't launch, crashes at runtime, wrong output, etc.]

## Suggested Fix

[If known — proposed approach, which file to modify, relevant offsets or patterns.]

## Resolution

[Filled in when resolved — what was done, which file changed, any follow-up needed.]

---

*Filed: YYYY-MM-DD*
*Resolved: YYYY-MM-DD*
