# Engagement Project Pattern

> Engagement work happens **outside this toolkit project**. This document is the canonical pattern for how an external engagement project wires Darkmach in.

Engagements live in their own project folders and reference Darkmach via a `.tools/darkmach` symlink. Each engagement keeps its own research notes, findings, evidence and disclosure routing. The directory layout is independent of the operator's editor or assistant.

## Why engagements are separate from the toolkit

Mixing engagement-specific artifacts (IPAs, captured traffic, findings, submission drafts) with toolkit development creates confusion:

- Toolkit changes get tangled with engagement-specific debugging
- Bounty findings clutter the dev workspace
- Multiple engagements would interfere
- The toolkit's intended audience (developers) sees research-specific noise

So: engagement projects fork off, reference Darkmach via a `.tools/darkmach` symlink, and evolve independently.

## Pattern for a new engagement

```
<research-root>/<target-slug>/
├── .project/
│   ├── README.md                # engagement project README
│   ├── changelog.md             # engagement timeline
│   ├── engagements/<target>/    # actual engagement workspace
│   │   ├── README.md            # orientation
│   │   ├── STATUS.md            # current state, finding tally
│   │   ├── ROUTING.md           # disclosure routing (H1 vs program-specific safety channel vs OOS)
│   │   ├── findings/            # candidate findings + INDEX.md
│   │   ├── experiments/         # phase write-ups
│   │   ├── safety/              # findings routed to non-H1 channels
│   │   └── <scope-config>       # H1 / Bugcrowd / etc. program config
│   ├── reports/                 # H1 submission drafts
│   └── safety/                  # safety-channel submission drafts
├── .tools/
│   └── darkmach -> <toolkit-checkout>/                # SYMLINK
└── output/<target>/             # all engagement artifacts (IPAs, dumps, captures, comb results, exploits, web/API replay)
```

## Engagement lifecycle phases

Each engagement progresses through:

1. **Acquisition** — install the app from the Mac App Store (opted-in). This is the only channel that decrypts on this Mac.
2. **Static analysis** — bundle inspection, plists, entitlements, frameworks, asset catalog.
3. **Runtime / dynamic analysis** — kernel page-in decryption of the opted-in bundle via the Darkmach Simulator pipeline. Bridge interrogation, interceptor capture.
4. **Comb / mining** — exhaust the captured data (static dumps, dynamic captures, traffic logs) before pursuing more rounds.
5. **Triage** — characterize each candidate finding by severity, scope-fit, evidence quality, disclosure channel.
6. **Web/API testing** — replay against the live backend if the program's web/API surface is in scope.
7. **PoC** — confirm impact via reproducible exploitation script.
8. **Submission** — H1 (or other program) per the program's rules; route AI/model issues separately per program.

## When toolkit improvements happen during an engagement

If an engagement reveals a need for new toolkit capability (the Grok engagement produced GOT-based shellcode and `darkmach-survival.dylib`), those improvements get committed to Darkmach itself — NOT to the engagement project. The engagement uses them via the `.tools/darkmach` symlink. This way:

- Toolkit improvements benefit every future engagement
- Engagement projects stay focused on findings, not tooling
- Darkmach git history captures the toolkit evolution; engagement git history captures the bounty work

## See also

- [`darkmach-brief.md`](darkmach-brief.md) — current-state capability brief for the toolkit
- [`bridge.md`](bridge.md) — full bridge command reference, the primary runtime control surface during an engagement
- [`research/methodology.md`](research/methodology.md) — research methodology for the pipeline
