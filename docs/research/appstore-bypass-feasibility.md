# App Store Bypass Feasibility Study

> Exploit-engineer research -- 2026-03-26
> Status: Vectors 1-2 RESOLVED. Vector 5 PoC EXECUTED -- authorization failure, not capability failure.
> Vector 1: Mac binary does NOT exist on CDN for never-opted-in apps (build pipeline enforcement).
> Vector 2: Simulator daemons have production URL bags but blocked by Simulator detection + missing auth + encrypted iOS delivery.
> **Vector 5 PoC (2026-03-26): DoorDash encrypted IPA installed into Simulator with cryptid=1 intact. Kernel activated FULL FairPlay decryption chain (IOTextEncryptionFamily -> AppleFairplayTextCrypter -> fairplayd). Failed at authorization: sinf bound to different Apple ID. Next: test with matching Apple ID.**
> Full recon: `.project/research-appstoreagent-recon.md`, `.project/research-fairplay-decryption.md`

## Problem Statement

The most valuable bounty targets (banking apps, social media, payment processors) opt out of Mac delivery via the "Available on Mac" developer flag. Darkmach's pipeline depends on Mac App Store acquisition of decrypted iOS binaries. This research explores whether the opt-out can be bypassed.

## Key Finding

**The developer opt-out has TWO enforcement layers: client-side metadata (cosmetic) + build pipeline (real).**

**Phase 1 finding (confirmed):** The "Available on Mac" flag controls storefront visibility -- whether the app appears in Mac App Store search results. The download API authenticates the Apple ID's purchase history, not the opt-out flag. The opt-out metadata exists in two cached locations on disk, both readable under standard user permissions.

**Phase 2 finding (2026-03-26):** The opt-out is ALSO enforced at Apple's build pipeline. The Mac delivery of iOS apps requires a separate build artifact -- a `.pfpkg` (Protected FairPlay Package) wrapped in a xar archive with macOS installer Distribution XML. Apple's pipeline only produces this artifact for apps whose developer enabled Mac delivery. For opted-out apps, the CDN artifact was never built. The DMAP purchase database confirms: `ajxi=0` (no Mac binary), `ajpu` absent (no CDN URL), `aeMk=0x00020000` (iOS-only product type).

**Revised assessment:** The opt-out provides genuine protection against Mac-side binary analysis for apps that NEVER opted in. However, apps that previously opted in then withdrew remain potentially exposed if the CDN artifact persists.

**Evidence collected 2026-03-26**: The opt-out flag exists in two cached locations on disk, both readable under standard user permissions:

1. **amp-api catalog JSON**: `attributes.isIOSBinaryMacOSCompatible` boolean -- `false` for opted-out apps (e.g., DoorDash), `true` for opted-in apps (e.g., Action Network). The API returns full metadata for ALL apps regardless of opt-out status.

2. **DMAP purchase database**: Binary tag `aeSS` bitmask (bit 3 = Mac Apple Silicon compatibility), `aeMk` product type (`0x00020000` = iOS-only, `0x04000000` = Mac-compat), `ajmE` mobile-eligible flag, and `ajpu` Mac package URL presence/absence.

Of 67 owned iOS apps: 51 opted out, 16 opted in. All 67 have valid purchase records. The opt-out metadata is informational alongside the purchase authorization, but the build pipeline enforcement means no Mac binary exists to download for never-opted-in apps.

## Attack Vectors Assessed

### Vector 1: appstoreagent Direct API -- RESOLVED (BLOCKED for never-opted-in apps)

- **Status**: **RESOLVED** -- The Mac binary genuinely does not exist on Apple's CDN for apps that never opted in to Mac delivery.
- **What**: macOS daemon `appstoreagent` (PID 1022) handles iOS app downloads on Apple Silicon
- **Database**: `~/Library/Caches/com.apple.appstoreagent/storeSystem.db` (schema v26200, 14 tables)
- **Opt-out fields**: `isIOSBinaryMacOSCompatible` (amp-api), `aeSS` bit 3 (DMAP), `aeMk` product type, `ajmE` mobile-eligible, `ajpu` Mac package URL
- **Feasibility**: **LOW for never-opted-in** / **MEDIUM for previously-opted-in**
- **The Answer**: The opt-out is enforced at the **build pipeline level**, not just the metadata level. Apple's build pipeline produces a `.pfpkg` (Protected FairPlay Package) -- a Mac-specific xar archive with installer Distribution XML -- only for apps whose developer enabled Mac delivery. For opted-out apps, `ajxi=0` (no Mac binary exists), `aeMk=0x00020000` (iOS-only product type), and `ajpu` tag is entirely absent. This is not metadata suppression -- the CDN artifact was never produced.
- **Evidence collected (Phase 2, 2026-03-26)**:
  - Compared amp-api catalog JSON for DoorDash (opted OUT) vs Action Network (opted IN): structurally identical except for `isIOSBinaryMacOSCompatible` boolean and `deviceFamilies` array. Neither has Mac-specific download URLs in the catalog -- those come from the DMAP purchase database.
  - 49 `.pfpkg` CDN download URLs cached over 15 months -- ALL on `osxapps.itunes.apple.com`, ALL for opted-in apps. Zero for opted-out apps.
  - 16 `ajpu` URLs in DMAP exactly match the 16 opted-in apps. 51 opted-out apps have no `ajpu` tag at all.
  - xar archives contain Mac installer Distribution XML with `hostArchitectures="arm64,x86_64"` -- these are Mac-native packages, not raw iOS IPAs.
  - Download pipeline reconstructed: amp-api -> MZBuy.woa -> downloaddispatch.itunes.apple.com -> osxapps CDN. The dispatch step requires a server-side package record.
- **Remaining attack surface**: Apps that PREVIOUSLY opted in then later opted out may still have CDN artifacts. The pfpkg download cache contains 15 months of URL history -- some may reference apps that have since withdrawn Mac availability.
- **Full analysis**: See `research-appstoreagent-recon.md`, Phase 2

### Vector 2: Simulator App Store Activation -- RESOLVED (LOW feasibility)
- **Status**: **RESOLVED** -- Daemons have LIVE production URL bags (not stubbed). Blocked by Simulator detection checks and missing authentication.
- **What**: iOS Simulator has appstored (PID 89570), itunesstored (PID 89576), storekitd, installd daemons running as real, full-size arm64 binaries (not stubs)
- **Key finding**: The daemons actively fetch and cache **production URL bags** from `bag.itunes.apple.com` and `init.itunes.apple.com`. The bags contain identical download pipeline URLs to the host Mac (buyProduct, downloadProduct, redownloadProduct, purchase-daap). The URL bags are NOT stubbed -- they are the real production endpoints.
- **Key finding**: The `enableMacOSCompatibleIOSApps` flag is **absent** from the iOS URL bag. The developer opt-out does not exist in the iOS download channel. If activation succeeded, the opt-out would be irrelevant.
- **Key finding**: The Simulator's `storeUser.db` is **NOT encrypted** (unlike the host Mac's SQLCipher-protected version). All app tracking data would be in plaintext if an account were active.
- **Barriers**: (1) Explicit "not supported on simulator" checks in daemon binaries (MEDIUM to bypass via binary patching), (2) No Apple ID signed in -- no auth cookies, no DSID, no machine tokens (HIGH to overcome), (3) iOS download channel delivers FairPlay-encrypted IPAs, not decrypted binaries (UNKNOWN whether the existing Simulator FairPlay kernel bypass would apply to freshly-downloaded IPAs)
- **Feasibility**: **LOW** -- The combination of authentication injection + download channel encryption makes this impractical compared to the existing Mac delivery pipeline
- **Evidence collected (Phase 3, 2026-03-26)**: Full daemon lsof, all 12+ databases examined, 3 cached URL bags parsed, binary string analysis for Simulator checks, account/keychain state verified empty
- **Full analysis**: See `research-appstoreagent-recon.md`, Phase 3

### Vector 3: MZBuy Protocol Replay
- **What**: Capture and replay the purchase/download protocol from a real iOS device
- **How**: MITM the device's App Store traffic, extract signed purchase tokens, replay against Mac delivery CDN
- **Feasibility**: MEDIUM -- requires owned iOS device + MITM setup
- **Risk**: Purchase tokens may be device-bound
- **Key**: Must target the Mac/Apple Silicon delivery endpoint, not iOS -- Mac delivery = decrypted binary

### Vector 4: Purchase History Exploitation
- **What**: If user previously purchased/downloaded an app on iOS, the purchase record exists
- **How**: Apple ID purchase history may authorize re-download even when Mac opt-out is set
- **Feasibility**: MEDIUM -- requires prior iOS purchase, but many users have this
- **Note**: Combined with Vector 1, this could bypass opt-out entirely

### Vector 5: Local FairPlay Decryption -- HIGHEST PRIORITY
- **Status**: **PoC EXECUTED (2026-03-26)** -- Kernel decryption chain activated but authorization failed. See `.project/research-fairplay-decryption.md`.
- **What**: Use macOS's own FairPlay decryption infrastructure to decrypt iOS-encrypted binaries locally
- **How**: Download encrypted IPA via ipatool (Apple ID owns the purchase) -> extract binary + SC_Info (sinf/supf) -> install into Simulator or load via dyld -> macOS kernel decrypts via mremap_encrypted syscall
- **Key findings (2026-03-26)**:
  - `mremap_encrypted` syscall (SYS 489) exists on macOS, actively used by dyld
  - dyld calls mremap_encrypted **unconditionally** when it encounters `cryptid=1` -- **no platform check**
  - `FairPlayIOKit` kext (257 KB, v72.14.0) loaded with active UserClient (creator: fairplayd)
  - `IOTextEncryptionFamily` kext loaded, `AppleFairplayTextCrypter` active in IOKit registry
  - fairplayd (PID 1049) running with 6 Mach endpoints including **`com.apple.fpsd.sim`** (Simulator-specific)
  - Device key material present: `/var/db/fpsd/SC Info/SC Info.sidb` (672 bytes) + `/var/db/fpsd/adi/adi.pb` (1650 bytes, Anisette Device Identity)
  - OddsJam binary in Simulator has `cryptid=1` with **genuinely encrypted** bytes on disk, yet runs correctly -- kernel decrypts pages at page-in time
  - sinf DRM atoms contain: user ID hash, content key (encrypted), IV, transaction ID, Apple FairPlay certificate chain
  - CoreFP.framework (60 MB) has fully obfuscated exported symbols (anti-analysis)
- **Why this changes everything**: Vectors 1-4 all tried to obtain a **decrypted** binary from Apple's delivery chain. Vector 5 instead obtains the **encrypted** binary (available for ALL apps from the iOS channel, regardless of opt-out) and decrypts it locally. The iOS download channel has NO developer opt-out flag.
- **Critical dependency**: The sinf file must be valid for this Mac's FairPlay key database. iOS IPAs from ipatool include SC_Info with sinf files bound to the user's purchase. The question is whether the Mac's SC_Info.sidb can process sinf files from iOS-channel downloads.
- **PoC Result (2026-03-26)**: DoorDash IPA (ipatool, different Apple ID) installed into Simulator with cryptid=1 preserved and SC_Info intact. **Kernel activated the FULL decryption chain** (IOTextEncryptionFamily -> AppleFairplayTextCrypterSession -> fairplayd) but fairplayd rejected authorization: `fairplayOpen() failed, error -42110`. The sinf key material is bound to the downloading Apple ID ("Justin McCloud") which doesn't match the Mac's local FairPlay identity. **The failure is authorization-based, NOT capability-based.** The kernel CAN decrypt -- it just needs matching key material.
- **Feasibility**: **MEDIUM** -- Infrastructure confirmed functional. Authorization is the remaining barrier. Testing with matching Apple ID is the next step. If the same Apple ID that owns the purchase is signed into the Mac, fairplayd may authorize decryption.
- **Pipeline if successful**: `ipatool download -> extract IPA -> sinf + binary present -> install to Simulator (with SC_Info) -> dyld calls mremap_encrypted -> kernel decrypts -> Darkmach pipeline (patch platform -> instrument -> bridge)`

## Critical Constraint: Decrypted Binary Required

~~All vectors MUST target the Mac/Apple Silicon delivery channel.~~ **REVISED (2026-03-26):** Vector 5 opens a second path. macOS's FairPlay decryption infrastructure can potentially decrypt iOS-channel binaries locally.

```
Pipeline A (Mac delivery -- decrypted on disk):
  Mac App Store -> decrypted binary on disk -> analyze/patch/instrument
  Status: Works for opted-in apps. Opted-out apps have no Mac binary.

Pipeline B (iOS delivery + local decryption) -- NEW:
  ipatool -> encrypted IPA + sinf -> install to Simulator with SC_Info
    -> kernel mremap_encrypted -> page-level FairPlay decryption
    -> decrypted binary in memory -> dump/analyze/instrument
  Status: Infrastructure confirmed present. sinf compatibility TBD.
  Key advantage: iOS channel has NO developer opt-out flag.
```

If Pipeline B works, the developer opt-out becomes irrelevant for ALL apps, not just the 16 opted-in ones.

## Bounty Angle

The platform-level finding for Apple Security Bounty:
1. **FairPlay gap (primary finding)**: iOS apps delivered via Mac App Store on Apple Silicon are stored fully decrypted on disk. `cryptid=1` but bytes are plaintext. Affects all 16 opted-in apps on this Apple ID, and every opted-in iOS app on the Mac App Store globally.
2. **Opt-out gap (secondary finding, revised)**: The developer opt-out is partially cosmetic (catalog metadata) and partially real (build pipeline). However:
   - Apps that previously opted in then withdrew may still have CDN artifacts available
   - The catalog API returns full metadata for opted-out apps, enabling reconnaissance without alerting the developer
   - The purchase database's opt-out fields are all client-side readable -- standard user permissions reveal which apps are opted out, which developers chose to withdraw, and the full purchase history
3. **Information disclosure**: The local caches expose the complete download pipeline architecture, CDN URL patterns, authentication flow, and URL bag endpoints -- all under `~/Library/Caches/` with standard user permissions

## Next Steps

### Revised Strategy (post-Phase 3 + FairPlay Decryption investigation)

**Vector 1 is CLOSED for never-opted-in apps.** The binary doesn't exist. No further investigation needed on this specific path.

**Vector 2 is CLOSED.** The Simulator daemons have production URL bags (not stubbed as initially assumed), but the combination of Simulator detection bypasses, authentication injection, and FairPlay encryption in the iOS download channel makes this impractical.

**Vector 5 is the NEW PRIMARY INVESTIGATION.** The FairPlay decryption infrastructure reconnaissance (2026-03-26) revealed that macOS has everything needed to decrypt iOS FairPlay binaries locally. This potentially solves the "encrypted iOS delivery" problem that killed Vector 2.

**Priority-ordered active investigations:**

1. **Vector 5: Local FairPlay Decryption -- PHASE 2** (HIGHEST)
   - PoC executed with DoorDash IPA (ipatool, different Apple ID): kernel activated full decryption chain, failed at authorization (-42110)
   - **NEXT**: Download IPA using the SAME Apple ID that's signed into the Mac's App Store
   - **NEXT**: Compare iOS-channel sinf with Mac-channel sinf for an opted-in app (are keys identical?)
   - **NEXT**: Test `repairAppWithOptions:replyHandler:` via AppStoreDaemon.framework to see if fairplayd can "repair" FairPlay state
   - **NEXT**: Explore `com.apple.fpsd.sim` Mach service directly via XPC
   - Key finding: The failure is authorization-based, not capability-based -- matching Apple ID may be sufficient
   - Full PoC results: `.project/research-fairplay-decryption.md` (PoC section)

2. **Previously-opted-in app scan** -- Cross-reference the 49 cached pfpkg download URLs (spanning 15 months) with current DMAP ajpu URLs. If any cached URL points to an app that has since opted out, test whether the CDN URL is still live. This is the remaining Vector 1 attack surface.

3. **Maximize coverage of opted-in apps** -- 16 apps are already available for full analysis. Focus Darkmach pipeline validation and bounty evidence collection on these. Every opted-in iOS app on the Mac App Store is exposed to the FairPlay gap.

4. **Vector 3 (MZBuy protocol)** -- The `buyProduct` endpoint accepts `buyParams` with `productType=C` for BOTH opted-in and opted-out apps. What happens if a purchase/redownload request is made with opted-out buyParams? (Deprioritized if Vector 5 succeeds -- local decryption bypasses the need to get a Mac delivery artifact.)

5. **Hybrid vector (low priority)** -- Cookie/token transplant from host Mac to Simulator AMS cookie store. (Deprioritized -- Vector 5 is a cleaner approach to the same goal.)

### Deferred

6. **appstoreagent XPC monitoring** -- Still valuable for understanding the complete download protocol, but lower priority.
7. **CDN artifact persistence study** -- How long do pfpkg URLs remain live after an app update or opt-out change?

## Risk Assessment

- All research operates within standard user permissions (no SIP bypass, no jailbreak)
- No unauthorized access to other users' data
- Exploits architectural decisions in Apple's app distribution, not software vulnerabilities
- Similar to the FairPlay gap -- a design choice that creates unintended exposure
- **Phases 2-3 findings reduce the opt-out bypass from HIGH to LOW feasibility** for the general case, but the core FairPlay finding remains Critical severity for opted-in apps
- **Phase 4 finding (FairPlay decryption recon)**: The complete FairPlay decryption stack is present and active on macOS. If Vector 5 succeeds, feasibility escalates from LOW back to **HIGH for ALL apps** -- the developer opt-out would be rendered meaningless.
- **Phase 5 finding (DoorDash PoC, 2026-03-26)**: Kernel activated full FairPlay decryption chain for an iOS-channel encrypted binary in the Simulator. Failed at authorization (-42110) because sinf key material was bound to a different Apple ID. This confirms: (a) the kernel treats Simulator FairPlay identically to Mac/iOS, (b) the ONLY barrier is key material authorization, (c) if matching Apple ID is used, decryption may succeed for ANY app regardless of developer opt-out.
- **New finding**: Simulator store daemons receive full production URL bags and have unencrypted user databases -- additional evidence of architectural assumptions about Simulator isolation that may not hold
- **New finding**: The FairPlay kernel infrastructure does NOT distinguish between iOS and macOS platform binaries at the mremap_encrypted level. The kernel decrypts whatever it's told to decrypt, as long as valid sinf/key material is available.
- **New finding**: fairplayd has an explicit Simulator-specific Mach service endpoint (`com.apple.fpsd.sim`), confirming that FairPlay decryption for Simulator processes is a supported, intentional feature -- not an accident.
