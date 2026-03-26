![Classification](https://img.shields.io/badge/classification-security%20research-red)
![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![App](https://img.shields.io/badge/app-OddsJam-blue)

# Example Findings: OddsJam Case Study

OddsJam is a sports odds comparison app available on the iOS App Store and installable on Apple Silicon Macs. It was used as the first full-pipeline test of the Darkmach toolkit. The analysis demonstrated that the toolkit works end-to-end and revealed multiple security findings in a real, production iOS app.

This document describes what was found and what it demonstrates about iOS app security on Apple Silicon.

---

## Pipeline Results

| Phase | Outcome |
|-------|---------|
| Discovery | Found via `darkmach discover "sports betting"` |
| Static analysis | Successful — URLs, secrets, SDKs extracted from decrypted binary |
| FairPlay decryption | Successful — `simctl spawn` + `darkmach-decrypt.dylib` extracted crypt region |
| Patching | Successful — full bundle patched, re-signed, Simulator-ready |
| Simulator launch | Successful — app launched, interceptors active, bridge connected |
| Dynamic analysis | Successful — all 6 interceptors captured data, zero crashes |

**Total dylibs running simultaneously:** 6 (net, keychain, crypto, storage, ssl, db)
**Crashes during analysis:** 0
**Bridge connectivity:** Connected on first launch

---

## Findings

### Finding 1: RevenueCat API Key — MEDIUM

**Description:** The RevenueCat subscription management API key is transmitted in the `Authorization: Bearer` header on every request to `api.revenuecat.com`.

**Captured value:**
```
appl_tAkyaqcdQtdrtPKPKTauixcBNvZ
```

**Evidence (from `darkmach-net.jsonl`):**
```json
{"ts":"2026-03-23T14:32:01.423","mod":"net","evt":"request",
 "url":"https://api.revenuecat.com/v1/subscribers",
 "method":"GET",
 "headers":{"Authorization":"Bearer appl_tAkyaqcdQtdrtPKPKTauixcBNvZ","X-Platform":"ios"}}
```

**Impact:** The RevenueCat API key with `appl_` prefix is a public app API key — it controls subscription verification and is by design client-visible. However, its capture demonstrates the complete network layer visibility Darkmach provides. An attacker with this key could potentially enumerate subscriber data through the RevenueCat API.

**Source:** Captured in plaintext from `NSURLSession` network traffic via `darkmach-net.dylib`.

---

### Finding 2: Sentry DSN Keys (2 keys) — LOW

**Description:** Two Sentry error monitoring DSN keys were extracted — one from the native iOS binary and one from the React Native layer.

**Captured values:**
- Native Sentry DSN key: `01926c0ef214f0d6eaf9717dec146f28`
- React Native (Hermes) Sentry DSN key: `97e2f765952d4f9e8f7e4d3f096a731d`
- Native Sentry Project ID: `4506388217987072`
- React Native Sentry Project ID: `4505030748405760`

**Source:** Native key from binary string extraction (`darkmach analyze`); React Native key from Hermes bytecode decompilation (`darkmach hermes`).

**Impact:** Sentry DSN keys are semi-public (they're meant to be in the client binary to report crashes), but they enable third parties to submit fake crash reports to the project, potentially polluting telemetry or causing alert fatigue.

---

### Finding 3: Expo Project UUID — INFORMATIONAL

**Description:** The Expo EAS (Expo Application Services) project UUID was extracted from binary strings.

**Captured value:**
```
2905535b-ab20-48e9-9f9e-3bb50be50ee5
```

**Source:** Binary string extraction.

**Impact:** This UUID identifies the EAS project and could be used to enumerate EAS CDN assets or understand the build pipeline configuration.

---

### Finding 4: 88+ EAS CDN HMAC-SHA256 Auth Tokens — MEDIUM

**Description:** The SQLite asset database (`expo-v11.db`) contains records with HMAC-SHA256 authentication tokens for EAS CDN assets. 88+ such tokens were extracted.

**Evidence (from `darkmach-db.jsonl`):**
```json
{"ts":"2026-03-23T15:01:22.891","mod":"db","evt":"row",
 "db":"/var/mobile/Containers/Data/Application/.../expo-v11.db",
 "sql":"SELECT * FROM assets",
 "row":{"id":"42","url":"https://u.expo.dev/...","token":"hmac_sha256_abc123..."}}
```

**Source:** Captured via `darkmach-db.dylib` intercepting `sqlite3_step` on the Expo asset database.

**Impact:** HMAC tokens in asset records may be used to authenticate CDN requests. Their exposure could allow replay attacks against CDN endpoints. The volume (88+ tokens) suggests these are per-asset authentication tokens that rotate, but their presence in a local database is a notable attack surface.

---

### Finding 5: Session Tokens and User IDs in NSUserDefaults — MEDIUM

**Description:** Active session tokens with project IDs and session IDs were stored in `NSUserDefaults` and captured in plaintext.

**Evidence (from `darkmach-storage.jsonl`):**
```json
{"ts":"2026-03-23T15:01:23.012","mod":"storage","evt":"defaults_set",
 "key":"session_token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."}
{"ts":"2026-03-23T15:01:23.034","mod":"storage","evt":"defaults_set",
 "key":"projectId","value":"2905535b-ab20-48e9-9f9e-3bb50be50ee5"}
{"ts":"2026-03-23T15:01:23.041","mod":"storage","evt":"defaults_set",
 "key":"sessionId","value":"sess_8b4f2a9c1e3d"}
```

**Impact:** Session tokens stored in `NSUserDefaults` are accessible to any code running in the app process, any DYLD-injected library, and (as demonstrated here) any attacker who can instrument the app. The correct storage location for session tokens is the Keychain, which provides OS-level access controls.

---

### Finding 6: Apple Device ID — INFORMATIONAL

**Description:** The device's unique identifier was observed in network requests.

**Captured value:**
```
2838DF34-D9D3-413F-A83C-74EC0DF5A0E2
```

**Source:** `darkmach-net.jsonl` — observed in request headers.

**Impact:** Device IDs enable cross-session user fingerprinting. This is a common practice but represents a privacy consideration under regulations like GDPR and CCPA.

---

### Finding 7: RevenueCat Subscriber Data — MEDIUM

**Description:** The complete RevenueCat subscriber object was captured from network responses, including anonymous user ID, subscriber attributes, offering configurations, and purchase history.

**Evidence (from `darkmach-net.jsonl`):**
```json
{"ts":"2026-03-23T15:01:24.112","mod":"net","evt":"response",
 "url":"https://api.revenuecat.com/v1/subscribers/anonymous_user_id",
 "status":200,
 "body":"{\"subscriber\":{\"original_app_user_id\":\"$RCAnonymousID:...\",\"entitlements\":{\"premium\":{\"expires_date\":\"2026-09-01\"}},\"offerings\":{...}}}"}
```

**Impact:** Full subscriber state visibility — including entitlement status, purchase dates, and offering configurations. This level of detail about a user's subscription could be used to craft targeted attacks or understand the app's revenue model.

---

### Finding 8: 4 SQLite Databases Fully Mapped — HIGH (Information Exposure)

**Description:** The complete schema and data of 4 SQLite databases were captured during the app session.

**Databases:**

| Database | Tables | Notable Contents |
|----------|--------|-----------------|
| `expo-v11.db` | assets, update-log, metadata | EAS CDN asset tokens, update manifest |
| `Cache.db` | cfurl_cache_response, cfurl_cache_blob_data | Full HTTP cache including authenticated responses |
| `httpstorages.sqlite` | ItemTable | HTTP local storage key-value pairs |
| `:memory:` | Internal tables | In-memory SQLite state |

**Evidence (from `darkmach-db.jsonl`):**
```json
{"ts":"2026-03-23T15:01:22.001","mod":"db","evt":"open","path":"/var/.../Cache.db"}
{"ts":"2026-03-23T15:01:22.045","mod":"db","evt":"query","db":"/var/.../Cache.db",
 "sql":"SELECT * FROM cfurl_cache_response WHERE url LIKE '%api.revenuecat%'"}
```

**Impact:** The HTTP cache (`Cache.db`) stored complete authenticated API responses, including the full RevenueCat subscriber response with subscription state. An attacker who can read this file gets the same data without intercepting live traffic. The cache also stored headers including authorization tokens that were valid at time of caching.

---

### Finding 9: Complete API Surface Visible — INFORMATIONAL

**Description:** The full API surface of the app became visible through network interception, including all service endpoints, authentication patterns, and data structures.

**Services observed:**

| Service | Endpoint Pattern | Auth Method |
|---------|-----------------|-------------|
| RevenueCat | `https://api.revenuecat.com/v1/` | Bearer token (`appl_...`) |
| Sentry (native) | `https://o4506388...ingest.sentry.io/` | DSN key in URL |
| Expo EAS | `https://u.expo.dev/` | HMAC token per asset |
| Sentry (RN) | `https://o4505030...ingest.sentry.io/` | DSN key in URL |

**Impact:** Complete API map enables:
- Understanding the app's backend architecture
- Identifying authorization patterns and potential misconfigurations
- Finding unauthenticated endpoints
- Replay attacks against captured requests

---

## What These Findings Demonstrate

### About Darkmach's Capabilities

These findings were obtained from a single app session, with no prior knowledge of the app's internals, using only standard Darkmach pipeline operations:

1. `darkmach run /Applications/OddsJam.app` — launched the full pipeline
2. Natural app usage for a few minutes — triggered network requests and data access
3. Review of output JSONL files — structured, timestamped, correlated across interceptors

The findings required no custom scripting, no reverse engineering of specific protocols, and no prior knowledge of OddsJam's architecture. Everything was captured passively.

### About iOS App Security

The OddsJam analysis illustrates patterns common across iOS apps:

**Secrets in the binary:** API keys, DSN keys, and configuration values embedded in the binary or bytecode are extractable via static analysis on any iOS app on Apple Silicon.

**Session tokens outside the Keychain:** Storing session tokens in NSUserDefaults is a common mistake. The Keychain provides OS-level access controls; NSUserDefaults does not.

**HTTP cache as a secret store:** The `Cache.db` file accumulates authenticated API responses over time. Any tool that can read the Simulator filesystem (including `darkmach keychain`) can access these cached responses.

**Runtime secrets are readable:** The `darkmach-crypto.dylib` interceptor captures encryption keys at the moment of use — before they are applied. Even well-encrypted data in storage becomes visible when the key is read from the process.

### About the Scale of Exposure

OddsJam is one of thousands of iOS apps available on the Mac App Store. The Darkmach discovery pipeline (`darkmach discover --category all`) can enumerate the full population. Every app in that population has its encrypted binary readable by this technique, making Darkmach applicable at scale.
