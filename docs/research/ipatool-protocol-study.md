# ipatool Protocol Study

> exploit-engineer research -- 2026-03-26
> Source: `/dev/ipatool/` (Go source, github.com/majd/ipatool/v2)
> Purpose: Map the complete App Store protocol to build a Python replacement that presents the Mac's real FairPlay device identity instead of a fake one.

---

## Executive Summary

ipatool is a Go CLI that downloads encrypted iOS IPAs from the App Store by impersonating **Apple Configurator 2** (a legitimate macOS management tool). It does NOT impersonate an iPhone. It identifies itself as a Mac application. The "device identity" is nothing more than the machine's Ethernet MAC address, reformatted as a GUID string.

The critical finding: **ipatool does not implement any Anisette/ADI protocol.** There are zero references to `X-Apple-I-MD`, `X-Apple-I-MD-M`, OTP headers, or any hardware attestation in the source code. The authentication flow is a simple Apple ID + password + 2FA exchange with Apple's `MZFinance` backend, and the only "device" identifier is a MAC-address-derived GUID string sent in request bodies.

This means the sinf key material returned by Apple's download endpoint is bound to:
1. The Apple ID (authenticated via `passwordToken` + `dsPersonId`)
2. The GUID sent in the request body (MAC address of the requesting machine)

The DoorDash PoC failed with -42110 because the GUID in the sinf did not match the Mac's local FairPlay identity. The hypothesis: if we send the Mac's **real** GUID (or the identity that fairplayd uses), the returned sinf will be keyed to this Mac's FairPlay infrastructure, and `mremap_encrypted` decryption will succeed.

---

## Table of Contents

1. [Protocol Flow Overview](#1-protocol-flow-overview)
2. [Study Area 1: Device Identity](#2-study-area-1-device-identity)
3. [Study Area 2: Authentication](#3-study-area-2-authentication)
4. [Study Area 3: sinf Acquisition (Download Response)](#4-study-area-3-sinf-acquisition)
5. [Study Area 4: Download Flow](#5-study-area-4-download-flow)
6. [Study Area 5: Purchase Flow](#6-study-area-5-purchase-flow)
7. [Study Area 6: Constants, Headers, and Client Identity](#7-study-area-6-constants-headers-and-client-identity)
8. [Study Area 7: The adi.pb Connection](#8-study-area-7-the-adipb-connection)
9. [Complete HTTP Endpoint Map](#9-complete-http-endpoint-map)
10. [Where ipatool "Fakes" an Identity](#10-where-ipatool-fakes-an-identity)
11. [What We Need to Change for Mac Identity](#11-what-we-need-to-change-for-mac-identity)
12. [Unknowns and Risks](#12-unknowns-and-risks)
13. [Python Rewrite Complexity Assessment](#13-python-rewrite-complexity-assessment)

---

## 1. Protocol Flow Overview

```
                       +-----------+
                       | Bag       |  GET https://init.itunes.apple.com/bag.xml?guid=<GUID>
                       | Endpoint  |  Returns: authenticateAccount URL
                       +-----+-----+
                             |
                             v
                       +-----------+
                       | Login     |  POST <authenticateAccount URL>
                       | (Auth)    |  Body: XML plist {appleId, password+2FA, guid, attempt, rmp, why}
                       +-----+-----+  Returns: passwordToken, dsPersonId, storeFront, pod
                             |         Response headers: X-Set-Apple-Store-Front, pod
                             |         Cookies saved to persistent jar
                             v
                       +-----------+
                       | Purchase  |  POST https://[pN-]buy.itunes.apple.com/.../buyProduct
            (if       | (MZBuy)   |  Headers: iCloud-DSID, X-Dsid, X-Apple-Store-Front, X-Token
         needed)       +-----+-----+  Body: XML plist {guid, salableAdamId, pricingParameters, ...}
                             |         Returns: jingleDocType="purchaseSuccess"
                             v
                       +-----------+
                       | Download  |  POST https://[pN-]buy.itunes.apple.com/.../volumeStoreDownloadProduct?guid=<GUID>
                       | Metadata  |  Headers: iCloud-DSID, X-Dsid, Content-Type: application/x-apple-plist
                       +-----+-----+  Body: XML plist {guid, salableAdamId, creditDisplay}
                             |         Returns: songList[0].URL, songList[0].sinfs[], songList[0].metadata
                             v
                       +-----------+
                       | File      |  GET <URL from songList[0].URL>
                       | Download  |  Supports Range header for resume
                       +-----+-----+  Returns: raw IPA bytes
                             |
                             v
                       +-----------+
                       | Post-     |  1. Write iTunesMetadata.plist into IPA zip
                       | Process   |  2. Replicate sinf files into IPA's SC_Info/ directory
                       +-----------+     (from sinfs[] returned by download response)
```

**Key observation:** The sinf is returned **inside the download metadata response**, not as a separate request. The `songList[0].sinfs` array in the download response contains the sinf byte blobs. ipatool then writes these into the IPA's `SC_Info/` directory during post-processing.

---

## 2. Study Area 1: Device Identity

### Source: `pkg/util/machine/machine.go`

ipatool's entire concept of "device identity" is a single function:

```go
func (*machine) MacAddress() (string, error) {
    interfaces, err := net.Interfaces()
    // ... error handling ...
    for _, netInterface := range interfaces {
        addr := netInterface.HardwareAddr.String()
        if addr != "" {
            return addr, nil  // Returns first non-empty MAC address
        }
    }
    return "", fmt.Errorf("could not find network interfaces with a valid mac address")
}
```

The MAC address is then converted to a GUID:

```go
macAddr, err := t.machine.MacAddress()
guid := strings.ReplaceAll(strings.ToUpper(macAddr), ":", "")
// Example: "aa:bb:cc:dd:ee:ff" -> "AABBCCDDEEFF"
```

### What This Means

- **There is no hardware identifier, serial number, UDID, or device model in the protocol.**
- **There is no Anisette/ADI (Apple Device Identity) provisioning.**
- **There is no `X-Apple-I-MD` or `X-Apple-I-MD-M` OTP header.**
- The "device" is identified solely by a 12-character hex string derived from the first network interface's MAC address.
- This GUID is sent in **every** request that talks to Apple's private API:
  - Bag request (query parameter)
  - Login request (body field)
  - Purchase request (body field)
  - Download request (body field AND query parameter)
  - Version listing requests (body field AND query parameter)

### GUID Usage Map

| Request | GUID Location | Field Name |
|---------|--------------|------------|
| Bag | URL query param | `?guid=<GUID>` |
| Login | XML plist body | `guid` |
| Purchase | XML plist body | `guid` |
| Download | URL query param + XML plist body | `?guid=<GUID>` and `guid` |
| List Versions | URL query param + XML plist body | `?guid=<GUID>` and `guid` |
| Get Version Metadata | URL query param + XML plist body | `?guid=<GUID>` and `guid` |

---

## 3. Study Area 2: Authentication

### Source: `pkg/appstore/appstore_login.go`, `pkg/appstore/appstore_bag.go`

### Step 1: Fetch the Authentication Endpoint (Bag)

```
GET https://init.itunes.apple.com/bag.xml?guid=<GUID>
Headers:
  User-Agent: Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6
  Accept: application/xml
Response format: XML plist
Returns: urlBag.authenticateAccount = <auth endpoint URL>
```

The bag is Apple's service discovery mechanism. It returns a bag of URLs for various operations. ipatool only extracts the `authenticateAccount` URL.

### Step 2: Authenticate

```
POST <authenticateAccount URL>
  (typically: https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate)
Headers:
  Content-Type: application/x-www-form-urlencoded
  User-Agent: Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6
Body: XML plist containing:
  {
    "appleId":  "<email>",
    "attempt":  "1",            // increments on retry (1-4)
    "guid":     "<GUID>",       // MAC-address-derived
    "password": "<password><2FA_code>",  // 2FA code appended directly to password
    "rmp":      "0",
    "why":      "signIn"
  }
```

### Authentication Flow Details

1. First attempt with `attempt=1`. If response is `FailureType=-5000` (invalid credentials), retry with `attempt=2` (this handles some Apple-side quirk).
2. If HTTP 302 redirect, follow the redirect URL and retry.
3. If response indicates 2FA required (`customerMessage == "MZFinance.BadLogin.Configurator_message"` with no failure type), the caller prompts for the 2FA code.
4. On success, response contains:

```
Response (XML plist):
  dsPersonId:      "123456789"           // Directory Services Person ID
  passwordToken:   "<long_base64_token>" // Session authentication token
  accountInfo:
    appleId:       "user@example.com"
    address:       {firstName, lastName}
Response Headers:
  X-Set-Apple-Store-Front: "143441-1,29"  // US storefront
  pod:                     "42"           // Server pod assignment
  Set-Cookie:              <session cookies>
```

### Tokens Obtained

| Token | Source | Used In | Purpose |
|-------|--------|---------|---------|
| `passwordToken` | Login response body | Purchase (`X-Token` header) | Authenticates purchase requests |
| `dsPersonId` (DirectoryServicesID) | Login response body | Download/Purchase/Versions (`iCloud-DSID` + `X-Dsid` headers) | Identifies the authenticated user |
| `storeFront` | Login response header (`X-Set-Apple-Store-Front`) | Purchase (`X-Apple-Store-Front` header), Search/Lookup (country code derivation) | Regional store identification |
| `pod` | Login response header | URL prefix for purchase/download endpoints | Server routing |
| Session cookies | Login response `Set-Cookie` | All subsequent requests (automatic via cookie jar) | Session persistence |

### Token Persistence

- `passwordToken` + `dsPersonId` + `storeFront` + `pod` + `password` are serialized as JSON and stored in the system keychain via `github.com/99designs/keyring` (or a file-based fallback at `~/.ipatool/`).
- Cookies are persisted via `github.com/juju/persistent-cookiejar` at `~/.ipatool/cookies`.
- On subsequent runs, `AccountInfo()` reads from keychain -- no re-auth needed unless token expires.

### Redirect Handling

The HTTP client has special redirect behavior:
```go
CheckRedirect: func(req *http.Request, via []*http.Request) error {
    if req.Referer() == appStoreAuthURL {
        return http.ErrUseLastResponse  // Don't follow redirects from auth endpoint
    }
    return nil  // Follow all other redirects normally
}
```

The auth endpoint at `buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate` returns 302 redirects that ipatool must NOT auto-follow -- it captures the redirect URL and manually retries to it.

---

## 4. Study Area 3: sinf Acquisition

### Source: `pkg/appstore/appstore_download.go`, `pkg/appstore/appstore_replicate_sinf.go`

### Critical Finding: sinf Is NOT a Separate Request

The sinf data is returned **inline in the download metadata response**. There is no separate "get sinf" endpoint. The download request returns both the IPA download URL and the sinf blobs:

```go
type downloadItemResult struct {
    HashMD5  string                 `plist:"md5,omitempty"`
    URL      string                 `plist:"URL,omitempty"`
    Sinfs    []Sinf                 `plist:"sinfs,omitempty"`
    Metadata map[string]interface{} `plist:"metadata,omitempty"`
}

type downloadResult struct {
    FailureType     string               `plist:"failureType,omitempty"`
    CustomerMessage string               `plist:"customerMessage,omitempty"`
    Items           []downloadItemResult  `plist:"songList,omitempty"`
}
```

The `sinfs` field is an array of `Sinf` structs:

```go
type Sinf struct {
    ID   int64  `plist:"id,omitempty"`
    Data []byte `plist:"sinf,omitempty"`
}
```

Each sinf has an `id` (numeric identifier) and `Data` (raw sinf bytes -- the DRM atom).

### sinf Replication into the IPA

After downloading the IPA, ipatool writes the sinf data into the zip archive. Two strategies:

**Strategy 1: Manifest-based** (preferred)
If the IPA contains `Payload/<App>.app/SC_Info/Manifest.plist`, it lists `SinfPaths` (e.g., `["SC_Info/AppName.sinf"]`). The sinfs are matched by index to the manifest paths.

**Strategy 2: Info.plist-based** (fallback)
If no manifest, uses `CFBundleExecutable` from Info.plist to construct the path: `Payload/<App>.app/SC_Info/<CFBundleExecutable>.sinf`. Writes the first sinf to this path.

### What Determines the sinf Content?

Apple's `volumeStoreDownloadProduct` endpoint receives:
- **GUID** (in both URL query parameter and body)
- **dsPersonId** (in `iCloud-DSID` and `X-Dsid` headers)
- **salableAdamId** (app ID)
- **Session cookies**

The server generates/returns sinf keyed to:
- The authenticated Apple ID (via dsPersonId + passwordToken cookies)
- Likely the GUID sent in the request (this is the central hypothesis)

**The question is: does Apple use the GUID to key the sinf to a specific device, or is the sinf generic to the Apple ID?**

From the DoorDash PoC analysis, the sinf contained:
- `[user]` = `50 13 5A 74` (Apple ID hash -- matches ipatool's auth account)
- `[name]` = "Justin McCloud" (the Apple ID owner)
- `[priv]` = 440 bytes encrypted private key material
- `[key]` = `0x1E` (key index 30)

The `priv` field is the encrypted content key. It must be decryptable by the device's FairPlay infrastructure. If it's encrypted under the GUID-associated device identity, then sending the correct GUID (matching the Mac's `adi.pb`) would produce a decryptable sinf.

---

## 5. Study Area 4: Download Flow

### Source: `pkg/appstore/appstore_download.go`, `cmd/download.go`

### Complete Sequence

```
1. AccountInfo()  -- read cached credentials from keychain
2. (if needed) Login()  -- re-authenticate if passwordToken expired
3. (if bundleID specified) Lookup()  -- resolve bundleID to trackId via iTunes API
4. (if license needed) Purchase()  -- acquire license for free app
5. Download()  -- the main download operation:
   a. Build download request
   b. Send to volumeStoreDownloadProduct endpoint
   c. Parse response: get URL, sinfs, metadata
   d. Download IPA file from URL
   e. Post-process: add iTunesMetadata.plist, replicate sinfs
6. ReplicateSinf()  -- write sinf blobs into the IPA zip
```

### Download Request

```
POST https://[p<pod>-]buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=<GUID>
Headers:
  Content-Type:  application/x-apple-plist
  iCloud-DSID:   <dsPersonId>
  X-Dsid:        <dsPersonId>
  User-Agent:    Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6
  Cookie:        <session cookies from login>
Body: XML plist:
  {
    "creditDisplay":  "",
    "guid":           "<GUID>",
    "salableAdamId":  <app_track_id>,
    "externalVersionId": "<version>"  // optional, for specific version downloads
  }
```

### Download Response

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>songList</key>
  <array>
    <dict>
      <key>URL</key>
      <string>https://iosapps.itunes.apple.com/itunes-assets/...</string>
      <key>md5</key>
      <string>abc123...</string>
      <key>sinfs</key>
      <array>
        <dict>
          <key>id</key>
          <integer>12345</integer>
          <key>sinf</key>
          <data>BASE64_ENCODED_SINF_BYTES</data>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundleShortVersionString</key>
        <string>8.11.0</string>
        <key>softwareVersionExternalIdentifier</key>
        <integer>876543210</integer>
        <key>softwareVersionExternalIdentifiers</key>
        <array>...</array>
        <key>releaseDate</key>
        <string>2026-03-15T00:00:00Z</string>
        ...
      </dict>
    </dict>
  </array>
</dict>
</plist>
```

### Post-Processing

Two operations after IPA download:

1. **iTunesMetadata.plist injection**: Takes the metadata dict from the response, adds `apple-id` and `userName` fields (both set to the account email), serializes as binary plist, and writes to the root of the IPA zip as `iTunesMetadata.plist`.

2. **sinf replication**: Writes sinf blobs into the IPA at the SC_Info paths (see Study Area 3).

### File Download

The actual IPA binary download is a simple HTTP GET with Range header support for resume:

```
GET <URL from songList[0].URL>
Headers:
  Range: bytes=<existing_size>-    // for resume support
  User-Agent: Configurator/2.17 ...
```

---

## 6. Study Area 5: Purchase Flow

### Source: `pkg/appstore/appstore_purchase.go`

### When Purchase Is Needed

The download endpoint returns `failureType: "9610"` (license not found) if the Apple ID hasn't "purchased" the app. Even free apps require a license acquisition step.

### Purchase Request

```
POST https://[p<pod>-]buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct
Headers:
  Content-Type:        application/x-apple-plist
  iCloud-DSID:         <dsPersonId>
  X-Dsid:              <dsPersonId>
  X-Apple-Store-Front: <storeFront>   // e.g., "143441-1,29" for US
  X-Token:             <passwordToken>
  User-Agent:          Configurator/2.17 ...
  Cookie:              <session cookies>
Body: XML plist:
  {
    "appExtVrsId":               "0",
    "hasAskedToFulfillPreorder": "true",
    "buyWithoutAuthorization":   "true",
    "hasDoneAgeCheck":           "true",
    "guid":                      "<GUID>",
    "needDiv":                   "0",
    "origPage":                  "Software-<app_id>",
    "origPageLocation":          "Buy",
    "price":                     "0",
    "pricingParameters":         "STDQ",   // or "GAME" for Apple Arcade
    "productType":               "C",
    "salableAdamId":             <app_id>
  }
```

### Purchase Response

```xml
<dict>
  <key>jingleDocType</key>
  <string>purchaseSuccess</string>
  <key>status</key>
  <integer>0</integer>
</dict>
```

### Important Purchase Fields

| Field | Value | Significance |
|-------|-------|--------------|
| `pricingParameters` | `"STDQ"` | Standard App Store pricing. Falls back to `"GAME"` for Apple Arcade titles |
| `productType` | `"C"` | Content type indicator (software) |
| `buyWithoutAuthorization` | `"true"` | Skips payment authorization (free apps only) |
| `guid` | `<MAC_GUID>` | Device identifier -- same GUID as everywhere else |

**Note:** ipatool explicitly refuses to purchase paid apps (`if input.App.Price > 0: return error`).

---

## 7. Study Area 6: Constants, Headers, and Client Identity

### Source: `pkg/http/constants.go`, `pkg/appstore/constants.go`, `pkg/appstore/storefront.go`

### User-Agent String

```
Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6
```

This impersonates **Apple Configurator 2** version 2.17, running on macOS 15.2 (build 24C5089c). Apple Configurator is a legitimate Apple tool for managing iOS devices from a Mac. It has the ability to download iOS apps from the App Store for deployment to managed devices.

**This is significant:** ipatool does NOT claim to be an iPhone. It claims to be a Mac running Apple Configurator. The App Store backend accepts this as a valid client for downloading iOS apps.

### API Domains

| Constant | Value | Purpose |
|----------|-------|---------|
| `iTunesAPIDomain` | `itunes.apple.com` | Public iTunes API (search, lookup) |
| `iTunesAPIPathSearch` | `/search` | App Store search |
| `iTunesAPIPathLookup` | `/lookup` | App lookup by bundle ID |
| `PrivateInitDomain` | `init.itunes.apple.com` | Service discovery (bag) |
| `PrivateInitPath` | `/bag.xml` | Bag endpoint path |
| `PrivateAppStoreAPIDomain` | `buy.itunes.apple.com` | Authenticated operations |
| `PrivateAppStoreAPIPathPurchase` | `/WebObjects/MZFinance.woa/wa/buyProduct` | License acquisition |
| `PrivateAppStoreAPIPathDownload` | `/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct` | Download metadata + sinf |

### Headers Summary (All Requests)

```
User-Agent:          Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6
```

**Additional headers per operation:**

| Operation | Extra Headers |
|-----------|--------------|
| Login | `Content-Type: application/x-www-form-urlencoded` |
| Purchase | `Content-Type: application/x-apple-plist`, `iCloud-DSID`, `X-Dsid`, `X-Apple-Store-Front`, `X-Token` |
| Download | `Content-Type: application/x-apple-plist`, `iCloud-DSID`, `X-Dsid` |
| List Versions | `Content-Type: application/x-apple-plist`, `iCloud-DSID`, `X-Dsid` |

### Pod-Based URL Routing

When the login response includes a `pod` header (e.g., `"42"`), subsequent authenticated requests prefix the domain with `p<pod>-`:

```
Standard:   https://buy.itunes.apple.com/...
With pod:   https://p42-buy.itunes.apple.com/...
```

### StoreFront Codes

ipatool maintains a map of 120+ country codes to storefront IDs (e.g., `"US": "143441"`, `"GB": "143444"`, `"JP": "143462"`). The storefront is received from the login response as `X-Set-Apple-Store-Front` and sent in subsequent requests as `X-Apple-Store-Front`.

### Failure Codes

| Code | Constant | Meaning |
|------|----------|---------|
| `-5000` | `FailureTypeInvalidCredentials` | Wrong password (first attempt retried) |
| `2034` | `FailureTypePasswordTokenExpired` | Token expired, need re-login |
| `9610` | `FailureTypeLicenseNotFound` | App not "purchased", need to call buyProduct first |
| `2059` | `FailureTypeTemporarilyUnavailable` | Temporary error, retry with Apple Arcade pricing param |

---

## 8. Study Area 7: The adi.pb Connection

### What's in the ipatool Source

**Nothing.** Zero references to:
- `adi.pb` or `adi`
- Anisette
- `X-Apple-I-MD` or `X-Apple-I-MD-M`
- OTP (One-Time Password/Provisioning)
- Machine headers
- Hardware model, UDID, serial number, or device class
- `ADILoadLibraryWithPath`, `ADIProvisionDevice`, `ADIGetLoginCode`

ipatool's authentication bypasses the Anisette layer entirely. It authenticates directly with the MZFinance backend using Apple ID credentials, not through the full Apple Identity Service (IDS/AKS) stack that includes Anisette provisioning.

### What Is adi.pb?

From our investigation (`/var/db/fpsd/adi/adi.pb`, 1650 bytes):

```
Offset 0x000: 00 00 00 01 00 00 00 16  (version=1, length/type=0x16=22)
Offset 0x008: 61 15 53 c9 72 3b 50 4e  (encrypted identity data)
...
Offset 0x670: 06 3a                    (end, total 1650 bytes)
```

- **Format:** Binary, not protobuf despite the `.pb` extension. Header is a big-endian version + type indicator followed by encrypted/opaque identity data.
- **Permissions:** `-rw-rw-rw-` (world-readable/writable) inside a `drwxrwxrwx` directory.
- **Purpose:** Contains the hardware-bound FairPlay Device Identity. Used by `fairplayd` to validate sinf key material during decryption.
- **Created by:** `fairplaydeviceidentityd` during device provisioning.

### SC Info.sidb

From `/var/db/fpsd/SC Info/SC Info.sidb` (672 bytes):

```
Offset 0x000: 00 07 00 0b  (version/type header)
Offset 0x004: 73 05 e2 3a  (encrypted key data)
...
Offset 0x29F: end (672 bytes)
```

- **Format:** Binary encrypted key database.
- **Permissions:** `-rw-rw-rw-` but inside a `drwx------` directory (only `_fpsd` can traverse).
- **Purpose:** Contains device-specific FairPlay decryption keys. The counterpart to sinf files in app bundles.

### The Anisette Protocol (Background Research)

The Apple Anisette protocol provides device attestation for Apple services. It uses:

- **X-Apple-I-MD** (Machine Data): A one-time token (~300 bytes base64) generated from the device's ADI provisioning
- **X-Apple-I-MD-M** (Machine Data - Machine): A machine identifier (~50 bytes base64) derived from hardware identity
- **X-Apple-I-MD-RINFO**: Request info code (typically `17106176`)
- **X-Apple-I-SRL-NO**: Serial number
- **X-Apple-I-Client-Time**: ISO 8601 timestamp
- **X-Apple-I-TimeZone**: Timezone abbreviation
- **X-Apple-I-Locale**: Locale string

These headers are required for most Apple authentication endpoints (iCloud, Apple ID, iMessage, etc.). The ADI library (`libstoreservicescore.dylib` on macOS, `CoreADI.framework` on iOS) generates the one-time tokens from the device's provisioning state stored in `adi.pb`.

**ipatool avoids this entirely** by impersonating Apple Configurator, which apparently authenticates through a different code path (MZFinance) that does not require Anisette headers. This is a significant protocol shortcut.

### The Connection We Need

The FairPlay decryption chain requires:
1. **sinf** (per-app key material, encrypted under a device identity)
2. **SC Info.sidb** (device key database, present on Mac)
3. **adi.pb** (device identity blob, present on Mac)

When `fairplayd` tries to decrypt an app's sinf, it derives the decryption key using the device identity from `adi.pb` and the key database from `SC Info.sidb`. If the sinf was generated for a different device identity (different GUID/adi.pb), the key derivation fails with error -42110.

**The hypothesis:** Apple's `volumeStoreDownloadProduct` endpoint uses the GUID to associate the sinf with a specific device's FairPlay identity. If we send the Mac's real GUID (the one associated with its `adi.pb`), the returned sinf should be decryptable by the Mac's `fairplayd`.

**Open question:** Is the GUID the only device identifier in the sinf binding, or does Apple use additional factors (Anisette attestation, hardware serial, etc.) that ipatool's simplified protocol doesn't provide? The fact that ipatool successfully downloads sinf data that works for decryption on jailbroken iPhones (its primary use case) suggests the GUID-based binding is sufficient.

---

## 9. Complete HTTP Endpoint Map

### Public Endpoints (No Auth)

| # | Method | URL | Purpose | Body/Params |
|---|--------|-----|---------|------------|
| 1 | GET | `https://itunes.apple.com/search?entity=software,iPadSoftware&limit=N&media=software&term=QUERY&country=CC` | Search apps | URL params |
| 2 | GET | `https://itunes.apple.com/lookup?entity=software,iPadSoftware&limit=1&media=software&bundleId=BUNDLE&country=CC` | Lookup by bundle ID | URL params |

### Service Discovery (No Auth)

| # | Method | URL | Purpose | Headers |
|---|--------|-----|---------|---------|
| 3 | GET | `https://init.itunes.apple.com/bag.xml?guid=GUID` | Fetch auth endpoint URL | `Accept: application/xml` |

### Authenticated Endpoints

| # | Method | URL | Purpose | Headers | Body Fields |
|---|--------|-----|---------|---------|-------------|
| 4 | POST | `<bag.authenticateAccount>` | Login | `Content-Type: application/x-www-form-urlencoded` | `appleId`, `password`, `guid`, `attempt`, `rmp`, `why` |
| 5 | POST | `https://[pN-]buy.itunes.apple.com/.../buyProduct` | Purchase | `iCloud-DSID`, `X-Dsid`, `X-Apple-Store-Front`, `X-Token` | `guid`, `salableAdamId`, `pricingParameters`, `productType`, ... |
| 6 | POST | `https://[pN-]buy.itunes.apple.com/.../volumeStoreDownloadProduct?guid=GUID` | Download metadata + sinf | `iCloud-DSID`, `X-Dsid` | `guid`, `salableAdamId`, `creditDisplay`, [`externalVersionId`] |
| 7 | GET | `<songList[0].URL>` | Download IPA binary | `Range: bytes=N-` (optional) | -- |

### Response Data Flow

```
Endpoint 3 (Bag)        -> authEndpoint URL
Endpoint 4 (Login)      -> passwordToken, dsPersonId, storeFront, pod, cookies
Endpoint 5 (Purchase)   -> purchaseSuccess confirmation
Endpoint 6 (Download)   -> sinfs[], download URL, metadata
Endpoint 7 (File DL)    -> IPA bytes
```

---

## 10. Where ipatool "Fakes" an Identity

### What ipatool DOES Present as Its Identity

| Factor | Value | Source |
|--------|-------|--------|
| User-Agent | `Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6` | Hardcoded constant |
| GUID | First non-empty MAC address, uppercase, no colons | `net.Interfaces()` |
| Apple ID | User-provided email + password + 2FA | CLI input |
| Storefront | Returned by Apple on login | Server-assigned |
| DSID | Returned by Apple on login | Server-assigned |

### What ipatool Does NOT Present

| Factor | Real Apple Configurator Behavior | ipatool |
|--------|--------------------------------|---------|
| Anisette headers (X-Apple-I-MD, X-Apple-I-MD-M) | Likely sends them | **Not sent** |
| Hardware serial number | Likely includes | **Not sent** |
| Device model/class | Likely includes | **Not sent** |
| OS build fingerprint | In User-Agent only (static) | Hardcoded |
| Code signing identity | Apple-signed binary | Not applicable |

### The "Fake" Is Minimal

ipatool doesn't fake an iPhone. It doesn't even fully fake Apple Configurator. It sends:
1. A Configurator-like User-Agent string
2. A MAC-address GUID as the device identifier
3. Real Apple ID credentials

The App Store backend apparently accepts this minimal set of identifiers. The GUID is the only "device identity" sent, and it determines (at minimum) which sinf key material is generated.

### Why the DoorDash PoC Failed

The DoorDash IPA was downloaded with ipatool running on an **unknown machine** (likely a different computer or VM). The GUID sent was derived from that machine's MAC address. The sinf was keyed to that GUID's associated device identity. When we tried to decrypt on our Mac, `fairplayd` couldn't match the sinf's key material against our Mac's `adi.pb`/`SC Info.sidb`, resulting in error -42110.

---

## 11. What We Need to Change for Mac Identity

### Minimal Change: Replace the GUID

The simplest approach: instead of generating a GUID from the machine's MAC address, generate or discover the GUID that `fairplayd` on this Mac associates with its own identity.

**The question is: what GUID does fairplayd expect?**

Possibilities:
1. **MAC address of en0** -- Same as what ipatool does, but our Mac's en0 MAC address. If the Mac's App Store client uses the same GUID derivation, this might work.
2. **A GUID derived from adi.pb** -- The adi.pb blob might contain or be indexed by a GUID. Need to investigate.
3. **A GUID from Apple's provisioning** -- The Mac's initial App Store activation might have registered a GUID with Apple that's different from the MAC address.
4. **The Mac's hardware UUID** -- `system_profiler SPHardwareDataType | grep "Hardware UUID"` or `ioreg -d2 -c IOPlatformExpertDevice | grep IOPlatformUUID`.

### What to Build (Python Replacement)

```python
# Core protocol (replaces ipatool Go):

1. guid_provider.py       -- Determine the correct GUID for this Mac
2. auth.py                -- Bag fetch + Apple ID login (same protocol)
3. purchase.py            -- MZBuy license acquisition (same protocol)
4. download.py            -- volumeStoreDownloadProduct + sinf extraction
5. sinf_replicator.py     -- Write sinf into IPA zip
6. main.py / cli.py       -- Orchestration
```

### Protocol Changes Required

| Component | ipatool Behavior | Our Behavior | Change Needed |
|-----------|-----------------|--------------|---------------|
| GUID generation | MAC address of first interface | Mac's FairPlay-associated GUID | **Yes -- critical** |
| User-Agent | Configurator/2.17 | Same or updated version | No (or cosmetic) |
| Auth flow | Apple ID + password + 2FA via MZFinance | Same | No |
| Purchase flow | buyProduct with GUID | Same, with correct GUID | GUID only |
| Download flow | volumeStoreDownloadProduct with GUID | Same, with correct GUID | GUID only |
| sinf handling | Extract from response, write to IPA | Same | No |
| Anisette | Not implemented | Investigate if needed | **Unknown** |

### The GUID Discovery Problem

This is the hardest unknown. We need to determine what GUID `fairplayd` expects for sinf validation. Approaches:

1. **Test with en0 MAC address**: Run our Python tool on this Mac with the same Apple ID that's logged into the Mac App Store. Use the en0 MAC address as GUID. Download an app we "own". See if `mremap_encrypted` succeeds.

2. **Inspect fairplayd traffic**: Use `dtrace` or `log stream` to observe what identifiers `fairplayd` uses when validating a Mac App Store-delivered app's sinf.

3. **Reverse engineer SC Info.sidb**: If we can determine what identifier is embedded in the key database, we know what GUID to present.

4. **Use Apple's own libraries**: Call into `StoreFoundation.framework` or `CommerceKit.framework` to have the system generate the correct download request, rather than building it from scratch.

---

## 12. Unknowns and Risks

### Risk 1: GUID-to-adi.pb Binding (HIGH)

**Unknown:** How exactly does Apple bind a GUID to the FairPlay device identity? Is it a simple mapping, or does it involve cryptographic attestation?

**Risk:** If the binding involves Anisette attestation that ipatool bypasses, sending the "correct" GUID might not be sufficient. Apple's server might need proof that the requesting machine actually controls that GUID (via X-Apple-I-MD signed OTP).

**Mitigation:** Test with the Mac's own MAC-derived GUID first. If that fails, investigate whether `libstoreservicescore.dylib` can provide the necessary Anisette headers.

### Risk 2: Apple Configurator Deprecation (MEDIUM)

**Unknown:** Apple may have tightened or deprecated the Configurator auth path since ipatool was last updated.

**Risk:** The MZFinance endpoints might start requiring Anisette headers, device attestation, or specific entitlements.

**Mitigation:** Test the current protocol. If it fails, reverse engineer how the real Apple Configurator 2 (or the Mac App Store client) authenticates.

### Risk 3: Per-App vs Per-Account sinf Binding (MEDIUM)

**Unknown:** Is the sinf's device binding per-GUID (any GUID you send gets that GUID's key material) or is there an additional check that the GUID is "registered" with Apple as a real device?

**Risk:** Apple might maintain a registry of valid GUIDs (provisioned via Anisette/ADI). A random GUID might get a sinf, but only a GUID with a matching adi.pb can decrypt it.

**Mitigation:** Use the Mac's real identifiers. The Mac IS a registered Apple device with valid adi.pb.

### Risk 4: Account-Level vs Device-Level Restrictions (LOW)

**Unknown:** Does downloading an iOS-only app (opted out of Mac) trigger any additional checks beyond standard purchase verification?

**Risk:** Apple might restrict iOS-channel downloads to devices claiming to be iPhones/iPads.

**Mitigation:** ipatool already downloads iOS-only apps (DoorDash was opted out of Mac). The download succeeds. The issue is sinf binding, not download eligibility.

### Risk 5: Rate Limiting / Account Flagging (LOW)

**Unknown:** Does Apple flag accounts that make API calls with the Configurator User-Agent pattern?

**Risk:** Account suspension or temporary blocks.

**Mitigation:** Low risk based on ipatool's widespread use. Use conservative request patterns.

---

## 13. Python Rewrite Complexity Assessment

### Scope

The critical path involves 4 network operations and 2 local file operations:

| Component | ipatool Lines (Go) | Estimated Python Lines | Complexity |
|-----------|-------------------|----------------------|------------|
| GUID provider | 20 (machine.go) | 30-50 (with Mac-specific discovery) | Low-Medium |
| HTTP client (plist handling) | 240 (client.go + payload.go) | 150-200 (requests + plistlib) | Medium |
| Cookie persistence | External dep (persistent-cookiejar) | 30-50 (http.cookiejar + pickle) | Low |
| Bag fetch | 25 (appstore_bag.go) | 20 | Low |
| Login/Auth | 60 (appstore_login.go) | 50-70 (including 2FA handling) | Medium |
| Purchase | 50 (appstore_purchase.go) | 40 | Low |
| Download metadata | 80 (appstore_download.go, relevant parts) | 60 | Low |
| File download | 40 (appstore_download.go, file download) | 30 | Low |
| sinf replication | 90 (appstore_replicate_sinf.go) | 60-80 (zipfile module) | Medium |
| Post-processing | 50 (applyPatches + writeMetadata) | 40 | Low |
| CLI / orchestration | 120 (cmd/*.go) | 80-100 (argparse) | Low |
| Credential storage | 70 (keychain + keyring deps) | 40-60 (keyring or file-based) | Low |
| **Total** | **~845** | **~600-760** | -- |

### Dependencies

**Required (Python stdlib):**
- `plistlib` -- XML plist encoding/decoding (replaces Go's `howett.net/plist`)
- `http.cookiejar` -- Cookie management
- `zipfile` -- IPA manipulation
- `urllib.request` or `requests` -- HTTP client
- `json` -- Credential serialization
- `hashlib` -- MD5 verification
- `uuid` -- MAC address retrieval

**Optional external:**
- `requests` -- Cleaner HTTP client than urllib (but stdlib works)
- `keyring` -- Cross-platform credential storage (or just use a file)

### Estimated Implementation Time

| Phase | Effort | Description |
|-------|--------|-------------|
| 1. GUID research | 2-4 hours | Determine what GUID fairplayd expects. Test with Mac's en0 MAC. |
| 2. Core protocol | 4-6 hours | Auth, purchase, download metadata, sinf extraction. All straightforward plist-over-HTTP. |
| 3. File operations | 2-3 hours | IPA download with resume, sinf replication, metadata injection. |
| 4. Testing | 2-4 hours | End-to-end test: download IPA, install in Simulator, verify decryption. |
| 5. GUID iteration | 0-8 hours | If en0 MAC doesn't work, investigate alternatives (hardware UUID, Anisette, StoreFoundation). |
| **Total (optimistic)** | **10-13 hours** | If en0 MAC GUID works |
| **Total (pessimistic)** | **18-25 hours** | If GUID discovery requires Anisette or framework integration |

### Critical Path

```
GUID research (MUST succeed) -> Core protocol -> File operations -> E2E test
                                                                      |
                                           If -42110 again -> GUID iteration
```

The entire effort hinges on GUID resolution. The protocol itself is simple -- it's plist-over-HTTP with straightforward authentication. The hard part is ensuring the sinf is keyed to this Mac's FairPlay identity.

---

## Appendix A: ipatool Source File Map

| File | Lines | Purpose | Relevance |
|------|-------|---------|-----------|
| `pkg/util/machine/machine.go` | 70 | MAC address (GUID source) | **Critical** -- device identity |
| `pkg/appstore/appstore_login.go` | 180 | Apple ID authentication | **Critical** -- auth flow |
| `pkg/appstore/appstore_download.go` | 305 | Download metadata + sinf acquisition | **Critical** -- sinf is here |
| `pkg/appstore/appstore_purchase.go` | 133 | License acquisition (MZBuy) | **High** -- needed for first download |
| `pkg/appstore/appstore_replicate_sinf.go` | 234 | sinf injection into IPA | **High** -- post-processing |
| `pkg/appstore/appstore_bag.go` | 58 | Service discovery (bag.xml) | **High** -- provides auth URL |
| `pkg/appstore/constants.go` | 29 | API domains and paths | **High** -- endpoint definitions |
| `pkg/http/constants.go` | 12 | User-Agent string | **High** -- client identity |
| `pkg/http/client.go` | 240 | HTTP client with plist/JSON parsing | **Medium** -- rewrite in Python |
| `pkg/http/payload.go` | 51 | XML plist body serialization | **Medium** -- plistlib replacement |
| `pkg/appstore/storefront.go` | 156 | Country code to storefront mapping | **Low** -- static data |
| `pkg/appstore/account.go` | 12 | Account data structure | **Low** -- trivial struct |
| `pkg/appstore/app.go` | 44 | App data structure | **Low** -- trivial struct |
| `pkg/appstore/appstore.go` | 72 | Interface + constructor | **Low** -- architectural glue |
| `pkg/appstore/appstore_search.go` | 70 | App Store search | **Low** -- optional feature |
| `pkg/appstore/appstore_lookup.go` | 65 | Bundle ID lookup | **Low** -- optional but useful |
| `pkg/appstore/appstore_list_versions.go` | 105 | Version history | **Low** -- optional feature |
| `pkg/appstore/appstore_get_version_metadata.go` | 98 | Version details | **Low** -- optional feature |
| `pkg/appstore/appstore_account_info.go` | 29 | Read cached account | **Low** -- credential management |
| `pkg/appstore/appstore_revoke.go` | 15 | Clear cached account | **Low** -- credential management |
| `pkg/keychain/` | ~70 | Credential storage | **Low** -- simple key-value store |
| `cmd/` | ~400 | CLI orchestration | **Low** -- separate concern |

## Appendix B: Request/Response Format Details

### XML Plist Body Encoding

ipatool sends request bodies as XML plists (not binary plist). The Go library `howett.net/plist` handles this. In Python, `plistlib.dumps(data, fmt=plistlib.FMT_XML)` is the equivalent.

Example login body:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>appleId</key>
    <string>user@example.com</string>
    <key>attempt</key>
    <string>1</string>
    <key>guid</key>
    <string>AABBCCDDEEFF</string>
    <key>password</key>
    <string>MyPassword123456</string>
    <key>rmp</key>
    <string>0</string>
    <key>why</key>
    <string>signIn</string>
</dict>
</plist>
```

### Response Parsing

Responses from Apple's private API can be in various XML formats:
1. Standard XML plist
2. Plist embedded in a `<Document>` wrapper
3. Plist embedded in a `<plist>` tag within other XML
4. Bare `<dict>` without plist wrapper
5. Bare `<key>` elements without any wrapper

ipatool's `normalizeXMLPlistBody()` handles all these cases by progressively extracting the inner plist content. Our Python implementation needs the same normalization.

### Cookie Handling

Cookies are critical for session persistence after login. ipatool uses `persistent-cookiejar` (GitHub: juju/persistent-cookiejar) which serializes cookies to a file. In Python, `http.cookiejar.MozillaCookieJar` or a simple pickle-based approach works.

The auth endpoint's redirect handling is particularly sensitive -- the HTTP client must NOT automatically follow redirects from the auth URL (`buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate`), but must capture the redirect location and manually retry.

---

## Appendix C: Proposed First Experiment

Before writing any Python code, validate the core hypothesis:

### Experiment: Same-Account Download with Mac's GUID

1. **Determine this Mac's GUID:**
   ```bash
   # Get en0 MAC address
   ifconfig en0 | grep ether | awk '{print $2}'
   # Convert to GUID format: uppercase, no colons
   # e.g., "a8:60:b6:12:34:56" -> "A860B6123456"
   ```

2. **Log into ipatool with the SAME Apple ID that's signed into this Mac's App Store:**
   ```bash
   ipatool auth login -e <your_apple_id>
   ```

3. **Download a free app that the Mac's Apple ID owns:**
   ```bash
   ipatool download -b <bundle_id> --purchase
   ```
   (ipatool will use this Mac's en0 MAC address as the GUID since it's running on this Mac)

4. **Extract and install in Simulator:**
   - Extract IPA
   - Patch platform (iOS -> iOSSimulator) but do NOT zero cryptid
   - Preserve SC_Info with sinf intact
   - Install in Simulator

5. **Launch and check kernel log:**
   ```bash
   xcrun simctl launch --console booted <bundle_id> &
   log show --predicate 'eventMessage contains "fairplay" OR eventMessage contains "42110" OR eventMessage contains "set_code_unprotect"' --last 10s
   ```

**Expected outcomes:**
- **Success:** No -42110 error. App launches (or at least passes FairPlay validation). This proves the hypothesis.
- **Failure with -42110:** The en0 MAC GUID isn't what fairplayd expects. Need to investigate alternative GUIDs.
- **Different error:** New failure mode to analyze.

This experiment costs zero code. It uses existing tools (ipatool + darkmach patcher) and takes ~30 minutes. It should be done BEFORE writing any Python.
