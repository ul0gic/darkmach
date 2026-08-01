![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Protocol](https://img.shields.io/badge/protocol-JSON--lines%20over%20Unix%20socket-lightgrey)

# LLM Runtime Bridge

The LLM Runtime Bridge is Darkmach's most powerful capability: an injected C dylib that opens a communication channel from inside a running iOS app, connected to an LLM or interactive client that can explore, interrogate, and reason about the live app autonomously.

---

## What the Bridge Is

`darkmach-bridge.dylib` is injected into the app process at launch alongside the interceptors. When its constructor runs, it:

1. Opens a Unix domain socket at `/tmp/darkmach-bridge.sock`
2. Starts a listener on a GCD dispatch queue (non-blocking)
3. Accepts JSON command requests and returns JSON responses
4. Remains active for the lifetime of the process

An external client — `darkmach bridge` interactive mode, a script, or an LLM agent — connects to the socket and sends commands. The dylib executes them inside the app process, with full access to the ObjC runtime, the live heap, all data stores, and all loaded memory.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    iOS App (Simulator)                       │
│                                                             │
│   darkmach-bridge.dylib                                       │
│   ├── Constructor: opens /tmp/darkmach-bridge.sock            │
│   ├── GCD listener: accepts connections                     │
│   ├── Command dispatch: parse JSON → execute → return JSON  │
│   │                                                         │
│   │   60 commands across 9 modules:                        │
│   │   ├── Core: info                                        │
│   │   ├── Recon: ObjC runtime, heap, data stores           │
│   │   ├── Network: HTTP tap, crypto, auth flow recording   │
│   │   ├── Trace: trampoline-based method tracing           │
│   │   ├── UI: view hierarchy, interactions                  │
│   │   ├── Analysis: WebViews, blocks, protobufs            │
│   │   ├── Forensics: memory scanning, cert pinning         │
│   │   ├── Injection: runtime class/method synthesis        │
│   │   └── Events: NSNotificationCenter monitoring          │
│   │                                                         │
│   └── Socket: /tmp/darkmach-bridge.sock                       │
│              │                                              │
└──────────────┼──────────────────────────────────────────────┘
               │
               │  Newline-delimited JSON
               │  Request:  {"id":1,"cmd":"...","args":{...}}\n
               │  Response: {"id":1,"ok":true,"data":{...}}\n
               │
┌──────────────┼──────────────────────────────────────────────┐
│   Client     │                                              │
│              │                                              │
│   ├── darkmach bridge (interactive REPL)                      │
│   ├── darkmach.bridge.send_command() (Python API)             │
│   └── Any client speaking the JSON protocol                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Protocol

The bridge uses newline-delimited JSON over a Unix domain socket (`AF_UNIX`, `SOCK_STREAM`).

### Request Format

```json
{"id": 1, "cmd": "enumerate_classes", "args": {"filter": "Auth"}}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Request ID. Echoed in the response for correlation. |
| `cmd` | string | Command name (see command table below) |
| `args` | object | Command-specific arguments. May be omitted for commands that take no arguments. |

### Response Format

Success:
```json
{"id": 1, "ok": true, "classes": ["AuthTokenManager", "AuthService", ...], "count": 12}
```

Error:
```json
{"id": 1, "ok": false, "error": "Class not found: NonExistentClass"}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | integer | Echoed request ID |
| `ok` | boolean | `true` on success, `false` on error |
| `error` | string | Error message (only when `ok` is false) |
| ... | varies | Command-specific response fields |

### Connection

```python
import socket, json

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/tmp/darkmach-bridge.sock")
sock.sendall((json.dumps({"id": 1, "cmd": "info"}) + "\n").encode())
sock.settimeout(30)
data = b""
while True:
    chunk = sock.recv(1 << 20)
    if not chunk or b"\n" in data:
        break
    data += chunk
response = json.loads(data.decode().strip())
sock.close()
```

The Python client in `src/darkmach/bridge.py` implements `send_command(cmd, args=None)` which wraps this pattern.

---

## Command Reference

60 commands total, organized by module.

### Quick Reference Table

| Module | Commands |
|--------|----------|
| **Core** | `info` |
| **Recon** | `enumerate_classes`, `get_methods`, `get_properties`, `get_ivars`, `read_property`, `call_method`, `heap_search`, `heap_dump`, `read_memory`, `memory_scan`, `env_dump`, `fs_scan`, `db_dump`, `db_query`, `db_queries`, `keychain_dump`, `userdefaults_dump`, `cookies_dump`, `entitlement_scan`, `shared_container_scan`, `sdk_map`, `sdk_keys` |
| **Network** | `net_tap`, `net_filter`, `crypto_tap`, `crypto_keys`, `auth_tap`, `auth_tokens` |
| **Trace** | `hook_method`, `unhook_method`, `trace`, `trace_class`, `trace_log`, `trace_verbose`, `untrace` |
| **UI** | `view_hierarchy`, `ui_tap`, `ui_type`, `ui_scroll`, `ui_back`, `ui_alert_dismiss` |
| **Analysis** | `webview_list`, `webview_eval`, `webview_content`, `webview_bridge_map`, `block_inspect`, `block_invoke`, `proto_decode`, `proto_schema` |
| **Forensics** | `mem_forensics`, `mem_snapshot`, `mem_diff`, `pin_analyze`, `pin_extract`, `timing_probe`, `timing_compare` |
| **Injection** | `inject_class`, `inject_method`, `replace_delegate` |
| **Events** | `event_tap` |

---

## Core Commands

### info

Get bridge metadata and app information.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "bridge": "darkmach-bridge",
  "version": "0.1.0",
  "appName": "MyApp",
  "appVersion": "3.2.1",
  "appBuild": "421",
  "bundleId": "com.example.myapp",
  "pid": 12345,
  "totalClasses": 8432,
  "activeHooks": 0,
  "commands": ["info", "enumerate_classes", ...]
}
```

**Interactive usage:**
```
darkmach> info
```

---

## Recon Commands

### enumerate_classes

List all ObjC classes loaded in the process.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `filter` | string (optional) | Case-sensitive substring filter on class names |

**Response:**
```json
{
  "ok": true,
  "classes": ["AuthTokenManager", "AuthService", "AuthViewController"],
  "total": 8432,
  "matched": 3
}
```

**Interactive usage:**
```
darkmach> enumerate_classes Auth
darkmach> enumerate_classes Payment
darkmach> enumerate_classes Crypto
```

---

### get_methods

Get all instance and class methods for a named class, including ObjC type encodings.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name |

**Response:**
```json
{
  "ok": true,
  "instance_methods": [
    {"name": "getToken", "types": "@@:"},
    {"name": "refreshToken:", "types": "v@:@"}
  ],
  "class_methods": [
    {"name": "sharedManager", "types": "@@:"}
  ],
  "instance_count": 8,
  "class_count": 1
}
```

**Interactive usage:**
```
darkmach> get_methods AuthTokenManager
darkmach> get_methods NSURLSession
```

---

### get_properties

Get declared properties for a class, including ObjC attribute strings.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name |

**Response:**
```json
{
  "ok": true,
  "properties": [
    {"name": "authToken", "attributes": "T@\"NSString\",C,N"},
    {"name": "expiresAt", "attributes": "T@\"NSDate\",C,N"},
    {"name": "isAuthenticated", "attributes": "TB,R,N"}
  ],
  "count": 3
}
```

**Interactive usage:**
```
darkmach> get_properties AuthTokenManager
```

---

### get_ivars

Get instance variables for a class, including types and memory offsets.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name |

**Response:**
```json
{
  "ok": true,
  "ivars": [
    {"name": "_authToken", "type": "@\"NSString\"", "offset": 8},
    {"name": "_userId", "type": "@\"NSString\"", "offset": 16},
    {"name": "_expiresAt", "type": "@\"NSDate\"", "offset": 24}
  ],
  "count": 3
}
```

**Interactive usage:**
```
darkmach> get_ivars AuthTokenManager
```

---

### read_property

Read a live property value from an object instance by memory address.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `address` | integer | Memory address of the object instance (from `heap_search` or `heap_dump`) |
| `property` | string | Property name (selector, no `get` prefix) |

**Response:**
```json
{
  "ok": true,
  "property": "authToken",
  "address": "0x600002a4f320",
  "value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "valueClass": "__NSCFString"
}
```

The bridge validates that the object is still alive before calling the getter. Returns an error if the object has been deallocated.

**Interactive usage:**
```
darkmach> read_property 0x600002a4f320 authToken
darkmach> read_property 0x600002a4f320 description
```

---

### call_method

Invoke a no-argument method on a live object instance and return the result.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `address` | integer | Memory address of the object instance |
| `method` | string | Method selector (must take no arguments) |

**Response:**
```json
{
  "ok": true,
  "method": "tokenString",
  "result": "eyJhbGciOiJSUzI1NiJ9...",
  "resultClass": "__NSCFString",
  "resultAddress": "0x0000600002a4f320"
}
```

Only no-argument methods are supported. For methods with arguments, use `trace` to intercept calls at runtime.

**Interactive usage:**
```
darkmach> call_method 0x600002a4f320 description
darkmach> call_method 0x600002a4f320 tokenString
```

---

### heap_search

Search for live instances of a class using singleton patterns and UIApplication graph traversal. Faster than `heap_dump` for well-known classes; use `heap_dump` for arbitrary class enumeration.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name to search for |

**Response:**
```json
{
  "ok": true,
  "instances": [
    {
      "address": "0x0000600002a4f320",
      "via": "sharedInstance",
      "description": "<AuthTokenManager: 0x600002a4f320>"
    }
  ],
  "found": 1
}
```

The `via` field names the singleton accessor used to find the instance (e.g., `sharedInstance`, `sharedManager`, `currentUser`, `UIApplication.delegate`).

**Interactive usage:**
```
darkmach> heap_search AuthTokenManager
darkmach> heap_search NSURLSession
```

---

### heap_dump

Walk all malloc zones to enumerate every live ObjC object on the heap. Two-phase algorithm: collect (address, size) pairs from the zone enumerator, then validate isa pointers against the registered class list after enumeration. Supports pagination via `offset`/`limit`.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string (optional) | Filter to instances of this class (includes subclasses) |
| `limit` | integer (optional) | Maximum instances to return. Default: 1000 |
| `offset` | integer (optional) | Skip first N matching instances (for pagination). Default: 0 |

**Response:**
```json
{
  "ok": true,
  "instances": [
    {"addr": "0x600002a4f320", "class": "AuthTokenManager", "size": 64},
    {"addr": "0x600003b12480", "class": "NSMutableString", "size": 48}
  ],
  "total_scanned": 58432,
  "total_matched": 2,
  "returned": 2,
  "time_ms": 234
}
```

**Interactive usage:**
```
darkmach> heap_dump AuthTokenManager
darkmach> heap_dump NSURLSession 50 0
```

---

### read_memory

Read raw bytes from a memory address. Verifies the address is readable via `vm_region_recurse_64` before reading.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `address` | integer | Memory address (decimal or `0x`-prefixed hex) |
| `size` | integer (optional) | Number of bytes to read. Default: 256. Max: 4096. |

**Response:**
```json
{
  "ok": true,
  "address": "0x0000600002a4f320",
  "size": 256,
  "hex": "cafebabe...",
  "ascii": "........"
}
```

**Interactive usage:**
```
darkmach> read_memory 0x600002a4f320
darkmach> read_memory 0x600002a4f320 128
```

---

### memory_scan

Scan all readable process memory regions for string patterns. Searches for JWT tokens, Bearer tokens, API keys, and other sensitive data patterns. Default scan covers a broad pattern set; specify `pattern` to search for a specific string.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `pattern` | string (optional) | Specific string to search for. If omitted, scans for a default set of sensitive patterns (JWT, Bearer, Basic, Stripe keys, AWS keys, etc.). |

**Response:**
```json
{
  "ok": true,
  "matches": [
    {
      "address": "0x00007f8a1234",
      "pattern": "Bearer ",
      "preview": "Bearer eyJhbGciOiJSUzI1Ni...",
      "region_info": {"base": "...", "size": 4096, "protection": "rw-"}
    }
  ],
  "match_count": 3,
  "regions_scanned": 1847
}
```

Cap: 200 matches maximum.

**Interactive usage:**
```
darkmach> memory_scan
darkmach> memory_scan sk_live_
```

---

### env_dump

Capture the complete process environment: environment variables, launch arguments, loaded dylib images with ASLR slides, and open file descriptors.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "env": {"PATH": "/usr/bin", "HOME": "/var/mobile", "SIMCTL_CHILD_DYLD_INSERT_LIBRARIES": "..."},
  "args": ["MyApp", "--some-flag"],
  "images": [
    {"name": "MyApp", "path": "/var/containers/.../MyApp.app/MyApp", "base": "0x100000000", "slide": "0x0"},
    {"name": "darkmach-bridge.dylib", "path": "...", "base": "0x1a0000000", "slide": "0x0"}
  ],
  "fds": [
    {"fd": 0, "path": "/dev/null", "type": "file"},
    {"fd": 5, "path": "/tmp/darkmach-bridge.sock", "type": "socket"}
  ],
  "pid": 12345
}
```

**Interactive usage:**
```
darkmach> env_dump
```

---

### fs_scan

Scan the app filesystem sandbox. Reads contents of interesting file types (`.json`, `.plist`, `.xml`, `.config`, `.key`, `.pem`, `.env`, `.yaml`, `.conf`) automatically if under 32KB.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `path` | string (optional) | Root path to scan. Defaults to the app home directory (`NSHomeDirectory()`). |
| `read` | string (optional) | `"true"` (default) to include file contents, `"false"` to list only. |

**Response:** Recursive directory tree with file names, sizes, and content previews for interesting file types. Cap: 500 files, 8 levels deep.

**Interactive usage:**
```
darkmach> fs_scan
darkmach> fs_scan /var/mobile/Containers/Data/Application/...
```

---

### db_dump

Find all SQLite databases in the app sandbox and dump schema and data. Recursively searches the home directory for `.db`, `.sqlite`, `.sqlite3`, and `.sql` files. Dumps up to 100 rows per table.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `table` | string (optional) | Filter to tables whose names contain this substring |

**Response:**
```json
{
  "ok": true,
  "home": "/var/mobile/Containers/Data/Application/.../",
  "databases": [
    {
      "path": "/var/.../Cache.db",
      "tables": [
        {
          "name": "sessions",
          "row_count": 3,
          "columns": [{"name": "id", "type": "INTEGER", "pk": true}, {"name": "token", "type": "TEXT"}],
          "rows": [{"id": 1, "token": "eyJ..."}]
        }
      ]
    }
  ]
}
```

**Interactive usage:**
```
darkmach> db_dump
darkmach> db_dump sessions
```

---

### db_query

Execute a raw SQL SELECT statement against a specific database file. Useful when `db_dump` is too broad or when you need custom query logic.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `path` | string | Absolute path to the SQLite database file |
| `sql` | string | SQL SELECT statement to execute |

**Response:**
```json
{
  "ok": true,
  "rows": [
    {"id": 1, "token": "eyJ...", "user_id": "u_12345"}
  ],
  "row_count": 1,
  "columns": ["id", "token", "user_id"]
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "db_query", "args": {"path": "/var/.../Cache.db", "sql": "SELECT * FROM sessions LIMIT 10"}}
```

---

### db_queries

Return recently intercepted SQL queries captured by the `darkmach-db.dylib` interceptor (if loaded). Queries are captured from the app's `sqlite3_exec` and `sqlite3_step` calls.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `limit` | integer (optional) | Maximum queries to return. Default: 50 |

**Response:**
```json
{
  "ok": true,
  "queries": [
    {"sql": "SELECT token FROM sessions WHERE user_id = ?", "timestamp": "2026-03-26T10:00:01.234"}
  ],
  "count": 1
}
```

Requires `darkmach-db.dylib` to be injected alongside the bridge.

**Interactive usage:**
```
darkmach> raw {"cmd": "db_queries", "args": {"limit": 20}}
```

---

### keychain_dump

Read all accessible keychain items across all five keychain classes: GenericPassword, InternetPassword, Certificate, Key, Identity. Attempts three access strategies in order: attributes + data, attributes only, and iCloud synchronizable items.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "items": [
    {
      "class": "GenericPassword",
      "data": "{acct = session; agrp = ...; data = s3cr3t-token; svce = com.example.myapp}"
    }
  ],
  "count": 3
}
```

**Interactive usage:**
```
darkmach> keychain_dump
```

---

### userdefaults_dump

Read all NSUserDefaults entries for the app. Returns keys, values, and value types.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "entries": [
    {"key": "session_token", "value": "eyJ...", "type": "__NSCFString"},
    {"key": "user_id", "value": "u_12345", "type": "__NSCFString"},
    {"key": "has_premium", "value": "1", "type": "__NSCFBoolean"}
  ],
  "count": 42
}
```

**Interactive usage:**
```
darkmach> userdefaults_dump
```

---

### cookies_dump

Read all HTTP cookies from the shared `NSHTTPCookieStorage`.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "cookies": [
    {
      "name": "auth",
      "value": "tok_xyz",
      "domain": ".example.com",
      "path": "/"
    }
  ],
  "count": 2
}
```

**Interactive usage:**
```
darkmach> cookies_dump
```

---

### entitlement_scan

Parse LC_CODE_SIGNATURE from all loaded Mach-O images to extract embedded entitlements. Annotates each entitlement with a risk level (high/medium/low/info) based on a built-in risk table covering 23 known sensitive entitlements.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "images": [
    {
      "name": "MyApp",
      "image_index": 0,
      "entitlements": {
        "com.apple.security.application-groups": ["group.com.example.myapp"],
        "keychain-access-groups": ["TEAM123.com.example.myapp"],
        "com.apple.developer.healthkit": true
      },
      "risks": [
        {"level": "high", "key": "keychain-access-groups", "description": "cross-app keychain access"},
        {"level": "high", "key": "com.apple.developer.healthkit", "description": "HealthKit data access"}
      ],
      "entitlement_count": 5,
      "high_risk_count": 2
    }
  ],
  "total_high_risk": 2
}
```

**Interactive usage:**
```
darkmach> entitlement_scan
```

---

### shared_container_scan

Scan the app group shared containers declared in `com.apple.security.application-groups` entitlements. Lists files accessible to the app from shared group containers (group.* identifiers).

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "containers": [
    {
      "group": "group.com.example.myapp",
      "path": "/private/var/mobile/Containers/Shared/AppGroup/.../",
      "files": [
        {"name": "shared_prefs.plist", "size": 1234, "content": "<?xml ..."}
      ]
    }
  ],
  "count": 1
}
```

**Interactive usage:**
```
darkmach> shared_container_scan
```

---

### sdk_map

Identify third-party SDKs loaded in the process by fingerprinting class name prefixes against a built-in SDK signature database. Returns SDK names, categories, and class counts.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "sdks": [
    {"name": "Firebase", "category": "analytics", "class_count": 247, "prefix": "FIR"},
    {"name": "Stripe", "category": "payments", "class_count": 89, "prefix": "STP"},
    {"name": "RevenueCat", "category": "subscriptions", "class_count": 43, "prefix": "RCPurchases"}
  ],
  "total_identified": 3
}
```

**Interactive usage:**
```
darkmach> sdk_map
```

---

### sdk_keys

Extract API keys, tokens, and configuration values associated with identified SDKs. Searches NSUserDefaults, the Info.plist, and known class properties for SDK-specific key patterns.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "keys": [
    {"sdk": "Firebase", "key_name": "GoogleAppID", "value": "1:123456789:ios:abc123"},
    {"sdk": "Stripe", "key_name": "publishableKey", "value": "pk_live_..."}
  ],
  "count": 2
}
```

**Interactive usage:**
```
darkmach> sdk_keys
```

---

## Network Commands

Network commands read ring buffers of 500 entries each. The bridge installs no HTTP hooks of its own: `darkmach-net.dylib` owns the NSURLSession swizzles, installs them from its load-time constructor, and pushes into the bridge's ring through the exported `darkmach_net_record_request` / `darkmach_net_record_response`. The ring fills from process start, so `net_tap`, `net_filter`, `auth_tap`, and `auth_tokens` return traffic that predates the first command. `crypto_tap` works the same way via `darkmach-crypto.dylib`.

This makes injection the prerequisite, not a command. Every response carries `capturing` — false means `darkmach-net.dylib` was not injected, and a zero count means *unobserved*, not *absent*. `auth_tap` and `auth_tokens` still lazily install one hook of their own on first call: the `LAContext evaluatePolicy:localizedReason:reply:` biometric swizzle, reported separately as `biometric_hooked`.

### net_tap

Return HTTP request/response pairs captured by `darkmach-net.dylib`, which hooks `dataTaskWithRequest:completionHandler:` and `dataTaskWithURL:completionHandler:`. Each entry carries source, method, URL, request headers, request body preview, status code, response headers, response body preview, error, and duration.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `limit` | integer (optional) | Maximum requests to return. Default: 50 |

**Response:**
```json
{
  "ok": true,
  "data": {
    "capturing": true,
    "source": "darkmach-net.dylib",
    "requests": [
      {
        "id": 1,
        "src": "dataTask",
        "method": "POST",
        "url": "https://api.example.com/v2/auth/token",
        "req_headers": {"Content-Type": "application/json", "Authorization": "..."},
        "req_body_preview": "{\"username\":\"user@example.com\",\"password\":\"...\"",
        "status": 200,
        "resp_headers": {"Content-Type": "application/json"},
        "resp_body_preview": "{\"access_token\":\"eyJ...\",\"expires_in\":3600}",
        "error": null,
        "duration_ms": 342,
        "timestamp": "2026-03-26T10:00:01.234"
      }
    ],
    "total_captured": 47,
    "returned": 47
  }
}
```

`src` is `dataTask` or `dataTaskURL`, naming which NSURLSession entry point produced the entry. `error` is the transport error string, or `null` on success.

When `darkmach-net.dylib` is not loaded, a top-level `error` sits alongside `data` and `capturing` is false:

```json
{
  "ok": true,
  "error": "HTTP traffic is not being captured — darkmach-net.dylib, which owns the NSURLSession hooks, is not loaded; a zero count here means unobserved, not absent",
  "data": {"capturing": false, "source": "darkmach-net.dylib", "requests": [], "total_captured": 0, "returned": 0}
}
```

**Interactive usage:**
```
darkmach> net_tap
darkmach> net_tap 100
```

#### Fidelity limits

A ring entry is a fixed 4096-byte JSON string. The per-field budget sums to 3962 bytes, so an entry can never truncate mid-string and corrupt the response. Fields are clipped on the way in:

| Field | Cap | Behavior at the cap |
|-------|-----|---------------------|
| `url` | 512 bytes escaped | Clipped |
| `req_headers` / `resp_headers` | 800 bytes each | Whole set replaced by `{"_truncated_bytes":N}` |
| `req_body_preview` | 384 bytes raw → 600 escaped | Clipped |
| `resp_body_preview` | 384 bytes raw → 800 escaped | Clipped |
| `error` | 128 bytes | Clipped |

Header sets are replaced rather than clipped because a half-written JSON object would corrupt the surrounding response. Bodies are sampled at 384 raw bytes *before* escaping, so a body full of quotes or newlines yields a visibly shorter preview than one that is plain text.

Body previews scan the first 256 bytes for control characters; anything that looks non-text renders as `<binary N bytes>` rather than mojibake.

These caps apply only to the bridge ring. Full request and response records are always written to `output/<app>/dynamic/darkmach-net.jsonl` — go there when a preview is truncated.

---

### net_filter

Filter the captured HTTP request ring buffer by host, path, method, or status code. All filters are additive (AND logic). Reads the same ring as `net_tap` and returns the same entry shape and `capturing` / `source` fields.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `host` | string (optional) | Substring match on URL |
| `path` | string (optional) | Substring match on URL path |
| `method` | string (optional) | HTTP method to filter (case-insensitive: GET, POST, etc.) |
| `status` | integer (optional) | HTTP status code to filter (exact match) |
| `limit` | integer (optional) | Maximum results to return. Default: 50 |

**Response:** Same format as `net_tap`.

**Interactive usage:**
```
darkmach> raw {"cmd": "net_filter", "args": {"method": "POST"}}
darkmach> raw {"cmd": "net_filter", "args": {"host": "api.stripe.com", "status": 200}}
```

---

### crypto_tap

Return CommonCrypto operations captured from CCCrypt and CCHmac calls. Each entry records the algorithm, encryption direction, key (hex), IV (hex), input length, and output preview.

**Dependency:** `darkmach-crypto.dylib` must be injected — it owns the CCCrypt/CCHmac interposes and fills this ring from process start. The bridge installs nothing itself; `capturing` false means a zero count is *unobserved*, not *absent*. The response also carries `digests`, a per-algorithm call and byte tally.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `limit` | integer (optional) | Maximum operations to return. Default: 50 |

**Response:**
```json
{
  "ok": true,
  "data": {
    "capturing": true,
    "source": "darkmach-crypto.dylib",
    "digests": [
      {"algorithm": "SHA256", "calls": 41, "bytes": 18432}
    ],
    "operations": [
      {
        "op": "CCCrypt",
        "algorithm": "AES-256-CBC",
        "encrypt": true,
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "iv_hex": "000102030405060708090a0b0c0d0e0f",
        "input_len": 128,
        "output_preview": "3ad77bb40d7a3660a89ecaf32466ef97...",
        "timestamp": "2026-03-26T10:00:01.234"
      }
    ],
    "total_captured": 12,
    "returned": 12
  }
}
```

**Interactive usage:**
```
darkmach> crypto_tap
```

---

### crypto_keys

Return the unique cryptographic keys observed across all captured CCCrypt and CCHmac operations. Keys are deduplicated — the same key used multiple times appears once with a use count.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "data": {
    "keys": [
      {
        "algorithm": "AES-256-CBC",
        "key_hex": "2b7e151628aed2a6abf7158809cf4f3c",
        "key_len_bits": 256,
        "first_seen": "2026-03-26T10:00:01.234",
        "last_seen": "2026-03-26T10:00:05.678",
        "use_count": 14
      }
    ],
    "total_unique": 1
  }
}
```

**Interactive usage:**
```
darkmach> crypto_keys
```

---

### auth_tap

Return captured authentication events. Scans the HTTP ring on each call to extract OAuth flows, JWT tokens from responses, and Bearer tokens from Authorization headers. On first call it installs one hook of its own — `LAContext evaluatePolicy:localizedReason:reply:` — to capture biometric authentication.

**Dependency:** `darkmach-net.dylib` must be injected. The HTTP events are derived from the ring that interceptor fills; `auth_tap` cannot install those hooks itself. `capturing` reports whether it is loaded, `biometric_hooked` whether the LAContext swizzle took.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `limit` | integer (optional) | Maximum events to return. Default: 50 |

**Response:**
```json
{
  "ok": true,
  "data": {
    "capturing": true,
    "http_source": "darkmach-net.dylib",
    "biometric_hooked": true,
    "events": [
      {
        "type": "oauth_token_response",
        "url": "https://auth.example.com/v2/token",
        "provider": "oauth2",
        "token_preview": "eyJhbGciOiJSUzI1NiI...",
        "token_type": "access_token",
        "claims": {"sub": "u_12345", "exp": 1740000000, "iss": "https://auth.example.com"},
        "timestamp": "2026-03-26T10:00:01.234"
      },
      {
        "type": "biometric_auth",
        "url": "",
        "provider": "LocalAuthentication",
        "token_preview": "",
        "token_type": "",
        "claims": {"policy": "deviceOwnerAuthenticationWithBiometrics", "result": "success", "reason": "Confirm your identity"},
        "timestamp": "2026-03-26T10:00:02.345"
      }
    ],
    "total_captured": 3,
    "returned": 3
  }
}
```

Detected OAuth providers: `firebase`, `apple`, `facebook`, `github`, `oauth2`, `oidc`, `custom`.

**Interactive usage:**
```
darkmach> auth_tap
```

---

### auth_tokens

Return the deduplicated set of unique authentication tokens observed so far. For JWT tokens, includes the decoded claims payload. Scans the HTTP ring before returning.

**Dependency:** `darkmach-net.dylib` must be injected — same as `auth_tap`.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "data": {
    "capturing": true,
    "http_source": "darkmach-net.dylib",
    "biometric_hooked": true,
    "tokens": [
      {
        "type": "access_token",
        "value_preview": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        "full_value_len": 1247,
        "claims": {"sub": "u_12345", "exp": 1740000000, "iss": "https://auth.example.com", "email": "user@example.com"},
        "source": "oauth_token_response",
        "first_seen": "2026-03-26T10:00:01.234",
        "last_seen": "2026-03-26T10:00:01.234"
      }
    ],
    "total_unique": 1
  }
}
```

**Interactive usage:**
```
darkmach> auth_tokens
```

---

## Trace Commands

Two trace systems are available. The trampoline-based system (`trace`, `trace_class`, `trace_log`, `trace_verbose`, `untrace`) is preferred — it captures argument values with full type information. The legacy system (`hook_method`, `unhook_method`) is simpler but discards arguments.

### hook_method

Install a simple swizzle hook on a method (legacy system). All subsequent calls to the method are logged to `darkmach-bridge.jsonl` with class name, method, and instance address. Arguments are not captured.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name |
| `method` | string | Method selector |

**Response:**
```json
{
  "ok": true,
  "hooked": true,
  "class": "AuthTokenManager",
  "method": "refreshToken:",
  "hookIndex": 0
}
```

**Interactive usage:**
```
darkmach> hook_method AuthTokenManager refreshToken:
```

---

### unhook_method

Remove a hook installed by `hook_method` and restore the original implementation.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name |
| `method` | string | Method selector |

**Response:**
```json
{
  "ok": true,
  "unhooked": true,
  "class": "AuthTokenManager",
  "method": "refreshToken:"
}
```

**Interactive usage:**
```
darkmach> unhook_method AuthTokenManager refreshToken:
```

---

### trace

Install a trampoline-based trace hook on a single method. Uses a 26-instruction ARM64 trampoline stub that saves all argument registers, calls `darkmach_on_method_enter()`, restores registers, and tail-calls the original IMP. Each call is logged to the trace ring buffer with arguments decoded from the ObjC type encoding. Up to 256 simultaneous trace hooks.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name |
| `method` | string | Method selector (instance or class method; instance tried first) |

**Response:**
```json
{
  "ok": true,
  "hooked": true,
  "slot": 0,
  "class": "AuthTokenManager",
  "method": "refreshToken:",
  "type_encoding": "v@:@",
  "arg_types": ["id (self)", "SEL (_cmd)", "id"]
}
```

**Interactive usage:**
```
darkmach> trace AuthTokenManager refreshToken:
darkmach> trace NSURLSession dataTaskWithRequest:completionHandler:
```

---

### trace_class

Install trace hooks on all instance methods of a class at once. Skips unsafe methods (dealloc, retain, release, etc.) and methods beginning with `_`.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name |

**Response:**
```json
{
  "ok": true,
  "class": "AuthTokenManager",
  "hooked": 6,
  "skipped": 2,
  "methods": ["getToken", "refreshToken:", "setToken:", "clearToken", "isTokenValid", "tokenString"],
  "skipped_reasons": ["dealloc (unsafe)", "init (unsafe)"]
}
```

**Interactive usage:**
```
darkmach> trace_class AuthTokenManager
darkmach> trace_class NSURLSession
```

---

### trace_log

Retrieve recent entries from the trace ring buffer. Supports filtering by class or method name.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `limit` | integer (optional) | Maximum entries to return. Default: 50. Max: 500 (ring buffer capacity). |
| `class` | string (optional) | Filter to entries from this class |
| `method` | string (optional) | Filter to entries matching this method name |

**Response:**
```json
{
  "ok": true,
  "entries": [
    {
      "slot": 0,
      "class": "AuthTokenManager",
      "method": "refreshToken:",
      "timestamp": "2026-03-26T10:00:01.234",
      "thread_id": "0x70000a1b2c3d",
      "args": {
        "arg2": {"type": "id", "value": "<NSString: 0x600001234567>"}
      },
      "call_count": 3
    }
  ],
  "returned": 1,
  "total_captured": 47
}
```

**Interactive usage:**
```
darkmach> trace_log
darkmach> trace_log 100
```

---

### untrace

Remove a trampoline trace hook by slot number (from the `trace` response) or by class+method.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `slot` | integer (optional) | Slot index from the `trace` response |
| `class` | string (optional) | Class name (used with `method` if `slot` not provided) |
| `method` | string (optional) | Method selector |

**Response:**
```json
{
  "ok": true,
  "untraced": true,
  "slot": 0,
  "class": "AuthTokenManager",
  "method": "refreshToken:"
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "untrace", "args": {"slot": 0}}
darkmach> raw {"cmd": "untrace", "args": {"class": "AuthTokenManager", "method": "refreshToken:"}}
```

---

### trace_verbose

Toggle verbose mode for traced hooks on a class. When verbose is enabled, traced methods use `-description` on ObjC object arguments (expensive, risks crash on partially-constructed objects). When disabled (default), arguments are formatted as safe `<ClassName: 0xaddr>`.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name to toggle verbose mode on |
| `selector` | string (optional) | Specific method. If omitted, affects all hooks for the class. |
| `verbose` | integer | `1` to enable verbose descriptions, `0` for safe format (default) |

**Response:**
```json
{
  "ok": true,
  "class": "NSURLSession",
  "verbose": 1,
  "updated": 49
}
```

| Field | Description |
|-------|-------------|
| `class` | The class whose hooks were updated |
| `verbose` | The verbose setting applied (0 or 1) |
| `updated` | Number of hook slots that were updated |

**Interactive usage:**
```
darkmach> raw {"cmd": "trace_verbose", "args": {"class": "NSURLSession", "verbose": 1}}
darkmach> raw {"cmd": "trace_verbose", "args": {"class": "NSURLSession", "verbose": 0}}
```

**Safety note:** Verbose mode can crash on partially-constructed objects during `object_cxxConstructFromClass`. Use sparingly and only on classes where you need full argument detail. The default safe format is recommended for most use cases.

---

## UI Commands

All UI commands dispatch to the main thread via `dispatch_async` + `dispatch_semaphore`. Timeout: 3 seconds.

### view_hierarchy

Dump the complete UIKit view hierarchy from all windows. Each view entry includes class, depth, address, frame, hidden state, accessibility label, and text content (for labels, text fields, and buttons).

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "views": [
    {
      "class": "UIWindow",
      "depth": 0,
      "address": "0x7f8a1234",
      "frame": {"x": 0, "y": 0, "w": 390, "h": 844},
      "hidden": false
    },
    {
      "class": "UILabel",
      "depth": 3,
      "address": "0x7f8b5678",
      "frame": {"x": 20, "y": 100, "w": 200, "h": 44},
      "text": "Welcome, User",
      "accessibilityLabel": "greeting"
    }
  ],
  "windowCount": 1,
  "viewCount": 47
}
```

**Interactive usage:**
```
darkmach> view_hierarchy
```

---

### ui_tap

Synthesize a tap on a UI element. Three targeting modes: screen coordinates, accessibility label, or class name + optional text. For UIControl targets, fires `sendActionsForControlEvents:` (UIControlEventTouchUpInside). For other views, fires attached UITapGestureRecognizers.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `x` | float | Screen X coordinate (requires `y`) |
| `y` | float | Screen Y coordinate (requires `x`) |
| `label` | string | Accessibility label substring to match (alternative to x/y) |
| `class` | string | Class name to match (alternative to x/y) |
| `text` | string | Text content to match (used with `class`) |
| `index` | integer (optional) | Which match to tap if multiple views match. Default: 0 (first). |

Exactly one of `x`+`y`, `label`, or `class` is required.

**Response:**
```json
{
  "ok": true,
  "tapped": true,
  "target_class": "UIButton",
  "target_label": "Submit",
  "target_frame": {"x": 20, "y": 580, "w": 350, "h": 44}
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "ui_tap", "args": {"label": "Submit"}}
darkmach> raw {"cmd": "ui_tap", "args": {"x": 195, "y": 600}}
darkmach> raw {"cmd": "ui_tap", "args": {"class": "UIButton", "text": "Login"}}
```

---

### ui_type

Type text into a UI text field or text view. Finds the first UITextField or UITextView in the hierarchy (or uses a specific address), optionally clearing existing content first.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `text` | string | Text to type |
| `address` | integer (optional) | Address of a specific UITextField or UITextView. If omitted, uses the current first responder or finds the first text field in the hierarchy. |
| `clear` | boolean (optional) | Clear existing text before typing. Default: false. |

**Response:**
```json
{
  "ok": true,
  "typed": true,
  "target_class": "UITextField",
  "target_address": "0x7f8b1234"
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "ui_type", "args": {"text": "user@example.com"}}
darkmach> raw {"cmd": "ui_type", "args": {"text": "password123", "clear": true}}
```

---

### ui_scroll

Scroll a UIScrollView by a delta offset.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `dx` | float | Horizontal scroll delta in points |
| `dy` | float | Vertical scroll delta in points |
| `address` | integer (optional) | Address of a specific UIScrollView. If omitted, finds the first UIScrollView in the hierarchy. |

**Response:**
```json
{
  "ok": true,
  "scrolled": true,
  "target_address": "0x7f8b5678",
  "new_offset": {"x": 0, "y": 300}
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "ui_scroll", "args": {"dy": 300}}
darkmach> raw {"cmd": "ui_scroll", "args": {"dy": -100, "dx": 0}}
```

---

### ui_back

Navigate back in the current UINavigationController. Equivalent to pressing the Back button.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "navigated_back": true,
  "previous_vc": "HomeViewController"
}
```

**Interactive usage:**
```
darkmach> ui_back
```

---

### ui_alert_dismiss

Dismiss the frontmost UIAlertController by tapping one of its actions.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `button_index` | integer (optional) | Which action to tap (0-based). Default: 0 (first button, typically "OK" or "Cancel"). |

**Response:**
```json
{
  "ok": true,
  "dismissed": true,
  "action_title": "OK"
}
```

**Interactive usage:**
```
darkmach> ui_alert_dismiss
darkmach> raw {"cmd": "ui_alert_dismiss", "args": {"button_index": 1}}
```

---

## Analysis Commands

### webview_list

Enumerate all WKWebView instances in the process by walking the malloc heap. Returns URL, title, JavaScript enabled state, user script count, and message handler count for each.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "webviews": [
    {
      "address": "0x7f8c1234",
      "class": "WKWebView",
      "url": "https://app.example.com/dashboard",
      "title": "Dashboard",
      "js_enabled": true,
      "user_scripts": 2,
      "handler_count": 3
    }
  ],
  "count": 1
}
```

**Interactive usage:**
```
darkmach> webview_list
```

---

### webview_eval

Evaluate JavaScript in a specific WKWebView instance. Dispatches to the main thread. Timeout: 5 seconds.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `address` | string | Hex address of the WKWebView (from `webview_list`) |
| `js` | string | JavaScript expression to evaluate |

**Response:**
```json
{
  "ok": true,
  "address": "0x7f8c1234",
  "result": "eyJhbGciOiJSUzI1NiJ9..."
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "webview_eval", "args": {"address": "0x7f8c1234", "js": "localStorage.getItem('token')"}}
darkmach> raw {"cmd": "webview_eval", "args": {"address": "0x7f8c1234", "js": "document.cookie"}}
```

---

### webview_content

Extract the full HTML source of a WKWebView's loaded page by evaluating `document.documentElement.outerHTML`. Dispatches to the main thread. Timeout: 5 seconds.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `address` | string | Hex address of the WKWebView (from `webview_list`) |

**Response:**
```json
{
  "ok": true,
  "address": "0x7f8c1234",
  "url": "https://app.example.com/dashboard",
  "content": "<!DOCTYPE html><html>...</html>",
  "content_length": 24871
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "webview_content", "args": {"address": "0x7f8c1234"}}
```

---

### webview_bridge_map

Map all WKScriptMessageHandlers registered across all WKWebViews. These are the named channels that JavaScript in the WebView uses to call native code — a key attack surface for hybrid apps.

**Arguments:** none

**Response:**
```json
{
  "ok": true,
  "handlers": [
    {
      "webview_address": "0x7f8c1234",
      "webview_url": "https://app.example.com",
      "handler_name": "nativeBridge",
      "handler_class": "AppBridgeHandler"
    },
    {
      "webview_address": "0x7f8c1234",
      "webview_url": "https://app.example.com",
      "handler_name": "analyticsHandler",
      "handler_class": "AnalyticsManager"
    }
  ],
  "count": 2
}
```

**Interactive usage:**
```
darkmach> webview_bridge_map
```

---

### block_inspect

Inspect an ObjC block at a given address. Reads the block descriptor fields to extract the block type (stack/heap/global), signature, and captured variables.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `address` | integer | Memory address of the block |

**Response:**
```json
{
  "ok": true,
  "address": "0x7f8c5678",
  "block_type": "heap",
  "signature": "v8@?0",
  "has_copy_dispose": true,
  "has_signature": true,
  "invoke_ptr": "0x100a1b2c3",
  "descriptor_size": 40
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "block_inspect", "args": {"address": 140234567890}}
```

---

### block_invoke

Invoke a block at a given address with no arguments. Only safe for blocks with signature `void(^)(void)`. Use with caution.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `address` | integer | Memory address of the block |

**Response:**
```json
{
  "ok": true,
  "address": "0x7f8c5678",
  "invoked": true
}
```

---

### proto_decode

Decode a protobuf-encoded binary blob at a given address or from a hex string. Uses field-level heuristic decoding without a schema — identifies field tags, wire types, and attempts to decode values as integers, strings, or nested messages.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `address` | integer (optional) | Memory address of the protobuf data |
| `hex` | string (optional) | Hex-encoded protobuf bytes |
| `size` | integer | Length in bytes (required with `address`) |

**Response:**
```json
{
  "ok": true,
  "fields": [
    {"field": 1, "wire_type": "varint", "value": 12345},
    {"field": 2, "wire_type": "length_delimited", "value": "user@example.com"},
    {"field": 3, "wire_type": "length_delimited", "value": "<nested message, 24 bytes>"}
  ],
  "decoded_count": 3
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "proto_decode", "args": {"hex": "0a0d6578616d706c652e636f6d10c2"}}
```

---

### proto_schema

Attempt to infer a protobuf schema from a decoded message. Inspects multiple instances of the same message type (if provided) to build field type statistics.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `hex` | string | Hex-encoded protobuf bytes to analyze |

**Response:**
```json
{
  "ok": true,
  "schema": [
    {"field": 1, "inferred_type": "string", "wire_type": "length_delimited"},
    {"field": 2, "inferred_type": "int64", "wire_type": "varint"}
  ]
}
```

---

## Forensics Commands

### mem_forensics

Scan all malloc zone regions (including freed blocks) for sensitive string patterns. Unlike `memory_scan` which walks VM regions, this walks the allocator's region list — recovering data from freed-but-not-zeroed blocks.

Default patterns: `eyJ` (JWT), `Bearer `, `Basic `, `password`, `token`, `secret`, `https://`, `apikey`, `-----BEGIN` (PEM). Timeout: 5 seconds.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `patterns` | string (optional) | Comma-separated list of strings to scan for. If omitted, uses default sensitive-data patterns. |
| `limit` | integer (optional) | Maximum findings to return. Default: 100. Max: 500. |

**Response:**
```json
{
  "ok": true,
  "data": {
    "findings": [
      {
        "address": "0x00007f8a1234",
        "zone": "DefaultMallocZone",
        "block_size": 4096,
        "pattern_matched": "Bearer ",
        "preview": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        "context": "heap_region"
      }
    ],
    "zones_scanned": 3,
    "blocks_scanned": 18432,
    "scan_time_ms": 1234,
    "total_findings": 7
  }
}
```

**Interactive usage:**
```
darkmach> mem_forensics
darkmach> raw {"cmd": "mem_forensics", "args": {"patterns": "sk_live_,pk_live_,AKIA"}}
```

---

### mem_snapshot

Capture a snapshot of the current heap state: all live ObjC objects classified by class, with counts and byte totals. Returns top 20 classes by byte usage. Snapshots are retained for later comparison with `mem_diff`.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `label` | string (optional) | Human-readable label for the snapshot (e.g., "before_login") |

**Response:**
```json
{
  "ok": true,
  "data": {
    "snapshot_id": "snap_001",
    "label": "before_login",
    "total_objects": 58432,
    "total_bytes": 12582912,
    "timestamp": "2026-03-26T10:00:01.234",
    "top_classes": [
      {"class": "NSMutableData", "count": 1234, "bytes": 4194304},
      {"class": "__NSCFString", "count": 8932, "bytes": 2097152}
    ]
  }
}
```

Up to 10 snapshots retained. Oldest is evicted when the limit is reached.

**Interactive usage:**
```
darkmach> raw {"cmd": "mem_snapshot", "args": {"label": "before_login"}}
```

---

### mem_diff

Compare two heap snapshots to identify added, removed, or changed classes. Useful for detecting memory leaks or identifying objects created during a specific app action.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `a` | string | First snapshot ID (e.g., `"snap_001"`) |
| `b` | string | Second snapshot ID (e.g., `"snap_002"`) |

**Response:**
```json
{
  "ok": true,
  "data": {
    "added": [
      {"class": "AuthTokenManager", "count_delta": 1, "bytes_delta": 128}
    ],
    "removed": [],
    "changed": [
      {"class": "__NSCFString", "count_delta": 47, "bytes_delta": 9408, "count_a": 8932, "count_b": 8979}
    ]
  }
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "mem_diff", "args": {"a": "snap_001", "b": "snap_002"}}
```

---

### pin_analyze

Analyze SSL/TLS certificate pinning. Returns certificate chains, public key hashes, trust results, and bypass detection from trust evaluations captured by `darkmach-ssl.dylib`, which owns the `SecTrust` interposes. Also scans for TrustKit configuration and reads ATS (App Transport Security) settings from Info.plist.

**Dependency:** `darkmach-ssl.dylib` must be injected. As with the network commands, `capturing` reports whether it is loaded, and a zero count means *unobserved*, not *unpinned*. Interact with the app to trigger connections, then call again for new evaluations.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `limit` | integer (optional) | Maximum trust evaluations to return. Default: 50 |

**Response:**
```json
{
  "ok": true,
  "data": {
    "evaluations": [
      {
        "host": "api.example.com",
        "port": 0,
        "trusted": true,
        "bypassed": false,
        "timestamp": "2026-03-26T10:00:01.234",
        "policy": "1.2.840.113635.100.1.3",
        "cert_count": 3,
        "certs": [
          {"subject": "api.example.com", "der_size": 1842, "pubkey_sha256": "abc123..."}
        ]
      }
    ],
    "total_captured": 5,
    "returned": 5,
    "trustkit": {"detected": true, "validator": "...", "plist_config": "..."},
    "ats": {
      "configured": true,
      "allows_arbitrary_loads": false,
      "exception_domains": [
        {"domain": "localhost", "allows_insecure_http": true, "includes_subdomains": false}
      ]
    },
    "pinned_hosts": ["api.example.com", "auth.example.com"]
  }
}
```

**Interactive usage:**
```
darkmach> pin_analyze
```

---

### pin_extract

Return base64-encoded DER certificate data from captured trust evaluations. Used to extract the actual certificate bytes for analysis or to generate pinning hashes.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `host` | string (optional) | Filter to certificates from this host (substring match) |
| `limit` | integer (optional) | Maximum certificates to return. Default: 10 |

**Response:**
```json
{
  "ok": true,
  "data": {
    "certificates": [
      {
        "host": "api.example.com",
        "subject": "api.example.com",
        "der_base64": "MIIFkzCCBHugAwIBAgIRAI...",
        "pubkey_sha256": "abc123...",
        "der_size": 1842,
        "trusted": true
      }
    ],
    "returned": 1
  }
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "pin_extract", "args": {"host": "api.example.com"}}
```

---

### timing_probe

Measure execution time of a method call using `mach_absolute_time`. Calls the method N times and reports min, max, mean, and standard deviation in nanoseconds. Useful for timing side-channel analysis.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Class name |
| `method` | string | Method selector (no-argument methods only) |
| `address` | integer | Instance address to call the method on |
| `count` | integer (optional) | Number of iterations. Default: 100 |

**Response:**
```json
{
  "ok": true,
  "class": "CryptoManager",
  "method": "hashPassword",
  "iterations": 100,
  "min_ns": 123456,
  "max_ns": 234567,
  "mean_ns": 156789,
  "stddev_ns": 12345
}
```

---

### timing_compare

Compare execution times of two method calls side-by-side. Returns the same statistics as `timing_probe` for both methods plus a ratio.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class_a` | string | Class name for first method |
| `method_a` | string | Method selector for first method |
| `address_a` | integer | Instance address for first method |
| `class_b` | string | Class name for second method |
| `method_b` | string | Method selector for second method |
| `address_b` | integer | Instance address for second method |
| `count` | integer (optional) | Iterations per method. Default: 100 |

**Response:**
```json
{
  "ok": true,
  "a": {"class": "CryptoManager", "method": "hashWeak", "mean_ns": 1234},
  "b": {"class": "CryptoManager", "method": "hashStrong", "mean_ns": 123400},
  "ratio_b_over_a": 100.0
}
```

---

## Injection Commands

### inject_class

Create a new ObjC class at runtime using `objc_allocateClassPair` + `objc_registerClassPair`. The class is registered with the runtime and becomes immediately visible to `enumerate_classes`. Up to 64 injected classes.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `name` | string | Name for the new class (must not already exist) |
| `superclass` | string (optional) | Superclass name. Default: `"NSObject"` |
| `protocols` | string (optional) | Comma-separated protocol names to conform to |

**Response:**
```json
{
  "ok": true,
  "protocols": ["NSCopying"],
  "name": "DarkmachProbe",
  "superclass": "NSObject",
  "class_address": "0x7f8c1234",
  "protocol_count": 1,
  "injected_total": 1
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "inject_class", "args": {"name": "DarkmachProbe", "superclass": "NSObject"}}
```

---

### inject_method

Add a method to an existing class using a pre-built implementation from the catalog. If the method already exists, replaces its implementation and stores the original for `forward_to_original` chaining.

Available implementations:

| Name | Behavior |
|------|----------|
| `log_all_args` | Logs class, method, and address to stderr; returns nil |
| `return_yes` | Always returns `YES` (for BOOL methods) |
| `return_no` | Always returns `NO` |
| `return_nil` | Always returns `nil` |
| `forward_to_original` | Chains to the original implementation stored by a previous `inject_method` call |

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Target class name |
| `selector` | string | Method selector to add or replace |
| `implementation` | string | Catalog implementation name (see table above) |
| `types` | string (optional) | ObjC type encoding. Uses catalog default if omitted. |

**Response:**
```json
{
  "ok": true,
  "class": "AuthTokenManager",
  "selector": "isTokenValid",
  "implementation": "return_yes",
  "replaced_existing": true,
  "original_saved": true
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "inject_method", "args": {"class": "AuthTokenManager", "selector": "isTokenValid", "implementation": "return_yes"}}
```

---

### replace_delegate

Replace the `UIApplicationDelegate` with a new class that conforms to the same protocol. The replacement class is injected at runtime and forwards all delegate messages to the original.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `class` | string | Name of the replacement delegate class (must be injected first via `inject_class`) |

**Response:**
```json
{
  "ok": true,
  "original_delegate_class": "AppDelegate",
  "replacement_class": "DarkmachDelegate",
  "replaced": true
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "inject_class", "args": {"name": "DarkmachDelegate", "protocols": "UIApplicationDelegate"}}
darkmach> raw {"cmd": "inject_method", "args": {"class": "DarkmachDelegate", "selector": "applicationDidBecomeActive:", "implementation": "log_all_args"}}
darkmach> raw {"cmd": "replace_delegate", "args": {"class": "DarkmachDelegate"}}
```

---

## Events Commands

### event_tap

Monitor `NSNotificationCenter` posts. Three actions: `enable` to install a catch-all observer, `disable` to remove it, and `recent` (default) to return captured events.

**Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `action` | string (optional) | `"enable"`, `"disable"`, or `"recent"`. Default: `"recent"` |
| `name_filter` | string (optional) | Capture-time filter: only record notifications whose name contains this substring. Only used with `enable`. |
| `limit` | integer (optional) | Maximum events to return (with `"recent"`). Default: 50 |

**Response (enable):**
```json
{"ok": true, "enabled": true, "name_filter": "Auth"}
```

**Response (recent):**
```json
{
  "ok": true,
  "events": [
    {
      "name": "NSNotificationName(com.example.userDidLogin)",
      "object_class": "AuthTokenManager",
      "user_info_keys": ["userId", "sessionToken"],
      "timestamp": "2026-03-26T10:00:01.234"
    }
  ],
  "returned": 5,
  "total_captured": 47
}
```

**Interactive usage:**
```
darkmach> raw {"cmd": "event_tap", "args": {"action": "enable"}}
darkmach> raw {"cmd": "event_tap", "args": {"action": "enable", "name_filter": "Auth"}}
darkmach> event_tap
darkmach> raw {"cmd": "event_tap", "args": {"action": "disable"}}
```

---

## Using the Bridge Interactively

`darkmach bridge` opens the interactive REPL:

```bash
darkmach bridge
```

```
darkmach-bridge client — type 'help' for commands, 'quit' to exit
Connecting to /tmp/darkmach-bridge.sock...
Bridge: darkmach-bridge v0.1.0
App: OddsJam 3.2.1 (build 421)
Bundle: com.oddsjam.app
PID: 12345
Classes: 8432
Active hooks: 0

darkmach>
```

Type `help` for the full command list. Commands match the protocol command names.

### Example Session

```
darkmach> enumerate_classes Auth
Found 4 classes (8432 total):
  AuthTokenManager
  AuthService
  AuthViewController
  OAuthHandler

darkmach> get_methods AuthTokenManager
8 instance methods:
  getToken: types=@@:
  refreshToken:: types=v@:@
  setToken:: types=v@:@
  clearToken: types=v@:
  isTokenValid: types=B@:
  tokenExpiresAt: types=@@:
  tokenString: types=@@:

darkmach> heap_search AuthTokenManager
Found 1 instance:
  0x0000600002a4f320 via sharedInstance
    <AuthTokenManager: 0x600002a4f320>

darkmach> read_property 0x0000600002a4f320 tokenString
Property: tokenString
Value: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ1XzEyMzQ1IiwiZXhwIjoxN...
Class: __NSCFString

darkmach> trace AuthTokenManager refreshToken:
Hooked slot 0: AuthTokenManager -refreshToken: (arg_types: [id, SEL, id])

darkmach> trace_log
1 entry:
  [slot=0] AuthTokenManager -refreshToken: @ 2026-03-26T10:00:01.234 (thread 0x700012345678)
    arg2: {type: id, value: <NSString: "https://api.example.com/token">}

darkmach> keychain_dump
Keychain items: 2
  [GenericPassword] {acct = session; svce = com.oddsjam.app; data = tok_xyz...}
  [GenericPassword] {acct = anonymous_id; svce = com.oddsjam.app.revenuecat; data = ...}

darkmach> net_tap 5
5 of 47 captured requests:
  #1 POST https://api.oddsjam.com/v2/auth/token -> 200 (342ms)
  #2 GET  https://api.oddsjam.com/v2/user/profile -> 200 (128ms)
  ...

darkmach> auth_tokens
1 unique token:
  access_token: eyJhbGciOiJSUzI1Ni... (1247 chars)
    sub=u_12345, exp=1740000000, iss=https://auth.oddsjam.com
    source: oauth_token_response
```

### Raw JSON Mode

Send arbitrary JSON for commands or arguments not yet in the REPL parser:

```
darkmach> raw {"cmd": "mem_forensics", "args": {"patterns": "sk_live_,pk_live_"}}
darkmach> raw {"cmd": "net_filter", "args": {"host": "stripe.com", "method": "POST"}}
```

---

## Python API

Use the bridge from your own scripts:

```python
from darkmach.bridge import send_command

# Get all classes containing "Auth"
response = send_command("enumerate_classes", {"filter": "Auth"})
if response["ok"]:
    for cls in response["classes"]:
        print(cls)

# Read a live property
response = send_command("read_property", {
    "address": 0x0000600002a4f320,
    "property": "tokenString"
})
print(response["value"])

# Dump the keychain
response = send_command("keychain_dump")
for item in response["items"]:
    print(item["data"])

# Read captured network traffic. darkmach-net.dylib has been filling the ring
# since process start, so this returns history — no activation call needed.
response = send_command("net_tap", {"limit": 100})
if not response["data"]["capturing"]:
    print("darkmach-net.dylib not injected — 0 results means unobserved, not absent")
for req in response["data"]["requests"]:
    print(f"{req['method']} {req['url']} -> {req['status']}")

# Forensic memory scan
response = send_command("mem_forensics")
for finding in response["data"]["findings"]:
    print(f"[{finding['pattern_matched']}] {finding['preview'][:80]}")
```

The `send_command` function handles connection, request serialization, response reading, and JSON parsing. It returns a dict — check `response["ok"]` before using the result.

---

## Operator Exploration Workflow

The bridge supports a systematic exploration loop. Whether driven by a human operator or an automation client speaking the JSON protocol, the recommended sequence is:

```
1. Call enumerate_classes → identify high-value class names
   (Auth, Token, Payment, Crypto, API, Secret, Key, Wallet, Session, Credential)

2. For each high-value class:
   a. get_methods → understand what it does
   b. get_properties → understand what it stores
   c. heap_search → find live instances (fast path)
      OR heap_dump {class: "ClassName"} → exhaustive walk

3. For each live instance:
   a. read_property on interesting properties → extract live values
   b. trace on interesting methods → capture future calls with arguments
   c. call_method on accessors → read current state

4. Dump all data stores:
   keychain_dump, userdefaults_dump, cookies_dump, db_dump

5. Monitor network activity:
   net_tap → HTTP traffic with headers and body previews
   auth_tap → OAuth flows and JWT tokens (decoded claims)
   crypto_tap → encryption operations and keys

6. SDK and entitlement analysis:
   sdk_map → identify third-party SDKs
   sdk_keys → extract SDK API keys
   entitlement_scan → flag overprivileged entitlements

7. Scan for residual secrets:
   mem_forensics → find sensitive data in freed memory
   memory_scan → search across all VM regions

8. Analyze findings:
   - Decode JWTs, identify key formats
   - Correlate: API key in UserDefaults → used by NetworkClient → sent to endpoint
   - Identify authentication flows, secret storage patterns
   - Flag security issues: hardcoded credentials, weak crypto, missing pinning

9. Continue exploring based on what was found
```

The LLM connects via `darkmach.bridge.send_command()` and uses the Python API directly. No special MCP or tool wrapper is required.

---

## Technical Notes

**Socket path:** `/tmp/darkmach-bridge.sock`. Fixed path shared between the app process and the host. The CLI removes the socket before each launch.

**Max response size:** 1MB per response. Large responses (e.g., `enumerate_classes` without a filter, `heap_dump` on a large app) may be truncated. Use the `filter`, `limit`, and `offset` arguments to scope requests.

**Request timeout:** The Python client sets a 30-second socket timeout. Long-running operations (heap scan on a large app, `mem_forensics`) may approach this limit. `mem_forensics` has a built-in 5-second scan timeout.

**Concurrency:** Each client connection is handled on its own GCD serial queue. The bridge accepts multiple simultaneous connections, but ObjC runtime calls within commands are not synchronized — avoid concurrent commands that modify the same class.

**Ring buffer capacity:** Network (net_tap, crypto_tap, auth_tap), event_tap, and trace_log each use a 500-entry ring buffer. Entries beyond capacity overwrite the oldest.

**Trace hook limit:** 256 simultaneous trampoline trace hooks (one stub per slot). `trace_class` on large classes may exhaust slots.

**Bridge log:** Commands and events are logged to `output/<app>/dynamic/darkmach-bridge.jsonl` when `DARKMACH_OUTPUT_DIR` is set.

**auth_tap dependency:** `auth_tap` and `auth_tokens` automatically activate `net_tap` if it is not already enabled. The auth scanner works by re-scanning the net_tap ring buffer each time it is called.

**Stealth commands:** `stealth_scan`, `stealth_enable`, and `stealth_status` are dispatched to `darkmach-stealth.dylib` via `dlsym`. They return an error if `darkmach-stealth.dylib` is not loaded.
