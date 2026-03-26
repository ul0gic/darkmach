# Bridge Command Protocol Specification

> Source of truth for ALL new bridge commands. Both C (mobile-engineer) and Python (code-engineer) code against this spec.
> Date: 2026-03-25 | Sprint 13.0.3 | Phase 13: Bridge Capabilities

---

## Protocol Fundamentals

**Transport:** Unix domain socket at `/tmp/sphinx-bridge.sock`

**Encoding:** JSON-lines (one JSON object per line, newline-delimited)

**Request format:**
```json
{"id": <int>, "cmd": "<command_name>", "args": {<command-specific>}}
```

**Success response:**
```json
{"id": <int>, "ok": true, "data": {<command-specific>}}
```

**Error response:**
```json
{"id": <int>, "ok": false, "error": "<human-readable message>"}
```

**Conventions:**
- `id` is echoed back from the request, used by the client to correlate async responses.
- All addresses are hex strings with `0x` prefix (e.g., `"0x1a2b3c4d"`).
- Timestamps are ISO 8601 strings (`"2026-03-25T14:30:00.123"`).
- Binary data previews are hex-encoded strings, capped at 128 hex chars (64 bytes) unless otherwise noted.
- `limit` defaults vary per command (documented below). A value of `0` means "return all."
- String args are parsed via `json_get_string()` (max 256 chars unless noted).
- Integer args are parsed via `json_get_long()`.
- Optional args that are omitted use the documented default.

**Response size:** Hard cap at 1 MB (`BRIDGE_MAX_RESPONSE`). Commands that may exceed this must paginate or truncate with a `truncated: true` field.

---

## Existing Commands (18 -- unchanged)

These commands are already implemented and their protocol is frozen. Listed here for completeness; new commands must not conflict with these names.

| Command | Module | Purpose |
|---------|--------|---------|
| `info` | cmd-recon.c | App metadata, class count, available commands |
| `enumerate_classes` | cmd-recon.c | List ObjC classes with optional filter |
| `get_methods` | cmd-recon.c | List methods on a class |
| `get_properties` | cmd-recon.c | List properties on a class |
| `get_ivars` | cmd-recon.c | List instance variables on a class |
| `read_property` | cmd-recon.c | Read live property value from object instance |
| `call_method` | cmd-recon.c | Invoke no-arg method on live object |
| `view_hierarchy` | cmd-recon.c | Dump UIKit view tree |
| `heap_search` | cmd-recon.c | Find live instances of a class (legacy) |
| `read_memory` | cmd-recon.c | Read N bytes at address |
| `hook_method` | cmd-trace.c | Install logging hook on a method |
| `unhook_method` | cmd-trace.c | Remove a logging hook |
| `keychain_dump` | cmd-events.c | Read keychain items |
| `userdefaults_dump` | cmd-events.c | Read NSUserDefaults |
| `cookies_dump` | cmd-events.c | Read HTTP cookies |
| `db_dump` | cmd-events.c | Enumerate SQLite databases and dump contents |
| `fs_scan` | cmd-recon.c | Scan app container filesystem |
| `memory_scan` | cmd-recon.c | Pattern search through memory |

---

## Sprint 13.1 -- Foundation

### 1. `heap_dump`

**File:** `cmd-recon.c`
**Purpose:** Walk all malloc zones, enumerate live ObjC objects on the heap.
**Infrastructure:** `sphinx_heap_scan_t` from `sphinx-core.h`, `malloc_get_all_zones()`.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `class` | string | no | `""` (all) | Filter by exact class name. Empty = return all ObjC objects. |
| `limit` | int | no | `1000` | Maximum objects to return. |
| `offset` | int | no | `0` | Skip this many matching objects (pagination). |

**Response `data`:**
```json
{
  "instances": [
    {"addr": "0x600001234560", "class": "NSURLCredential", "size": 64},
    {"addr": "0x600001234600", "class": "NSURLCredential", "size": 64}
  ],
  "total_scanned": 482916,
  "total_matched": 2,
  "returned": 2,
  "time_ms": 340
}
```

**Example:**
```
-> {"id":1,"cmd":"heap_dump","args":{"class":"NSURLCredential","limit":50}}
<- {"id":1,"ok":true,"data":{"instances":[{"addr":"0x600001234560","class":"NSURLCredential","size":64}],"total_scanned":482916,"total_matched":1,"returned":1,"time_ms":340}}
```

**Notes:**
- Uses `malloc_get_all_zones()` + zone introspect enumerator with `MALLOC_PTR_IN_USE_RANGE_TYPE`.
- Validates each allocation with `is_valid_objc_ptr()` from `sphinx-core.h`.
- Without `class` filter, returns all ObjC objects up to `limit` -- use with care.
- Replaces the broken `heap_search` command for class-based object discovery.
- See `dev/frida-gum-heap-study.md` for implementation patterns.

---

### 2. `event_tap`

**File:** `cmd-events.c`
**Purpose:** Monitor NSNotificationCenter posts. Ring buffer captures all notifications; this command queries/controls the tap.
**Infrastructure:** `sphinx_ring_t` from `sphinx-core.h`.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `action` | string | yes | -- | `"enable"`, `"disable"`, or `"recent"` |
| `name_filter` | string | no | `""` (all) | Substring filter on notification name. |
| `limit` | int | no | `50` | Max events to return (for `"recent"`). |

**Response `data` (action = "enable"):**
```json
{
  "enabled": true,
  "name_filter": "Auth"
}
```

**Response `data` (action = "disable"):**
```json
{
  "disabled": true,
  "total_captured": 147
}
```

**Response `data` (action = "recent"):**
```json
{
  "events": [
    {
      "name": "com.app.AuthStateChanged",
      "object_class": "AuthManager",
      "user_info_keys": ["token", "expiry", "user_id"],
      "timestamp": "2026-03-25T14:30:01.456"
    }
  ],
  "total_captured": 147,
  "returned": 1
}
```

**Example:**
```
-> {"id":2,"cmd":"event_tap","args":{"action":"enable"}}
<- {"id":2,"ok":true,"data":{"enabled":true,"name_filter":""}}

-> {"id":3,"cmd":"event_tap","args":{"action":"recent","name_filter":"Auth","limit":10}}
<- {"id":3,"ok":true,"data":{"events":[{"name":"com.app.AuthStateChanged","object_class":"AuthManager","user_info_keys":["token","expiry"],"timestamp":"2026-03-25T14:30:01.456"}],"total_captured":147,"returned":1}}
```

**Notes:**
- Enable installs a catch-all observer via `addObserverForName:nil object:nil queue:nil usingBlock:`.
- Also swizzles `NSNotificationCenter postNotificationName:object:userInfo:` for comprehensive capture.
- Ring buffer holds 500 entries. Oldest entries are overwritten.
- `name_filter` applies both at capture time (when set via `enable`) and at query time (via `recent`).

---

### 3. `env_dump`

**File:** `cmd-recon.c`
**Purpose:** Capture complete process environment -- env vars, launch args, loaded images, open file descriptors.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "env": {
    "HOME": "/Users/user/Library/Developer/CoreSimulator/...",
    "DYLD_INSERT_LIBRARIES": "/path/to/sphinx-bridge.dylib",
    "SPHINX_OUTPUT_DIR": "/path/to/output"
  },
  "args": ["AppName", "-AppleLanguages", "(en)"],
  "images": [
    {"name": "AppName", "path": "/path/to/AppName.app/AppName", "base": "0x100000000", "slide": "0x4000"},
    {"name": "sphinx-bridge.dylib", "path": "/path/to/sphinx-bridge.dylib", "base": "0x100100000", "slide": "0x0"}
  ],
  "fds": [
    {"fd": 0, "path": "/dev/null", "type": "file"},
    {"fd": 3, "path": "/tmp/sphinx-bridge.sock", "type": "socket"},
    {"fd": 5, "path": "/path/to/db.sqlite", "type": "file"}
  ],
  "pid": 12345
}
```

**Example:**
```
-> {"id":4,"cmd":"env_dump","args":{}}
<- {"id":4,"ok":true,"data":{"env":{"HOME":"/Users/..."},"args":["AppName"],"images":[{"name":"AppName","path":"/path","base":"0x100000000","slide":"0x4000"}],"fds":[{"fd":0,"path":"/dev/null","type":"file"}],"pid":12345}}
```

**Notes:**
- Environment: iterate `extern char **environ`.
- Args: `[[NSProcessInfo processInfo] arguments]`.
- Images: loop `_dyld_image_count()`, call `_dyld_get_image_name()` and `_dyld_get_image_header()`. Slide via `_dyld_get_image_vmaddr_slide()`.
- FDs: iterate 0..1024, `fcntl(fd, F_GETFL)` to test validity, `fcntl(fd, F_GETPATH, buf)` for file path, `getsockname()` for sockets.
- Trivial complexity (~100 lines). No dependencies.

---

### 4. `db_inject`

**File:** `cmd-inject.c`
**Purpose:** Execute arbitrary SQL (read/write) against any SQLite database in the app sandbox.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `path` | string | yes | -- | Absolute path to the SQLite database file. |
| `sql` | string | yes | -- | SQL statement to execute. |

**Response `data` (SELECT):**
```json
{
  "columns": ["id", "username", "email"],
  "rows": [
    [1, "admin", "admin@example.com"],
    [2, "user1", "user1@example.com"]
  ],
  "row_count": 2
}
```

**Response `data` (INSERT/UPDATE/DELETE):**
```json
{
  "affected": 1,
  "last_insert_id": 42
}
```

**Example:**
```
-> {"id":5,"cmd":"db_inject","args":{"path":"/path/to/app.db","sql":"SELECT * FROM users LIMIT 5"}}
<- {"id":5,"ok":true,"data":{"columns":["id","username","email"],"rows":[[1,"admin","admin@example.com"]],"row_count":1}}

-> {"id":6,"cmd":"db_inject","args":{"path":"/path/to/app.db","sql":"UPDATE users SET is_premium=1 WHERE id=1"}}
<- {"id":6,"ok":true,"data":{"affected":1,"last_insert_id":0}}
```

**Notes:**
- Opens database with `SQLITE_OPEN_READWRITE`. Falls back to `SQLITE_OPEN_READONLY` on permission error.
- For SELECT: detects query type by checking if `sqlite3_column_count() > 0` after prepare.
- For writes: returns `sqlite3_changes()` as `affected` and `sqlite3_last_insert_rowid()` as `last_insert_id`.
- Row values: integers as JSON numbers, floats as JSON numbers, text as JSON strings, blobs as `"<blob N bytes>"`, NULLs as JSON `null`.
- Rows capped at 500 to stay within response size limit. Set `truncated: true` if more exist.
- Uses the existing `sqlite3` link from cmd-events.c (db_dump).

---

### 5. `db_queries`

**File:** `cmd-inject.c`
**Purpose:** Return recently intercepted SQL queries from live app activity.
**Infrastructure:** `sphinx_ring_t` from `sphinx-core.h`. Populated by `sqlite3_prepare_v2` interpose.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `limit` | int | no | `50` | Max queries to return. |
| `path_filter` | string | no | `""` | Filter by database path substring. |

**Response `data`:**
```json
{
  "queries": [
    {
      "sql": "SELECT token FROM auth WHERE user_id = ?",
      "params": ["12345"],
      "path": "/path/to/app.db",
      "timestamp": "2026-03-25T14:30:05.789",
      "duration_us": 230
    }
  ],
  "total_captured": 89,
  "returned": 1
}
```

**Example:**
```
-> {"id":7,"cmd":"db_queries","args":{"limit":20}}
<- {"id":7,"ok":true,"data":{"queries":[{"sql":"SELECT token FROM auth WHERE user_id = ?","params":["12345"],"path":"/path/to/app.db","timestamp":"2026-03-25T14:30:05.789","duration_us":230}],"total_captured":89,"returned":1}}
```

**Notes:**
- Requires DYLD_INTERPOSE on `sqlite3_prepare_v2` and `sqlite3_exec` (via `interceptors/sphinx-db.c` or inline in cmd-inject.c).
- Params captured by also interposing `sqlite3_bind_text`, `sqlite3_bind_int`, `sqlite3_bind_int64`, `sqlite3_bind_double`, `sqlite3_bind_blob`.
- Ring buffer of 500 entries. Starts capturing on bridge init (constructor).
- `duration_us` measured from prepare to finalize.

---

## Sprint 13.2 -- Network Intelligence

### 6. `net_tap`

**File:** `cmd-network.c`
**Purpose:** Return recently captured HTTP request/response pairs.
**Infrastructure:** `sphinx_ring_t` from `sphinx-core.h`. Populated by NSURLSession swizzle hooks.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `limit` | int | no | `50` | Max requests to return. |

**Response `data`:**
```json
{
  "requests": [
    {
      "id": 42,
      "method": "POST",
      "url": "https://api.example.com/v1/auth/login",
      "req_headers": {
        "Authorization": "Bearer eyJ...",
        "Content-Type": "application/json"
      },
      "req_body_preview": "{\"username\":\"admin\",\"password\":\"...",
      "status": 200,
      "resp_headers": {
        "Set-Cookie": "session=abc123; HttpOnly",
        "Content-Type": "application/json"
      },
      "resp_body_preview": "{\"access_token\":\"eyJ...\",\"refresh...",
      "duration_ms": 245,
      "timestamp": "2026-03-25T14:30:10.123"
    }
  ],
  "total_captured": 156,
  "returned": 1
}
```

**Example:**
```
-> {"id":8,"cmd":"net_tap","args":{"limit":10}}
<- {"id":8,"ok":true,"data":{"requests":[{"id":42,"method":"POST","url":"https://api.example.com/v1/auth/login","req_headers":{"Authorization":"Bearer eyJ..."},"req_body_preview":"{\"username\":...","status":200,"resp_headers":{},"resp_body_preview":"{\"access_token\":...","duration_ms":245,"timestamp":"2026-03-25T14:30:10.123"}],"total_captured":156,"returned":1}}
```

**Notes:**
- Hooks installed at bridge init: swizzle `NSURLSession -dataTaskWithRequest:completionHandler:`, `-dataTaskWithURL:completionHandler:`, and delegate-based variants.
- Request body: `[NSURLRequest HTTPBody]`, truncated to 512 bytes for preview.
- Response body: accumulated in wrapped completion handler, truncated to 512 bytes.
- Response headers and status captured from `NSHTTPURLResponse`.
- Ring buffer of 500 entries. Each entry is one complete request/response pair.
- Headers stored as flat JSON object (key: value). Duplicate header names are comma-joined.
- Body previews are UTF-8 text. Binary bodies shown as `"<binary N bytes>"`.
- Captures traffic regardless of certificate pinning (hooks are inside the process).

---

### 7. `net_filter`

**File:** `cmd-network.c`
**Purpose:** Query captured traffic with filters. Same underlying ring buffer as `net_tap`.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `host` | string | no | `""` | Filter by hostname substring. |
| `path` | string | no | `""` | Filter by URL path substring. |
| `method` | string | no | `""` | Filter by HTTP method (exact match, case-insensitive). |
| `status` | int | no | `0` | Filter by exact status code. `0` = no filter. |
| `limit` | int | no | `50` | Max requests to return. |

**Response `data`:** Same structure as `net_tap`.

**Example:**
```
-> {"id":9,"cmd":"net_filter","args":{"host":"api.example.com","method":"POST","limit":5}}
<- {"id":9,"ok":true,"data":{"requests":[...],"total_captured":156,"returned":3}}
```

**Notes:**
- Reads from the same ring buffer as `net_tap`, applying filters during iteration.
- All filters are AND-combined (all specified filters must match).
- `host` is extracted from the URL at query time; does not require separate storage.

---

### 8. `crypto_tap`

**File:** `cmd-network.c`
**Purpose:** Return recently intercepted cryptographic operations.
**Infrastructure:** `sphinx_ring_t`. Populated by DYLD_INTERPOSE on CommonCrypto functions.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `limit` | int | no | `50` | Max operations to return. |

**Response `data`:**
```json
{
  "operations": [
    {
      "op": "CCCrypt",
      "algorithm": "AES-256-CBC",
      "encrypt": true,
      "key_hex": "a1b2c3d4e5f6...0000",
      "iv_hex": "00112233445566778899aabbccddeeff",
      "input_len": 2048,
      "output_preview": "e3f4a5b6c7d8...",
      "timestamp": "2026-03-25T14:30:12.456"
    },
    {
      "op": "CCHmac",
      "algorithm": "HMAC-SHA256",
      "encrypt": false,
      "key_hex": "deadbeef...",
      "iv_hex": "",
      "input_len": 128,
      "output_preview": "f1e2d3c4b5a6...",
      "timestamp": "2026-03-25T14:30:12.789"
    }
  ],
  "total_captured": 34,
  "returned": 2
}
```

**Example:**
```
-> {"id":10,"cmd":"crypto_tap","args":{"limit":20}}
<- {"id":10,"ok":true,"data":{"operations":[{"op":"CCCrypt","algorithm":"AES-256-CBC","encrypt":true,"key_hex":"a1b2c3...","iv_hex":"001122...","input_len":2048,"output_preview":"e3f4a5...","timestamp":"2026-03-25T14:30:12.456"}],"total_captured":34,"returned":2}}
```

**Notes:**
- Interpose targets: `CCCrypt`, `CCCryptorCreate`, `CCCryptorUpdate`, `CCCryptorFinal`, `CCHmac`, `CCHmacInit`, `CCKeyDerivationPBKDF`.
- `algorithm` is a human-readable string derived from `CCAlgorithm` + `CCMode` enums (e.g., `"AES-128-CBC"`, `"AES-256-GCM"`, `"3DES-ECB"`, `"HMAC-SHA256"`, `"PBKDF2"`).
- `encrypt` is `true` for encryption, `false` for decryption/hashing/HMAC.
- Key and IV are full hex dumps (not truncated -- keys are the whole point).
- `output_preview` is first 64 bytes of output, hex-encoded (128 hex chars).
- Wires existing patterns from `interceptors/sphinx-crypto.c` into the bridge ring buffer.

---

### 9. `crypto_keys`

**File:** `cmd-network.c`
**Purpose:** Return deduplicated key material extracted from crypto operations.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "keys": [
    {
      "algorithm": "AES-256-CBC",
      "key_hex": "a1b2c3d4e5f6...0000",
      "key_len_bits": 256,
      "first_seen": "2026-03-25T14:30:12.456",
      "last_seen": "2026-03-25T14:31:45.789",
      "use_count": 12
    }
  ],
  "total_unique": 3
}
```

**Example:**
```
-> {"id":11,"cmd":"crypto_keys","args":{}}
<- {"id":11,"ok":true,"data":{"keys":[{"algorithm":"AES-256-CBC","key_hex":"a1b2c3...","key_len_bits":256,"first_seen":"2026-03-25T14:30:12.456","last_seen":"2026-03-25T14:31:45.789","use_count":12}],"total_unique":3}}
```

**Notes:**
- Maintained as a separate deduplication table (not the ring buffer). Max 128 unique keys.
- Keys are deduplicated by their raw bytes (regardless of which operation used them).
- `algorithm` is from the first observed operation using this key.
- High-value target: captured keys unlock encrypted local databases, encrypted preferences, API request signing.

---

### 10. `auth_tap`

**File:** `cmd-network.c`
**Purpose:** Record authentication flow events -- OAuth tokens, biometric auth, session establishment.
**Infrastructure:** `sphinx_ring_t`. Populated by hooks on auth-related APIs + filtered `net_tap` entries.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `limit` | int | no | `50` | Max events to return. |

**Response `data`:**
```json
{
  "events": [
    {
      "type": "oauth_token_response",
      "url": "https://auth.example.com/oauth/token",
      "provider": "oauth2",
      "token_preview": "eyJhbGciOiJSUzI1NiIs...",
      "token_type": "access_token",
      "claims": {
        "sub": "user123",
        "exp": 1711382400,
        "scope": "read write",
        "iss": "https://auth.example.com"
      },
      "timestamp": "2026-03-25T14:30:15.123"
    },
    {
      "type": "biometric_auth",
      "url": "",
      "provider": "LocalAuthentication",
      "token_preview": "",
      "token_type": "",
      "claims": {
        "policy": "deviceOwnerAuthenticationWithBiometrics",
        "result": "success",
        "reason": "Authenticate to access your account"
      },
      "timestamp": "2026-03-25T14:30:14.890"
    }
  ],
  "total_captured": 8,
  "returned": 2
}
```

**Example:**
```
-> {"id":12,"cmd":"auth_tap","args":{"limit":20}}
<- {"id":12,"ok":true,"data":{"events":[{"type":"oauth_token_response","url":"https://auth.example.com/oauth/token","provider":"oauth2","token_preview":"eyJhbG...","token_type":"access_token","claims":{"sub":"user123","exp":1711382400},"timestamp":"2026-03-25T14:30:15.123"}],"total_captured":8,"returned":2}}
```

**Notes:**
- Event types: `"oauth_authorize"`, `"oauth_token_request"`, `"oauth_token_response"`, `"token_refresh"`, `"biometric_auth"`, `"keychain_token_read"`, `"keychain_token_write"`, `"session_cookie"`.
- Hook targets: `ASWebAuthenticationSession`, `LAContext evaluatePolicy:localizedReason:reply:`, keychain SecItem* ops filtered for auth-related `kSecAttrService` values.
- JWT detection: base64-decode tokens matching `eyJ...` pattern, parse header + payload as JSON.
- `claims` contains decoded JWT payload for JWT tokens; for non-JWT, contains relevant metadata.
- `provider` heuristic: detect OAuth2, OIDC, Firebase Auth, Apple Sign-In, custom.
- Depends on `net_tap` being active (filters auth-related requests from the same ring buffer + adds its own hooks).

---

### 11. `auth_tokens`

**File:** `cmd-network.c`
**Purpose:** Return deduplicated extracted tokens from auth flow.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "tokens": [
    {
      "type": "access_token",
      "value_preview": "eyJhbGciOiJSUzI1NiIs...",
      "full_value_len": 847,
      "claims": {"sub": "user123", "exp": 1711382400, "scope": "read write"},
      "source": "oauth_token_response",
      "first_seen": "2026-03-25T14:30:15.123",
      "last_seen": "2026-03-25T14:30:15.123"
    },
    {
      "type": "refresh_token",
      "value_preview": "dGhpcyBpcyBhIHJlZnJl...",
      "full_value_len": 128,
      "claims": {},
      "source": "oauth_token_response",
      "first_seen": "2026-03-25T14:30:15.123",
      "last_seen": "2026-03-25T14:30:15.123"
    }
  ],
  "total_unique": 2
}
```

**Example:**
```
-> {"id":13,"cmd":"auth_tokens","args":{}}
<- {"id":13,"ok":true,"data":{"tokens":[{"type":"access_token","value_preview":"eyJhbG...","full_value_len":847,"claims":{"sub":"user123"},"source":"oauth_token_response","first_seen":"2026-03-25T14:30:15.123","last_seen":"2026-03-25T14:30:15.123"}],"total_unique":2}}
```

**Notes:**
- Deduplicated by raw token value. Max 64 unique tokens tracked.
- `value_preview` is first 64 characters of the token. Full value available via the auth_tap ring buffer entry.
- Token types: `"access_token"`, `"refresh_token"`, `"id_token"`, `"session_cookie"`, `"api_key"`, `"bearer"`, `"custom"`.

---

## Sprint 13.3 -- Trampoline (Method Tracing)

### 12. `trace`

**File:** `cmd-trace.c`
**Purpose:** Install a tracing hook on a specific ObjC method with full argument and return value capture.
**Infrastructure:** `sphinx_hook_t` table (256 slots) from `sphinx-core.h`, ARM64 trampoline from `sphinx-trampoline.S`.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `class` | string | yes | -- | ObjC class name. |
| `method` | string | yes | -- | Selector name (e.g., `"sendAuthToken:"`). |

**Response `data`:**
```json
{
  "hooked": true,
  "slot": 7,
  "class": "AuthManager",
  "method": "sendAuthToken:",
  "type_encoding": "v@:@",
  "arg_types": ["id (self)", "SEL (_cmd)", "NSString*"]
}
```

**Example:**
```
-> {"id":14,"cmd":"trace","args":{"class":"AuthManager","method":"sendAuthToken:"}}
<- {"id":14,"ok":true,"data":{"hooked":true,"slot":7,"class":"AuthManager","method":"sendAuthToken:","type_encoding":"v@:@","arg_types":["id (self)","SEL (_cmd)","NSString*"]}}
```

**Notes:**
- Replaces the existing `hook_method` for traced methods (with full arg/return capture vs. fire-and-forget).
- Slot is the index into the global `sphinx_hook_t` table (0-255). Needed for `untrace`.
- Type encoding parsed via `method_getTypeEncoding()`. `arg_types` is a human-readable decode.
- Trampoline saves X0-X7 + Q0-Q7 (200 bytes), calls logging function, restores, calls original IMP.
- Reentrancy guard via `pthread_key_t` TLS -- prevents recursive logging when traced methods call other traced methods.
- Error if class/method not found, or if all 256 slots are full.
- Supersedes `hook_method` -- both can coexist but `trace` provides argument capture while `hook_method` does not.

---

### 13. `trace_class`

**File:** `cmd-trace.c`
**Purpose:** Install tracing hooks on ALL instance methods of a class.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `class` | string | yes | -- | ObjC class name. |
| `include_super` | string | no | `"false"` | If `"true"`, also hook inherited methods. |

**Response `data`:**
```json
{
  "class": "AuthManager",
  "hooked": 12,
  "skipped": 3,
  "methods": [
    "sendAuthToken:",
    "validatePassword:",
    "refreshSession",
    "logout"
  ],
  "skipped_reasons": ["dealloc (unsafe)", "class (meta)", ".cxx_destruct (unsafe)"]
}
```

**Example:**
```
-> {"id":15,"cmd":"trace_class","args":{"class":"AuthManager"}}
<- {"id":15,"ok":true,"data":{"class":"AuthManager","hooked":12,"skipped":3,"methods":["sendAuthToken:","validatePassword:","refreshSession","logout"],"skipped_reasons":["dealloc (unsafe)"]}}
```

**Notes:**
- Uses `class_copyMethodList()` to enumerate all instance methods.
- Skips: `dealloc`, `.cxx_destruct`, `retain`, `release`, `autorelease`, `class`, `respondsToSelector:` (unsafe to hook, cause crashes).
- Consumes one slot per method. Will stop and report partial success if slots run out.
- `methods` list in response contains all successfully hooked selectors.

---

### 14. `trace_log`

**File:** `cmd-trace.c`
**Purpose:** Retrieve recent trace log entries (argument/return value captures).

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `limit` | int | no | `50` | Max entries to return. |
| `class` | string | no | `""` | Filter by class name. |
| `method` | string | no | `""` | Filter by selector name. |
| `slot` | int | no | `-1` | Filter by specific hook slot. `-1` = no filter. |

**Response `data`:**
```json
{
  "entries": [
    {
      "slot": 7,
      "class": "AuthManager",
      "method": "sendAuthToken:",
      "timestamp": "2026-03-25T14:30:20.123",
      "thread_id": "0x700001234000",
      "args": {
        "arg2": {"type": "NSString*", "value": "eyJhbGciOiJSUzI1NiIs..."}
      },
      "return_value": {"type": "void", "value": null},
      "duration_ns": 45000
    }
  ],
  "total_entries": 234,
  "returned": 1
}
```

**Example:**
```
-> {"id":16,"cmd":"trace_log","args":{"class":"AuthManager","limit":10}}
<- {"id":16,"ok":true,"data":{"entries":[{"slot":7,"class":"AuthManager","method":"sendAuthToken:","timestamp":"2026-03-25T14:30:20.123","thread_id":"0x700001234000","args":{"arg2":{"type":"NSString*","value":"eyJhbG..."}},"return_value":{"type":"void","value":null},"duration_ns":45000}],"total_entries":234,"returned":1}}
```

**Notes:**
- Trace entries stored in a global ring buffer (500 entries, shared across all hooks).
- Args are numbered `arg0` (self), `arg1` (_cmd), `arg2`...`argN`. Self and _cmd are always omitted from the output for brevity -- args start at `arg2`.
- Type-aware decoding: `@` -> call `description` on ObjC object; `i`/`l`/`q` -> integer; `f`/`d` -> float/double; `*` -> C string; `#` -> class name; `:` -> selector name; `{...}` -> struct as hex dump; `@?` -> block (shows invoke address).
- `duration_ns` is wall time from entry to original IMP return (via `mach_absolute_time()`).
- `return_value` decoded using the same type encoding rules.
- ObjC object `value` strings are truncated at 256 characters.

---

### 15. `untrace`

**File:** `cmd-trace.c`
**Purpose:** Remove a tracing hook. Restores the original method implementation.

**Args (option A -- by class+method):**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `class` | string | yes* | -- | ObjC class name. |
| `method` | string | yes* | -- | Selector name. |

**Args (option B -- by slot):**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `slot` | int | yes* | -- | Hook slot index (from `trace` response). |

*One of the two options must be provided. If `slot` is >= 0, it takes precedence.

**Response `data`:**
```json
{
  "unhooked": true,
  "slot": 7,
  "class": "AuthManager",
  "method": "sendAuthToken:"
}
```

**Example:**
```
-> {"id":17,"cmd":"untrace","args":{"slot":7}}
<- {"id":17,"ok":true,"data":{"unhooked":true,"slot":7,"class":"AuthManager","method":"sendAuthToken:"}}

-> {"id":18,"cmd":"untrace","args":{"class":"AuthManager","method":"sendAuthToken:"}}
<- {"id":18,"ok":true,"data":{"unhooked":true,"slot":7,"class":"AuthManager","method":"sendAuthToken:"}}
```

**Notes:**
- Restores original IMP via `method_setImplementation(method, hook->original_imp)`.
- Marks the slot as inactive (`active = 0`), making it available for reuse.
- Error if the specified hook is not found or already inactive.

---

## Sprint 13.4 -- Active Capabilities

### 16. `ui_tap`

**File:** `cmd-ui.c`
**Purpose:** Synthesize a touch event on a UI element. Supports targeting by coordinates, accessibility label, class name, or displayed text.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `x` | string | no | -- | X coordinate (screen points). Use with `y`. |
| `y` | string | no | -- | Y coordinate (screen points). Use with `x`. |
| `label` | string | no | -- | Accessibility label to find and tap. |
| `class` | string | no | -- | UIKit class name to find (e.g., `"UIButton"`). |
| `text` | string | no | -- | Displayed text to match (searches titleLabel, text properties). |
| `index` | int | no | `0` | If multiple matches, tap the Nth one (0-based). |

*At least one targeting arg must be provided: `x`+`y`, `label`, `class`, or `text`.*

**Response `data`:**
```json
{
  "tapped": true,
  "target_class": "UIButton",
  "target_label": "Login",
  "target_frame": {"x": 120.0, "y": 450.0, "w": 200.0, "h": 44.0}
}
```

**Example:**
```
-> {"id":19,"cmd":"ui_tap","args":{"label":"Login"}}
<- {"id":19,"ok":true,"data":{"tapped":true,"target_class":"UIButton","target_label":"Login","target_frame":{"x":120.0,"y":450.0,"w":200.0,"h":44.0}}}

-> {"id":20,"cmd":"ui_tap","args":{"x":"160","y":"472"}}
<- {"id":20,"ok":true,"data":{"tapped":true,"target_class":"UIButton","target_label":"Login","target_frame":{"x":120.0,"y":450.0,"w":200.0,"h":44.0}}}
```

**Notes:**
- All UI operations dispatch to main thread via `dispatch_sync(dispatch_get_main_queue(), ...)`.
- Coordinate taps: use `UIApplication sendEvent:` with synthesized `UITouch`/`UIEvent`, or call `sendActionsForControlEvents:UIControlEventTouchUpInside` on the hit-tested view.
- Label/class/text search: walk the view hierarchy from `keyWindow.rootViewController.view`, find matching views.
- `x` and `y` are strings because they are parsed via `json_get_string` and converted to float. (Protocol limitation of the minimal JSON parser.)
- Error if no matching element found.
- Float values in frame are formatted to 1 decimal place.

---

### 17. `ui_type`

**File:** `cmd-ui.c`
**Purpose:** Insert text into a text field.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `text` | string | yes | -- | Text to insert. |
| `address` | string | no | -- | Address of a specific UITextField/UITextView (hex). |
| `clear` | string | no | `"false"` | If `"true"`, clear existing text before typing. |

**Response `data`:**
```json
{
  "typed": true,
  "field_class": "UITextField",
  "field_address": "0x7fc1234abcd0",
  "previous_text": "old value",
  "new_text": "new value"
}
```

**Example:**
```
-> {"id":21,"cmd":"ui_type","args":{"text":"admin@example.com","clear":"true"}}
<- {"id":21,"ok":true,"data":{"typed":true,"field_class":"UITextField","field_address":"0x7fc1234abcd0","previous_text":"","new_text":"admin@example.com"}}
```

**Notes:**
- If `address` is omitted, targets the current first responder (the active text field).
- If no first responder, searches the view hierarchy for the first UITextField/UITextView and calls `becomeFirstResponder`.
- Text insertion via `insertText:` on `UITextInput` protocol or direct `setText:` property.
- Dispatches to main thread.

---

### 18. `ui_scroll`

**File:** `cmd-ui.c`
**Purpose:** Scroll a UIScrollView by a delta.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `address` | string | no | -- | Address of UIScrollView (hex). If omitted, finds first scrollable view. |
| `dx` | string | yes | -- | Horizontal scroll delta (points, positive = right). |
| `dy` | string | yes | -- | Vertical scroll delta (points, positive = down). |

**Response `data`:**
```json
{
  "scrolled": true,
  "scroll_view_class": "UITableView",
  "content_offset": {"x": 0.0, "y": 320.0},
  "content_size": {"w": 375.0, "h": 2400.0}
}
```

**Example:**
```
-> {"id":22,"cmd":"ui_scroll","args":{"dy":"300"}}
<- {"id":22,"ok":true,"data":{"scrolled":true,"scroll_view_class":"UITableView","content_offset":{"x":0.0,"y":320.0},"content_size":{"w":375.0,"h":2400.0}}}
```

**Notes:**
- Calls `setContentOffset:animated:` with `animated:YES` for natural scrolling.
- `dx` and `dy` are strings parsed to float (JSON parser limitation).
- Error if no UIScrollView found at address or in hierarchy.

---

### 19. `ui_back`

**File:** `cmd-ui.c`
**Purpose:** Navigate back -- pop navigation or dismiss presented controller.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "action": "pop",
  "from_class": "SettingsViewController",
  "to_class": "MainViewController"
}
```

**Example:**
```
-> {"id":23,"cmd":"ui_back","args":{}}
<- {"id":23,"ok":true,"data":{"action":"pop","from_class":"SettingsViewController","to_class":"MainViewController"}}
```

**Notes:**
- Strategy: first try `[navigationController popViewControllerAnimated:YES]`. If no nav controller, try `[presentedViewController dismissViewControllerAnimated:YES completion:nil]`.
- `action` is `"pop"` for navigation pop, `"dismiss"` for modal dismiss, `"none"` if no back action was possible.
- Dispatches to main thread.

---

### 20. `stealth_scan`

**File:** `cmd-analysis.c` (detection analysis) / `stealth/sphinx-stealth.c` (bypass implementation)
**Purpose:** Detect anti-analysis mechanisms in the running app.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "detections": [
    {
      "technique": "jailbreak_file_check",
      "description": "Checks for /Applications/Cydia.app via NSFileManager",
      "library": "iXGuard",
      "confidence": "high",
      "class": "SecurityChecker",
      "method": "isDeviceCompromised"
    },
    {
      "technique": "debugger_detection",
      "description": "Calls sysctl to check P_TRACED flag",
      "library": "custom",
      "confidence": "medium",
      "class": "",
      "method": ""
    }
  ],
  "risk_level": "high",
  "total_detections": 2
}
```

**Example:**
```
-> {"id":24,"cmd":"stealth_scan","args":{}}
<- {"id":24,"ok":true,"data":{"detections":[{"technique":"jailbreak_file_check","description":"Checks for /Applications/Cydia.app","library":"iXGuard","confidence":"high","class":"SecurityChecker","method":"isDeviceCompromised"}],"risk_level":"high","total_detections":1}}
```

**Notes:**
- Detection strategies: scan class names for known libraries (iXGuard, DexProtector, Arxan, Promon), check for known jailbreak-detection method selectors, scan strings for jailbreak artifact paths.
- `confidence`: `"high"` (known detection pattern), `"medium"` (heuristic match), `"low"` (possible false positive).
- `risk_level`: overall assessment (`"none"`, `"low"`, `"medium"`, `"high"`).
- This is read-only analysis. Use `stealth_enable` to activate bypasses.

---

### 21. `stealth_enable`

**File:** `cmd-analysis.c` + `stealth/sphinx-stealth.c`
**Purpose:** Activate anti-detection evasion hooks.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `techniques` | string | no | `"all"` | Comma-separated list of techniques to enable, or `"all"`. |

**Valid technique names:** `"jailbreak"`, `"debugger"`, `"dyld_hiding"`, `"fork_check"`, `"integrity"`, `"all"`.

**Response `data`:**
```json
{
  "active_bypasses": ["jailbreak", "debugger", "dyld_hiding", "fork_check"],
  "total_active": 4
}
```

**Example:**
```
-> {"id":25,"cmd":"stealth_enable","args":{"techniques":"jailbreak,debugger"}}
<- {"id":25,"ok":true,"data":{"active_bypasses":["jailbreak","debugger"],"total_active":2}}
```

**Notes:**
- `jailbreak`: hooks `NSFileManager fileExistsAtPath:`, `stat()`, `access()`, `open()` for known jailbreak paths.
- `debugger`: hooks `sysctl()` to hide P_TRACED, makes `ptrace(PT_DENY_ATTACH)` a no-op.
- `dyld_hiding`: hooks `_dyld_image_count()` and `_dyld_get_image_name()` to filter sphinx dylibs.
- `fork_check`: hooks `fork()` to return -1.
- `integrity`: hooks `CC_SHA256` etc. to return expected hashes when app checks its own binary.
- Techniques are idempotent -- enabling an already-active technique is a no-op.
- `techniques` is a single string (comma-separated), not a JSON array, due to the minimal JSON parser.

---

### 22. `stealth_status`

**File:** `cmd-analysis.c`
**Purpose:** Report which stealth bypasses are active and their intercept counts.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "bypasses": [
    {"technique": "jailbreak", "active": true, "intercept_count": 47},
    {"technique": "debugger", "active": true, "intercept_count": 3},
    {"technique": "dyld_hiding", "active": false, "intercept_count": 0},
    {"technique": "fork_check", "active": false, "intercept_count": 0},
    {"technique": "integrity", "active": false, "intercept_count": 0}
  ]
}
```

**Example:**
```
-> {"id":26,"cmd":"stealth_status","args":{}}
<- {"id":26,"ok":true,"data":{"bypasses":[{"technique":"jailbreak","active":true,"intercept_count":47},{"technique":"debugger","active":true,"intercept_count":3}]}}
```

---

## Sprint 13.5 -- Deep Analysis

### 23. `webview_list`

**File:** `cmd-ui.c`
**Purpose:** Find all WKWebView instances and their configuration.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "webviews": [
    {
      "address": "0x7fc12345abc0",
      "url": "https://app.example.com/dashboard",
      "title": "Dashboard",
      "loading": false,
      "bridge_handlers": ["nativeCallback", "logEvent", "getAuthToken"],
      "user_scripts_count": 2,
      "allows_javascript": true
    }
  ],
  "total": 1
}
```

**Example:**
```
-> {"id":27,"cmd":"webview_list","args":{}}
<- {"id":27,"ok":true,"data":{"webviews":[{"address":"0x7fc12345abc0","url":"https://app.example.com/dashboard","title":"Dashboard","loading":false,"bridge_handlers":["nativeCallback","logEvent"],"user_scripts_count":2,"allows_javascript":true}],"total":1}}
```

**Notes:**
- Finds WKWebView instances by walking the view hierarchy (not heap enumeration -- more reliable for UI-attached views).
- Bridge handlers extracted from `WKWebViewConfiguration userContentController` via `_scriptMessageHandlers` (private API) or known handler registration.
- `allows_javascript` from `WKWebViewConfiguration.preferences.javaScriptEnabled`.
- For non-visible WebViews (e.g., background data loading), requires `heap_dump` with class `"WKWebView"`.

---

### 24. `webview_eval`

**File:** `cmd-ui.c`
**Purpose:** Execute JavaScript in a specific WKWebView.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `address` | string | yes | -- | Address of WKWebView instance (hex). |
| `js` | string | yes | -- | JavaScript code to evaluate. |

**Response `data`:**
```json
{
  "result": "document.cookie value here",
  "result_type": "string"
}
```

**Example:**
```
-> {"id":28,"cmd":"webview_eval","args":{"address":"0x7fc12345abc0","js":"document.cookie"}}
<- {"id":28,"ok":true,"data":{"result":"session=abc123; csrf=xyz789","result_type":"string"}}

-> {"id":29,"cmd":"webview_eval","args":{"address":"0x7fc12345abc0","js":"JSON.stringify(Array.from(document.querySelectorAll('input')).map(i => ({name: i.name, type: i.type, value: i.value})))"}}
<- {"id":29,"ok":true,"data":{"result":"[{\"name\":\"email\",\"type\":\"text\",\"value\":\"user@example.com\"}]","result_type":"string"}}
```

**Notes:**
- Calls `[webView evaluateJavaScript:js completionHandler:^(id result, NSError *error) {...}]`.
- Dispatches to main thread, blocks bridge thread until completion handler fires (with 10s timeout).
- `result_type`: `"string"`, `"number"`, `"boolean"`, `"null"`, `"object"` (JSON-serialized), `"error"`.
- Results truncated at 8192 characters.
- Validates that `address` points to a valid WKWebView before calling.

---

### 25. `webview_content`

**File:** `cmd-ui.c`
**Purpose:** Get the full HTML content of a WKWebView.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `address` | string | yes | -- | Address of WKWebView instance (hex). |

**Response `data`:**
```json
{
  "html": "<!DOCTYPE html><html><head>...",
  "url": "https://app.example.com/dashboard",
  "truncated": false
}
```

**Example:**
```
-> {"id":30,"cmd":"webview_content","args":{"address":"0x7fc12345abc0"}}
<- {"id":30,"ok":true,"data":{"html":"<!DOCTYPE html><html>...","url":"https://app.example.com/dashboard","truncated":false}}
```

**Notes:**
- Internally calls `webview_eval` with `document.documentElement.outerHTML`.
- HTML truncated at 512 KB. Set `truncated: true` if truncation occurred.

---

### 26. `inject_class`

**File:** `cmd-inject.c`
**Purpose:** Create a new ObjC class at runtime.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | -- | Name for the new class. |
| `superclass` | string | no | `"NSObject"` | Superclass name. |
| `protocols` | string | no | `""` | Comma-separated protocol names to adopt. |

**Response `data`:**
```json
{
  "created": true,
  "name": "SphinxFakeDelegate",
  "superclass": "NSObject",
  "protocols": ["UIApplicationDelegate"],
  "address": "0x7fc1234def00"
}
```

**Example:**
```
-> {"id":31,"cmd":"inject_class","args":{"name":"SphinxFakeDelegate","superclass":"NSObject","protocols":"UIApplicationDelegate,UINavigationControllerDelegate"}}
<- {"id":31,"ok":true,"data":{"created":true,"name":"SphinxFakeDelegate","superclass":"NSObject","protocols":["UIApplicationDelegate","UINavigationControllerDelegate"],"address":"0x7fc1234def00"}}
```

**Notes:**
- Uses `objc_allocateClassPair()`, `class_addProtocol()`, `objc_registerClassPair()`.
- `protocols` is a comma-separated string (not JSON array) due to minimal parser.
- Error if class name already exists, superclass not found, or protocol not found.
- Class persists for the process lifetime after creation. No "undo."

---

### 27. `inject_method`

**File:** `cmd-inject.c`
**Purpose:** Add a method to an existing class with a pre-built implementation.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `class` | string | yes | -- | Target class name. |
| `selector` | string | yes | -- | Selector to add (e.g., `"application:didFinishLaunchingWithOptions:"`). |
| `implementation` | string | yes | -- | Implementation from the catalog (see below). |
| `type_encoding` | string | no | `"v@:"` | ObjC type encoding for the method signature. |

**Implementation catalog:**
| Name | Behavior |
|------|----------|
| `"log_and_return_yes"` | Logs invocation, returns YES. |
| `"log_and_return_no"` | Logs invocation, returns NO. |
| `"log_and_return_nil"` | Logs invocation, returns nil. |
| `"log_all_args"` | Logs invocation with all arguments (uses trace infrastructure). |
| `"noop"` | Does nothing, returns void. |

**Response `data`:**
```json
{
  "added": true,
  "class": "SphinxFakeDelegate",
  "selector": "application:didFinishLaunchingWithOptions:",
  "implementation": "log_and_return_yes"
}
```

**Example:**
```
-> {"id":32,"cmd":"inject_method","args":{"class":"SphinxFakeDelegate","selector":"application:didFinishLaunchingWithOptions:","implementation":"log_and_return_yes","type_encoding":"B@:@@"}}
<- {"id":32,"ok":true,"data":{"added":true,"class":"SphinxFakeDelegate","selector":"application:didFinishLaunchingWithOptions:","implementation":"log_and_return_yes"}}
```

**Notes:**
- Uses `class_addMethod()`. Error if method already exists on the class (use swizzle to replace).
- The implementation catalog is a set of C functions compiled into the bridge. No arbitrary code injection.
- `type_encoding` is critical for the ObjC runtime to call the method correctly. Defaults to `"v@:"` (void, self, _cmd) if not specified.

---

### 28. `replace_delegate`

**File:** `cmd-inject.c`
**Purpose:** Replace an object's delegate with a new (typically injected) class instance.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `object_address` | string | yes | -- | Address of the object whose delegate to replace (hex). |
| `property` | string | no | `"delegate"` | The delegate property name. |
| `new_class` | string | yes | -- | Class to instantiate and set as delegate. |

**Response `data`:**
```json
{
  "replaced": true,
  "original_class": "AppDelegate",
  "new_class": "SphinxFakeDelegate",
  "new_address": "0x7fc1234abc00"
}
```

**Example:**
```
-> {"id":33,"cmd":"replace_delegate","args":{"object_address":"0x7fc1234def00","new_class":"SphinxFakeDelegate"}}
<- {"id":33,"ok":true,"data":{"replaced":true,"original_class":"AppDelegate","new_class":"SphinxFakeDelegate","new_address":"0x7fc1234abc00"}}
```

**Notes:**
- Validates that the object at `object_address` is a valid ObjC object.
- Creates a new instance of `new_class` via `[[NewClass alloc] init]`.
- Sets the delegate via `[object setValue:newDelegate forKey:property]`.
- Returns the original delegate class name for potential restoration.

---

### 29. `entitlement_scan`

**File:** `cmd-analysis.c`
**Purpose:** Extract entitlements from the main binary and all loaded images.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "images": [
    {
      "name": "AppName",
      "path": "/path/to/AppName.app/AppName",
      "entitlements": {
        "com.apple.security.application-groups": ["group.com.company.shared"],
        "keychain-access-groups": ["TEAMID.com.company.app"],
        "com.apple.developer.associated-domains": ["applinks:example.com"]
      },
      "risk_flags": ["shared_app_group", "associated_domains"]
    }
  ],
  "shared_containers": [
    {"group": "group.com.company.shared", "path": "/path/to/group/container", "exists": true}
  ],
  "total_images_scanned": 42,
  "total_with_entitlements": 1
}
```

**Example:**
```
-> {"id":34,"cmd":"entitlement_scan","args":{}}
<- {"id":34,"ok":true,"data":{"images":[{"name":"AppName","path":"/path","entitlements":{"keychain-access-groups":["TEAMID.com.company.app"]},"risk_flags":["shared_app_group"]}],"shared_containers":[],"total_images_scanned":42,"total_with_entitlements":1}}
```

**Notes:**
- Parses LC_CODE_SIGNATURE from Mach-O headers via `_dyld_get_image_header()`.
- Finds the embedded entitlements blob (magic `0xFADE7171`) within the code signature superblob.
- Also calls `SecTaskCopyValueForEntitlement` for runtime entitlement checking.
- Risk flags: `"shared_app_group"` (cross-app data access), `"associated_domains"` (web credential sharing), `"icloud_container"` (cloud data access), `"push_production"` (production push certs), `"keychain_shared"` (shared keychain).
- `shared_containers`: checks if the group container directory exists and is readable.

---

### 30. `pin_analyze`

**File:** `cmd-forensics.c`
**Purpose:** Detect and analyze certificate pinning in the running app.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "pinned_hosts": [
    {
      "host": "api.example.com",
      "pin_type": "public_key_hash",
      "pin_values": ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
      "library": "TrustKit",
      "bypass_status": "bypassed"
    }
  ],
  "certificates": [
    {
      "subject": "CN=api.example.com",
      "issuer": "CN=Let's Encrypt Authority X3",
      "sha256": "b5bb9d8014a0f9b1d61e21e796d78dcc..."
    }
  ],
  "ats_config": {
    "allows_arbitrary_loads": false,
    "exception_domains": ["legacy.example.com"]
  }
}
```

**Example:**
```
-> {"id":35,"cmd":"pin_analyze","args":{}}
<- {"id":35,"ok":true,"data":{"pinned_hosts":[{"host":"api.example.com","pin_type":"public_key_hash","pin_values":["sha256/AAA..."],"library":"TrustKit","bypass_status":"bypassed"}],"certificates":[],"ats_config":{"allows_arbitrary_loads":false}}}
```

**Notes:**
- Hooks `SecTrustEvaluateWithError`, `URLSession:didReceiveChallenge:completionHandler:` at scan time.
- Scans for TrustKit config in UserDefaults and class presence.
- Reads ATS configuration from `Info.plist` via `NSBundle`.
- Extracts certificates via `SecTrustGetCertificateAtIndex` + `SecCertificateCopyData`.
- `bypass_status`: `"bypassed"` (sphinx-ssl.dylib active), `"not_bypassed"`, `"untested"`.

---

### 31. `pin_extract`

**File:** `cmd-forensics.c`
**Purpose:** Extract raw certificate data from the trust chain.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `host` | string | no | `""` | Filter by hostname. Empty = return all captured certs. |
| `index` | int | no | `-1` | Specific certificate index. `-1` = all. |

**Response `data`:**
```json
{
  "certificates": [
    {
      "index": 0,
      "host": "api.example.com",
      "subject": "CN=api.example.com",
      "issuer": "CN=Let's Encrypt Authority X3",
      "der_base64": "MIIFazCCA1OgAwIBAgIR...",
      "public_key_hash": "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  ],
  "total": 1
}
```

**Example:**
```
-> {"id":36,"cmd":"pin_extract","args":{"host":"api.example.com"}}
<- {"id":36,"ok":true,"data":{"certificates":[{"index":0,"host":"api.example.com","subject":"CN=api.example.com","issuer":"CN=Let's Encrypt Authority X3","der_base64":"MIIF...","public_key_hash":"sha256/AAA..."}],"total":1}}
```

**Notes:**
- Certificates must be captured first (by triggering network requests to pinned hosts, or by `pin_analyze`).
- `der_base64` is the full DER-encoded certificate, base64-encoded. Can be decoded offline.
- Public key hash: SHA256 of the SubjectPublicKeyInfo, base64-encoded (same format TrustKit uses).

---

## Sprint 13.6 -- Advanced

### 32. `block_inspect`

**File:** `cmd-analysis.c`
**Purpose:** Introspect an ObjC block object's internal structure.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `address` | string | yes | -- | Address of the block object (hex). |

**Response `data`:**
```json
{
  "isa_type": "_NSConcreteMallocBlock",
  "flags": 1342177280,
  "flags_decoded": ["BLOCK_HAS_COPY_DISPOSE", "BLOCK_HAS_SIGNATURE"],
  "invoke": "0x100012340",
  "invoke_symbol": "-[AuthManager loginWithCompletion:]_block_invoke",
  "size": 48,
  "signature": "v8@?0",
  "signature_decoded": "void (^)()",
  "captured_vars_preview": "0x7fc1234abc00 (NSString: \"eyJhbG...\"), 0x0000000000000001 (int: 1)"
}
```

**Example:**
```
-> {"id":37,"cmd":"block_inspect","args":{"address":"0x600001234560"}}
<- {"id":37,"ok":true,"data":{"isa_type":"_NSConcreteMallocBlock","flags":1342177280,"flags_decoded":["BLOCK_HAS_COPY_DISPOSE","BLOCK_HAS_SIGNATURE"],"invoke":"0x100012340","invoke_symbol":"-[AuthManager loginWithCompletion:]_block_invoke","size":48,"signature":"v8@?0","signature_decoded":"void (^)()","captured_vars_preview":"0x7fc1234abc00 (NSString: \"eyJhbG...\"), 0x0000000000000001 (int: 1)"}}
```

**Notes:**
- Block layout: isa (8 bytes), flags (4), reserved (4), invoke (8), descriptor (8), then captured variables.
- `invoke_symbol` resolved via `dladdr()`.
- Signature extracted from descriptor if `BLOCK_HAS_SIGNATURE` flag is set.
- Captured variables are heuristically decoded: test each pointer-sized slot with `is_valid_objc_ptr()`, format as ObjC object if valid, otherwise as raw hex/integer.
- Complex internals -- 350+ lines estimated. High risk of false positives in captured variable decoding.

---

### 33. `proto_decode`

**File:** `cmd-analysis.c`
**Purpose:** Decode Protocol Buffer (and other binary serialization) data.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `data` | string | yes | -- | The binary data to decode. |
| `format` | string | no | `"hex"` | Input encoding: `"hex"` or `"base64"`. |

**Response `data`:**
```json
{
  "fields": [
    {"field_num": 1, "wire_type": 2, "wire_type_name": "length_delimited", "value": "Hello World"},
    {"field_num": 2, "wire_type": 0, "wire_type_name": "varint", "value": 42},
    {
      "field_num": 3, "wire_type": 2, "wire_type_name": "length_delimited",
      "nested": [
        {"field_num": 1, "wire_type": 2, "wire_type_name": "length_delimited", "value": "user@example.com"},
        {"field_num": 2, "wire_type": 0, "wire_type_name": "varint", "value": 1711382400}
      ]
    }
  ],
  "bytes_consumed": 64,
  "decode_format": "protobuf"
}
```

**Example:**
```
-> {"id":38,"cmd":"proto_decode","args":{"data":"0a0b48656c6c6f20576f726c641002","format":"hex"}}
<- {"id":38,"ok":true,"data":{"fields":[{"field_num":1,"wire_type":2,"wire_type_name":"length_delimited","value":"Hello World"},{"field_num":2,"wire_type":0,"wire_type_name":"varint","value":2}],"bytes_consumed":17,"decode_format":"protobuf"}}
```

**Notes:**
- Protobuf wire format decoder: varint, 32-bit, 64-bit, length-delimited.
- Length-delimited fields: try UTF-8 string first, then try recursive protobuf decode (nested message), fall back to hex dump.
- Wire type names: `"varint"` (0), `"fixed64"` (1), `"length_delimited"` (2), `"fixed32"` (5).
- Does not require .proto schema -- pure wire format parsing.
- Very high complexity (~800 lines). First pass: protobuf only. MessagePack/CBOR deferred.
- If decoding fails, returns error with byte position of failure.

---

### 34. `sdk_map`

**File:** `cmd-analysis.c`
**Purpose:** Identify third-party SDKs and their configuration.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "sdks": [
    {
      "name": "Firebase",
      "version": "10.12.0",
      "confidence": "high",
      "classes": ["FIRApp", "FIRAnalytics", "FIRCrashlytics"],
      "image": "GoogleUtilities",
      "keys": {
        "API_KEY": "AIzaSyC...",
        "GCM_SENDER_ID": "123456789",
        "PROJECT_ID": "my-firebase-project"
      }
    },
    {
      "name": "Mixpanel",
      "version": "unknown",
      "confidence": "medium",
      "classes": ["Mixpanel", "MPTweakStore"],
      "image": "Mixpanel",
      "keys": {
        "token": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
      }
    }
  ],
  "total_images": 87,
  "total_sdks_identified": 2
}
```

**Example:**
```
-> {"id":39,"cmd":"sdk_map","args":{}}
<- {"id":39,"ok":true,"data":{"sdks":[{"name":"Firebase","version":"10.12.0","confidence":"high","classes":["FIRApp","FIRAnalytics"],"image":"GoogleUtilities","keys":{"API_KEY":"AIzaSyC..."}}],"total_images":87,"total_sdks_identified":1}}
```

**Notes:**
- Enumerate loaded images via `_dyld_image_count()` and `_dyld_get_image_name()`.
- SDK fingerprint database (compiled in): class prefix -> SDK name mapping. Examples: `FIR*` = Firebase, `AMP*` = Amplitude, `MPT*` = Mixpanel, `ABK*` = Braze, `ADJ*` = Adjust, `BNC*` = Branch, `FBSDK*` = Facebook SDK.
- Key extraction: call known accessors for identified SDKs (e.g., `[[FIRApp defaultApp] options].APIKey`).
- Version detection: from dylib LC_ID_DYLIB version, SDK class version methods, or Info.plist values.
- `confidence`: `"high"` (class prefix + accessor confirmed), `"medium"` (class prefix only), `"low"` (heuristic).

---

### 35. `sdk_keys`

**File:** `cmd-analysis.c`
**Purpose:** Return extracted SDK credentials (convenience view of `sdk_map` keys).

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| (none) | -- | -- | -- | No arguments required. |

**Response `data`:**
```json
{
  "credentials": [
    {"sdk": "Firebase", "key_name": "API_KEY", "value": "AIzaSyC...", "source": "FIROptions.APIKey"},
    {"sdk": "Firebase", "key_name": "GCM_SENDER_ID", "value": "123456789", "source": "FIROptions.GCMSenderID"},
    {"sdk": "Mixpanel", "key_name": "token", "value": "a1b2c3d4...", "source": "Mixpanel.apiToken"}
  ],
  "total": 3
}
```

**Example:**
```
-> {"id":40,"cmd":"sdk_keys","args":{}}
<- {"id":40,"ok":true,"data":{"credentials":[{"sdk":"Firebase","key_name":"API_KEY","value":"AIzaSyC...","source":"FIROptions.APIKey"}],"total":1}}
```

**Notes:**
- Flat list of all credentials extracted by `sdk_map`, presented for easy consumption.
- `source` describes how the credential was obtained (property accessor, UserDefaults key, memory pattern match).

---

### 36. `mem_forensics`

**File:** `cmd-forensics.c`
**Purpose:** Scan freed memory for recoverable sensitive data.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `patterns` | string | no | `""` | Comma-separated search patterns (e.g., `"eyJ,Bearer,password"`). Empty = use defaults. |
| `limit` | int | no | `100` | Max findings to return. |

**Default patterns:** `"eyJ"` (JWT), `"Bearer "`, `"Basic "`, `"password"`, `"token"`, `"secret"`, `"https://"`, `"apikey"`, `"-----BEGIN"`.

**Response `data`:**
```json
{
  "findings": [
    {
      "address": "0x600001234560",
      "zone": "DefaultMallocZone",
      "block_size": 256,
      "pattern_matched": "eyJ",
      "preview": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY...",
      "context": "freed_block"
    }
  ],
  "zones_scanned": 3,
  "blocks_scanned": 45000,
  "scan_time_ms": 890,
  "total_findings": 1
}
```

**Example:**
```
-> {"id":41,"cmd":"mem_forensics","args":{"patterns":"eyJ,Bearer","limit":50}}
<- {"id":41,"ok":true,"data":{"findings":[{"address":"0x600001234560","zone":"DefaultMallocZone","block_size":256,"pattern_matched":"eyJ","preview":"eyJhbGciOiJSUzI1NiIs...","context":"freed_block"}],"zones_scanned":3,"blocks_scanned":45000,"scan_time_ms":890,"total_findings":1}}
```

**Notes:**
- Walks freed blocks in malloc zones. High risk of instability -- must not crash the app.
- `patterns` is a comma-separated string (not JSON array).
- Preview: up to 256 bytes of context around the pattern match, as UTF-8 text (non-printable bytes replaced with `.`).
- `context`: `"freed_block"` (deallocated), `"live_block"` (still allocated, pattern found in non-object data).
- Scan is expensive -- may take 500ms+ for large heaps. Timeout at 5 seconds.

---

### 37. `mem_snapshot`

**File:** `cmd-forensics.c`
**Purpose:** Take a labeled heap snapshot for later comparison.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `label` | string | no | `""` | Human-readable label for this snapshot. |

**Response `data`:**
```json
{
  "snapshot_id": "snap_001",
  "label": "before_login",
  "total_objects": 48291,
  "total_bytes": 12582912,
  "top_classes": [
    {"class": "NSString", "count": 12000, "bytes": 384000},
    {"class": "NSDictionary", "count": 3400, "bytes": 272000}
  ],
  "timestamp": "2026-03-25T14:30:00.000"
}
```

**Example:**
```
-> {"id":42,"cmd":"mem_snapshot","args":{"label":"before_login"}}
<- {"id":42,"ok":true,"data":{"snapshot_id":"snap_001","label":"before_login","total_objects":48291,"total_bytes":12582912,"top_classes":[{"class":"NSString","count":12000,"bytes":384000}],"timestamp":"2026-03-25T14:30:00.000"}}
```

**Notes:**
- Snapshots stored in-memory (max 10 snapshots, oldest evicted). Stores class -> count/size mappings, not individual objects.
- `snapshot_id` is auto-generated: `"snap_001"`, `"snap_002"`, etc.
- `top_classes` returns top 20 classes by byte count.
- Uses the same heap walking infrastructure as `heap_dump`.

---

### 38. `mem_diff`

**File:** `cmd-forensics.c`
**Purpose:** Compare two heap snapshots.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `a` | string | yes | -- | First snapshot ID (e.g., `"snap_001"`). |
| `b` | string | yes | -- | Second snapshot ID (e.g., `"snap_002"`). |

**Response `data`:**
```json
{
  "added": [
    {"class": "NSURLCredential", "count_delta": 2, "bytes_delta": 128},
    {"class": "NSHTTPURLResponse", "count_delta": 5, "bytes_delta": 640}
  ],
  "removed": [
    {"class": "UIAlertController", "count_delta": -1, "bytes_delta": -512}
  ],
  "changed": [
    {"class": "NSString", "count_a": 12000, "count_b": 12450, "count_delta": 450, "bytes_delta": 14400}
  ],
  "summary": {
    "total_objects_a": 48291,
    "total_objects_b": 49100,
    "total_bytes_a": 12582912,
    "total_bytes_b": 13107200
  }
}
```

**Example:**
```
-> {"id":43,"cmd":"mem_diff","args":{"a":"snap_001","b":"snap_002"}}
<- {"id":43,"ok":true,"data":{"added":[{"class":"NSURLCredential","count_delta":2,"bytes_delta":128}],"removed":[],"changed":[{"class":"NSString","count_a":12000,"count_b":12450,"count_delta":450,"bytes_delta":14400}],"summary":{"total_objects_a":48291,"total_objects_b":49100,"total_bytes_a":12582912,"total_bytes_b":13107200}}}
```

**Notes:**
- `added`: classes present in B but not A (or count increased).
- `removed`: classes present in A but not B (or count decreased).
- `changed`: classes present in both with different counts (above a threshold of 5% change).
- Error if either snapshot ID not found.

---

### 39. `timing_probe`

**File:** `cmd-forensics.c`
**Purpose:** Measure method execution time with nanosecond precision.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `class` | string | yes | -- | ObjC class name. |
| `method` | string | yes | -- | Selector name. |
| `iterations` | int | yes | -- | Number of iterations to run. |
| `warmup` | int | no | `5` | Warmup iterations to discard. |

**Response `data`:**
```json
{
  "class": "AuthManager",
  "method": "validatePassword:",
  "iterations": 100,
  "warmup_discarded": 5,
  "mean_ns": 45230,
  "median_ns": 43100,
  "stddev_ns": 8200,
  "min_ns": 32000,
  "max_ns": 112000,
  "constant_time": true,
  "cv_percent": 18.1
}
```

**Example:**
```
-> {"id":44,"cmd":"timing_probe","args":{"class":"AuthManager","method":"validatePassword:","iterations":"100"}}
<- {"id":44,"ok":true,"data":{"class":"AuthManager","method":"validatePassword:","iterations":100,"warmup_discarded":5,"mean_ns":45230,"median_ns":43100,"stddev_ns":8200,"min_ns":32000,"max_ns":112000,"constant_time":true,"cv_percent":18.1}}
```

**Notes:**
- Uses `mach_absolute_time()` for nanosecond-precision monotonic timing.
- Calls the method N+warmup times. First `warmup` calls are discarded.
- `constant_time`: heuristic -- true if coefficient of variation (CV) < 20%.
- `cv_percent`: coefficient of variation (stddev / mean * 100).
- **Limitation:** This version calls the method with no arguments (only methods with signature `v@:` or similar). Argument-aware timing is deferred to `timing_compare`.
- `iterations` parsed as string via `json_get_string` then `atol()`.

---

### 40. `timing_compare`

**File:** `cmd-forensics.c`
**Purpose:** Compare timing of a method with two different argument sets to detect timing side-channels.

**Args:**
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `class` | string | yes | -- | ObjC class name. |
| `method` | string | yes | -- | Selector name. |
| `arg_a` | string | yes | -- | First argument value (string, passed as NSString). |
| `arg_b` | string | yes | -- | Second argument value. |
| `iterations` | int | yes | -- | Iterations per argument set. |

**Response `data`:**
```json
{
  "class": "AuthManager",
  "method": "validatePassword:",
  "iterations": 1000,
  "result_a": {
    "arg": "valid_password",
    "mean_ns": 125000,
    "median_ns": 121000,
    "stddev_ns": 15000
  },
  "result_b": {
    "arg": "wrong_password",
    "mean_ns": 43000,
    "median_ns": 41000,
    "stddev_ns": 8000
  },
  "differential_ns": 82000,
  "differential_percent": 190.7,
  "significant": true,
  "p_value_approx": 0.0001
}
```

**Example:**
```
-> {"id":45,"cmd":"timing_compare","args":{"class":"AuthManager","method":"validatePassword:","arg_a":"correct_pw","arg_b":"wrong_pw","iterations":"500"}}
<- {"id":45,"ok":true,"data":{"class":"AuthManager","method":"validatePassword:","iterations":500,"result_a":{"arg":"correct_pw","mean_ns":125000,"median_ns":121000,"stddev_ns":15000},"result_b":{"arg":"wrong_pw","mean_ns":43000,"median_ns":41000,"stddev_ns":8000},"differential_ns":82000,"differential_percent":190.7,"significant":true,"p_value_approx":0.0001}}
```

**Notes:**
- Runs A and B interleaved (not sequentially) to minimize environmental bias.
- Arguments passed as NSString via `objc_msgSend`. Only supports methods taking a single NSString argument.
- `significant`: true if the timing difference is statistically significant (Welch's t-test, p < 0.05).
- `p_value_approx`: approximate p-value from simplified t-test.
- This is side-channel analysis -- detects password oracles, account enumeration, etc.

---

## Command Summary Table

| # | Command | Sprint | File | Category |
|---|---------|--------|------|----------|
| 1 | `heap_dump` | 13.1 | cmd-recon.c | Recon |
| 2 | `event_tap` | 13.1 | cmd-events.c | Events |
| 3 | `env_dump` | 13.1 | cmd-recon.c | Recon |
| 4 | `db_inject` | 13.1 | cmd-inject.c | Injection |
| 5 | `db_queries` | 13.1 | cmd-inject.c | Injection |
| 6 | `net_tap` | 13.2 | cmd-network.c | Network |
| 7 | `net_filter` | 13.2 | cmd-network.c | Network |
| 8 | `crypto_tap` | 13.2 | cmd-network.c | Network |
| 9 | `crypto_keys` | 13.2 | cmd-network.c | Network |
| 10 | `auth_tap` | 13.2 | cmd-network.c | Network |
| 11 | `auth_tokens` | 13.2 | cmd-network.c | Network |
| 12 | `trace` | 13.3 | cmd-trace.c | Tracing |
| 13 | `trace_class` | 13.3 | cmd-trace.c | Tracing |
| 14 | `trace_log` | 13.3 | cmd-trace.c | Tracing |
| 15 | `untrace` | 13.3 | cmd-trace.c | Tracing |
| 16 | `ui_tap` | 13.4 | cmd-ui.c | UI |
| 17 | `ui_type` | 13.4 | cmd-ui.c | UI |
| 18 | `ui_scroll` | 13.4 | cmd-ui.c | UI |
| 19 | `ui_back` | 13.4 | cmd-ui.c | UI |
| 20 | `stealth_scan` | 13.4 | cmd-analysis.c | Stealth |
| 21 | `stealth_enable` | 13.4 | cmd-analysis.c | Stealth |
| 22 | `stealth_status` | 13.4 | cmd-analysis.c | Stealth |
| 23 | `webview_list` | 13.5 | cmd-ui.c | WebView |
| 24 | `webview_eval` | 13.5 | cmd-ui.c | WebView |
| 25 | `webview_content` | 13.5 | cmd-ui.c | WebView |
| 26 | `inject_class` | 13.5 | cmd-inject.c | Injection |
| 27 | `inject_method` | 13.5 | cmd-inject.c | Injection |
| 28 | `replace_delegate` | 13.5 | cmd-inject.c | Injection |
| 29 | `entitlement_scan` | 13.5 | cmd-analysis.c | Analysis |
| 30 | `pin_analyze` | 13.5 | cmd-forensics.c | Analysis |
| 31 | `pin_extract` | 13.5 | cmd-forensics.c | Analysis |
| 32 | `block_inspect` | 13.6 | cmd-analysis.c | Analysis |
| 33 | `proto_decode` | 13.6 | cmd-analysis.c | Analysis |
| 34 | `sdk_map` | 13.6 | cmd-analysis.c | Analysis |
| 35 | `sdk_keys` | 13.6 | cmd-analysis.c | Analysis |
| 36 | `mem_forensics` | 13.6 | cmd-forensics.c | Forensics |
| 37 | `mem_snapshot` | 13.6 | cmd-forensics.c | Forensics |
| 38 | `mem_diff` | 13.6 | cmd-forensics.c | Forensics |
| 39 | `timing_probe` | 13.6 | cmd-forensics.c | Forensics |
| 40 | `timing_compare` | 13.6 | cmd-forensics.c | Forensics |

---

## Dispatcher Registration

Each new command must be registered in `sphinx-bridge.c` `dispatch_command()`. Expected additions:

```c
/* Sprint 13.1 -- Foundation */
else if (strcmp(cmd, "heap_dump") == 0)        cmd_heap_dump(request, &r);
else if (strcmp(cmd, "event_tap") == 0)        cmd_event_tap(request, &r);
else if (strcmp(cmd, "env_dump") == 0)         cmd_env_dump(request, &r);
else if (strcmp(cmd, "db_inject") == 0)        cmd_db_inject(request, &r);
else if (strcmp(cmd, "db_queries") == 0)       cmd_db_queries(request, &r);

/* Sprint 13.2 -- Network Intelligence */
else if (strcmp(cmd, "net_tap") == 0)          cmd_net_tap(request, &r);
else if (strcmp(cmd, "net_filter") == 0)       cmd_net_filter(request, &r);
else if (strcmp(cmd, "crypto_tap") == 0)       cmd_crypto_tap(request, &r);
else if (strcmp(cmd, "crypto_keys") == 0)      cmd_crypto_keys(request, &r);
else if (strcmp(cmd, "auth_tap") == 0)         cmd_auth_tap(request, &r);
else if (strcmp(cmd, "auth_tokens") == 0)      cmd_auth_tokens(request, &r);

/* Sprint 13.3 -- Trampoline */
else if (strcmp(cmd, "trace") == 0)            cmd_trace(request, &r);
else if (strcmp(cmd, "trace_class") == 0)      cmd_trace_class(request, &r);
else if (strcmp(cmd, "trace_log") == 0)        cmd_trace_log(request, &r);
else if (strcmp(cmd, "untrace") == 0)          cmd_untrace(request, &r);

/* Sprint 13.4 -- Active */
else if (strcmp(cmd, "ui_tap") == 0)           cmd_ui_tap(request, &r);
else if (strcmp(cmd, "ui_type") == 0)          cmd_ui_type(request, &r);
else if (strcmp(cmd, "ui_scroll") == 0)        cmd_ui_scroll(request, &r);
else if (strcmp(cmd, "ui_back") == 0)          cmd_ui_back(request, &r);
else if (strcmp(cmd, "stealth_scan") == 0)     cmd_stealth_scan(request, &r);
else if (strcmp(cmd, "stealth_enable") == 0)   cmd_stealth_enable(request, &r);
else if (strcmp(cmd, "stealth_status") == 0)   cmd_stealth_status(request, &r);

/* Sprint 13.5 -- Deep Analysis */
else if (strcmp(cmd, "webview_list") == 0)     cmd_webview_list(request, &r);
else if (strcmp(cmd, "webview_eval") == 0)     cmd_webview_eval(request, &r);
else if (strcmp(cmd, "webview_content") == 0)  cmd_webview_content(request, &r);
else if (strcmp(cmd, "inject_class") == 0)     cmd_inject_class(request, &r);
else if (strcmp(cmd, "inject_method") == 0)    cmd_inject_method(request, &r);
else if (strcmp(cmd, "replace_delegate") == 0) cmd_replace_delegate(request, &r);
else if (strcmp(cmd, "entitlement_scan") == 0) cmd_entitlement_scan(request, &r);
else if (strcmp(cmd, "pin_analyze") == 0)      cmd_pin_analyze(request, &r);
else if (strcmp(cmd, "pin_extract") == 0)      cmd_pin_extract(request, &r);

/* Sprint 13.6 -- Advanced */
else if (strcmp(cmd, "block_inspect") == 0)    cmd_block_inspect(request, &r);
else if (strcmp(cmd, "proto_decode") == 0)     cmd_proto_decode(request, &r);
else if (strcmp(cmd, "sdk_map") == 0)          cmd_sdk_map(request, &r);
else if (strcmp(cmd, "sdk_keys") == 0)         cmd_sdk_keys(request, &r);
else if (strcmp(cmd, "mem_forensics") == 0)    cmd_mem_forensics(request, &r);
else if (strcmp(cmd, "mem_snapshot") == 0)     cmd_mem_snapshot(request, &r);
else if (strcmp(cmd, "mem_diff") == 0)         cmd_mem_diff(request, &r);
else if (strcmp(cmd, "timing_probe") == 0)     cmd_timing_probe(request, &r);
else if (strcmp(cmd, "timing_compare") == 0)   cmd_timing_compare(request, &r);
```

---

## C Function Signatures

Every command handler follows the same pattern:

```c
static void cmd_<name>(const char *request, resp_t *r);
```

The function receives the full JSON request string and a pre-initialized `resp_t` buffer that already contains `{"id":N,"ok":true,`. The handler appends its `"data":{...}` fields. The dispatcher closes with `}\n` and sends.

For error conditions within a handler, reset the buffer and write an error response:

```c
r->len = 0;
resp_append(r, "{\"id\":%s,\"ok\":false,\"error\":\"message\"", id_str);
```

---

## JSON Parser Limitations

The minimal `json_get_string()` parser has constraints that affect the protocol:

1. **No array parsing.** Array-valued args must be passed as comma-separated strings (e.g., `"protocols":"UIApplicationDelegate,NSCoding"`).
2. **No nested object parsing.** Args must be flat key-value pairs.
3. **String values max ~256 chars** unless the destination buffer is larger.
4. **Numbers parsed via `atol()`** -- no floating point via `json_get_long()`. Float args are passed as strings and converted with `strtof()` or `atof()` in the handler.

These limitations are acceptable for the bridge protocol. If a command needs complex structured input, encode it as a single string with a defined delimiter.

---

## Python Client Contract

The Python `bridge.py` client (`send_command(cmd, args)`) expects:

1. Response always has `"ok"` (bool) and `"id"` (int).
2. On success: `data` dict is present (or data fields are at top level -- the existing commands embed data fields directly in the response without a `"data"` wrapper).
3. On error: `"error"` string is present.

**Important compatibility note:** The existing 18 commands embed their data fields directly in the top-level response (e.g., `{"id":1,"ok":true,"classes":[...],"total":100}`), NOT inside a `"data"` wrapper. New commands SHOULD follow the same pattern for consistency -- embed data fields at the top level alongside `"id"` and `"ok"`. The `"data":{}` wrapper shown in this spec is the *logical* grouping. In the actual wire format, these fields are siblings of `"id"` and `"ok"`.

**Wire format example (actual):**
```json
{"id":1,"ok":true,"instances":[...],"total_scanned":482916,"total_matched":2,"returned":2,"time_ms":340}
```

The Python `format_response()` function in `bridge.py` will need a new formatter for each command (keyed on `cmd` string). Each formatter extracts the relevant fields and produces human-readable output.

---

*This document is the authoritative protocol contract for Phase 13 bridge capabilities. Both C implementations and Python formatters must conform to the schemas defined here. Any deviations must be documented as errata and communicated to all agents.*
