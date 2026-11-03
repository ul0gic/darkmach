![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Language](https://img.shields.io/badge/language-C-lightgrey)
![Dependencies](https://img.shields.io/badge/dependencies-none-green)

# Interceptor Dylib Reference

Log examples are illustrative and use synthetic values.

Darkmach uses a suite of DYLD-injected C dylibs to capture runtime behavior from iOS apps running in the Simulator. All interceptors are written in C, compiled against the iOS Simulator SDK, and have zero external dependencies.

---

## Why Custom C Dylibs

Darkmach uses launch-time library insertion rather than attaching an external instrumentation runtime to the running target. The custom dylibs keep capture and bridge behavior directly inspectable in this repository:

- `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES` passes the insertion list to the Simulator child process.
- DYLD interposition replaces selected C function calls; Objective-C swizzling replaces selected method implementations.
- Interceptor-owned hooks feed continuous JSONL logs and exported bridge recorders.

Loaded dylibs, replaced implementations, environment variables and the bridge socket are observable. The optional stealth component does not guarantee invisible instrumentation.

---

## Interceptor Table

| Dylib | Technique | What It Hooks |
|-------|-----------|--------------|
| `darkmach-net.dylib` | Method swizzle | `NSURLSession` |
| `darkmach-keychain.dylib` | DYLD interpose | `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete` |
| `darkmach-crypto.dylib` | DYLD interpose | `CCCrypt`, `CC_SHA256`, `CC_SHA1` |
| `darkmach-storage.dylib` | Method swizzle | `NSUserDefaults`, `UIPasteboard`, `NSFileManager`, `NSHTTPCookieStorage` |
| `darkmach-ssl.dylib` | DYLD interpose + method swizzle | `SecTrustEvaluateWithError`, `SecTrustEvaluateAsyncWithError` |
| `darkmach-db.dylib` | DYLD interpose | `sqlite3_open`, `sqlite3_open_v2`, `sqlite3_close`, `sqlite3_close_v2`, `sqlite3_exec`, `sqlite3_prepare_v2`, `sqlite3_prepare_v3`, `sqlite3_step`, `sqlite3_finalize` |
| `darkmach-bridge.dylib` | ObjC runtime introspection | Runtime queries and captured observations via JSON command protocol |
| `darkmach-decrypt.dylib` | Self-memory read | Mapped crypt region read directly from the current process |
| `darkmach-metal-fix.dylib` | Method swizzle | Metal framework GPU compatibility |
| `darkmach-tls.dylib` | DYLD interpose | BoringSSL low-level TLS functions |
| `darkmach-survival.dylib` | Compatibility transformations | Selected Strategy A initialization and runtime failures |
| `darkmach-stealth.dylib` | Interpose and swizzle | Selected environment and anti-instrumentation checks |

The default launch set contains eight components: metal-fix, net, keychain, crypto, storage, ssl, db and bridge. Decrypt, TLS, survival and stealth have separate roles and are not all injected by a normal launch.

---

## darkmach-net.dylib

**Network interceptor.** Hooks selected `NSURLSession` task-creation methods to capture requests and completion-handler responses. Other transports and API variants require separate coverage validation.

**Hooks:**
- `dataTaskWithRequest:completionHandler:` — captures URL, method, headers, body, wraps completion for response capture
- `dataTaskWithURL:completionHandler:` — same for the simpler URL-only variant

**Data captured:**

| Field | Description |
|-------|-------------|
| URL | Full request URL |
| Method | HTTP method (GET, POST, etc.) |
| Headers | All request headers — including `Authorization`, `X-API-Key`, session tokens |
| Body | Request body (for POST/PUT/PATCH) |
| Response status | HTTP status code |
| Response headers | Including `Set-Cookie`, `Content-Type` |
| Response body | Response payload |

**Output file:** `darkmach-net.jsonl`

**Example log entry:**

```json
{"ts":"2000-01-01T14:32:01.423","mod":"net","evt":"request","url":"https://api.example.com/items","method":"POST","headers":{"Authorization":"Bearer <example-token>","Content-Type":"application/json"},"body":"{\"app_user_id\":\"...\""}
```

---

## darkmach-keychain.dylib

**Keychain interceptor.** DYLD-interposes all four `SecItem` functions to capture every keychain read, write, update, and delete.

**Hooks (DYLD interpose):**
- `SecItemAdd` — credential storage
- `SecItemCopyMatching` — credential retrieval
- `SecItemUpdate` — credential modification
- `SecItemDelete` — credential removal

**Data captured:**

| Field | Description |
|-------|-------------|
| Operation | add, copy, update, delete |
| Security class | `kSecClassGenericPassword`, `kSecClassInternetPassword`, `kSecClassKey`, etc. |
| Service | `kSecAttrService` value |
| Account | `kSecAttrAccount` value |
| Label | `kSecAttrLabel` if present |
| Access group | `kSecAttrAccessGroup` if set |
| Data | Credential value, decoded as UTF-8 or hex |
| Status | `OSStatus` return value |

**Output file:** `darkmach-keychain.jsonl`

**Example log entry:**

```json
{"ts":"2000-01-01T14:32:02.011","mod":"keychain","evt":"copy","class":"genp","service":"com.example.myapp","account":"user@example.com","data":"example-session-token","status":0}
```

---

## darkmach-crypto.dylib

**Cryptographic operation interceptor.** DYLD-interposes Apple's CommonCrypto functions to capture keys, IVs, algorithms, and plaintext at the moment of use.

**Hooks (DYLD interpose):**
- `CCCrypt` — symmetric encryption and decryption (AES, DES, 3DES, RC4, etc.)
- `CC_SHA256` — SHA-256 digest
- `CC_SHA1` — SHA-1 digest

**Data captured for CCCrypt:**

| Field | Description |
|-------|-------------|
| Operation | Encrypt or decrypt |
| Algorithm | AES, DES, 3DES, CAST, RC4, RC2, Blowfish |
| Options | CBC, ECB, PKCS7 padding flags |
| Key | Full key bytes as hex |
| IV | Initialization vector as hex |
| Input preview | First 64 bytes of input as hex |
| Output preview | First 64 bytes of output as hex |

**Output file:** `darkmach-crypto.jsonl`

**Example log entry:**

```json
{"ts":"2000-01-01T14:32:03.112","mod":"crypto","evt":"crypt","op":"decrypt","alg":0,"key":"000102030405060708090a0b0c0d0e0f","iv":"00000000000000000000000000000000","input_hex":"e4f2...","output_hex":"7b22..."}
```

---

## darkmach-storage.dylib

**Local storage interceptor.** Hooks NSUserDefaults, pasteboard, file manager, and cookie storage.

**Hooks (method swizzle):**

`NSUserDefaults`:
- `setObject:forKey:` — any object write
- `objectForKey:` — any object read
- `setBool:forKey:` — boolean write
- `setInteger:forKey:` — integer write

`UIPasteboard`:
- `setString:` — clipboard write
- `string` (getter) — clipboard read

`NSFileManager`:
- `createFileAtPath:contents:attributes:` — file write
- `contentsAtPath:` — file read

`NSHTTPCookieStorage`:
- `setCookie:` — cookie storage
- `cookies` (getter) — all cookies read
- `cookiesForURL:` — cookies for a specific URL

**Output file:** `darkmach-storage.jsonl`

**Example log entries:**

```json
{"ts":"2000-01-01T14:32:04.211","mod":"storage","evt":"defaults_set","key":"session_token","value":"eyJ..."}
{"ts":"2000-01-01T14:32:04.389","mod":"storage","evt":"cookie_set","name":"auth","value":"tok_xyz","domain":".example.com"}
```

---

## darkmach-ssl.dylib

**SSL/TLS interceptor.** Captures certificate chain information and trust evaluation results. Optionally bypasses certificate pinning.

**Hooks:**
- `SecTrustEvaluateWithError` (DYLD interpose) — main trust evaluation entry point
- `SecTrustEvaluateAsyncWithError` (DYLD interpose) — async variant

**Data captured:**

| Field | Description |
|-------|-------------|
| Certificate count | Number of certs in the chain |
| Leaf certificate | Subject, issuer, expiry |
| Trust result | Original evaluation result |
| Bypassed | Whether SSL bypass was applied |

**SSL pinning bypass:**

Set `DARKMACH_SSL_BYPASS=1` (via `darkmach launch --ssl-bypass`) to override rejection in the hooked trust-evaluation paths. The synchronous `SecTrustEvaluateWithError` hook returns success when its original evaluator rejects trust and bypass is enabled. Custom pin checks, other transports and application-level decisions may still reject a connection; verify the exercised path rather than assuming universal pinning bypass.

```bash
darkmach launch com.example.myapp --ssl-bypass
```

**Output file:** `darkmach-ssl.jsonl`

---

## darkmach-db.dylib

**SQLite database interceptor.** DYLD-interposes 9 sqlite3 functions to capture every database operation — queries, results, and database paths.

**Hooks (DYLD interpose):**
- `sqlite3_open` / `sqlite3_open_v2` — database open (captures file path)
- `sqlite3_close` / `sqlite3_close_v2` — database close
- `sqlite3_exec` — direct SQL execution
- `sqlite3_prepare_v2` / `sqlite3_prepare_v3` — statement preparation (captures SQL)
- `sqlite3_step` — statement execution (captures each result row)
- `sqlite3_finalize` — statement finalization

The interceptor maintains a mapping from database handle to file path, and from statement handle to SQL text, so each row result is annotated with the originating query and database.

**Data captured:**

| Field | Description |
|-------|-------------|
| Database path | Absolute path to the `.db` / `.sqlite` file |
| SQL | Prepared SQL statement text |
| Columns | Column names and SQLite type codes |
| Row values | All column values for each row returned |

**Output file:** `darkmach-db.jsonl`

**Example log entries:**

```json
{"ts":"2000-01-01T14:32:05.001","mod":"db","evt":"open","path":"/var/mobile/Containers/Data/Application/.../Cache.db"}
{"ts":"2000-01-01T14:32:05.123","mod":"db","evt":"query","db":"/var/.../Cache.db","sql":"SELECT id, token, expires FROM sessions WHERE active=1"}
{"ts":"2000-01-01T14:32:05.124","mod":"db","evt":"row","db":"/var/.../Cache.db","sql":"SELECT id, token, expires FROM sessions WHERE active=1","row":{"id":"42","token":"eyJ...","expires":"2000-01-01"}}
```

---

## darkmach-bridge.dylib

**Runtime bridge.** Opens the Unix socket selected by the launcher inside the running app process. An external operator/client sends JSON commands to inspect and operate on the live app.

This is Darkmach's most powerful capability. See [LLM Runtime Bridge](bridge.md) for complete documentation.

**Socket:** normally `/tmp/darkmach-bridge-<UUID>.sock`, or explicit `--socket`; standalone native injection falls back to legacy `/tmp/darkmach-bridge.sock`.
**Protocol:** Newline-delimited JSON (request/response)
**Max response size:** 1MB

---

## darkmach-decrypt.dylib

**FairPlay crypt region extractor.** Used internally by the patching pipeline — not part of the standard interceptor set for `darkmach run` / `darkmach launch`.

Called via `xcrun simctl spawn` (not `simctl launch`) to bypass SpringBoard. Reads decrypted FairPlay bytes from the process's own memory and writes them to a file.

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `SIMCTL_CHILD_DARKMACH_CRYPTOFF` | Hex offset of the crypt region in the binary (e.g., `0x4000`) |
| `SIMCTL_CHILD_DARKMACH_CRYPTSIZE` | Hex size of the crypt region (e.g., `0x8000`) |
| `SIMCTL_CHILD_DARKMACH_DECRYPT_OUT` | Absolute path for the output file |

The extraction path relies on the system making the marked region readable in the temporary process. The dylib computes the mapped executable header plus `cryptoff` and writes `cryptsize` bytes through ordinary memory access and file I/O. It does not call `mach_vm_read`. The mapping assumption and evidence for system-managed decryption are explained in [two-pass extraction](how-it-works.md).

---

## darkmach-metal-fix.dylib

**Metal GPU compatibility shim.** Patches Metal framework calls to work correctly in the Simulator environment. Some apps make Metal API calls that assume device GPU presence; this dylib applies compatibility fixes to prevent crashes.

---

## darkmach-tls.dylib

**BoringSSL low-level TLS interceptor.** Hooks BoringSSL functions directly for apps that bypass the Security framework and use BoringSSL directly (common in React Native and Flutter apps).

Links against `libboringssl`.

---

## darkmach-core.h

All interceptors include `darkmach-core.h`, which provides shared infrastructure.

### Logging

```c
void darkmach_log_init(const char *module);
void darkmach_log(const char *module, const char *event, const char *json_data);
```

`darkmach_log_init` is called automatically on first use. It checks `DARKMACH_OUTPUT_DIR` (set by the CLI) and writes to `$DARKMACH_OUTPUT_DIR/darkmach-<module>.jsonl`. Falls back to `/tmp/darkmach-<module>.jsonl` if the env var is not set.

All writes are protected by a pthread mutex for thread safety.

### ObjC Helpers

```c
BOOL darkmach_isKindOfClass(id obj, const char *className);
const char *nsstring_to_c(id nsstr);
const char *nsobject_desc(id obj);
long nsnumber_long(id num);
```

`nsstring_to_c` safely extracts UTF-8 C strings from NSString objects. It uses `darkmach_isKindOfClass` to verify the object type before sending messages — this is critical because DYLD interpose and swizzle hooks may receive `CFStringRef` constants or other non-NSString types.

### JSON String Escaping

```c
void json_escape(const char *src, char *dst, size_t dst_size);
```

Escapes a C string for safe embedding in a JSON value — handles quotes, backslashes, newlines, carriage returns, tabs, and non-printable characters.

### Method Swizzling

```c
void darkmach_swizzle(Class cls, SEL orig_sel, SEL new_sel);
```

Exchanges two method implementations using the ObjC runtime. Uses `class_addMethod` + `class_replaceMethod` if the original method is inherited, or `method_exchangeImplementations` if it is already defined on the class.

---

## Injection

### Standard injection (darkmach run / darkmach launch)

The CLI injects all 8 standard interceptors automatically:

```bash
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=\
  /path/to/darkmach-metal-fix.dylib:\
  /path/to/darkmach-net.dylib:\
  /path/to/darkmach-keychain.dylib:\
  /path/to/darkmach-crypto.dylib:\
  /path/to/darkmach-storage.dylib:\
  /path/to/darkmach-ssl.dylib:\
  /path/to/darkmach-db.dylib:\
  /path/to/darkmach-bridge.dylib \
xcrun simctl launch <udid> <bundle-id>
```

### Manual injection

You can inject a subset manually. The example requires your reserved device UUID in `DARKMACH_UDID` and an already installed target; replace the dylib/log paths and bundle ID with that session’s values:

```bash
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/path/to/darkmach/src/dylibs/build/darkmach-net.dylib \
SIMCTL_CHILD_DARKMACH_OUTPUT_DIR=/tmp/myapp-logs \
xcrun simctl launch "$DARKMACH_UDID" com.example.myapp
```

### Environment variables

| Variable | Set By | Description |
|----------|--------|-------------|
| `SIMCTL_CHILD_DARKMACH_OUTPUT_DIR` | CLI (`DARKMACH_OUTPUT_DIR` inside process) | Directory for JSONL output files |
| `SIMCTL_CHILD_DARKMACH_SSL_BYPASS` | `darkmach launch --ssl-bypass` | Set to `1` to bypass SSL pinning |
| `SIMCTL_CHILD_DARKMACH_CRYPTOFF` | Patching pipeline | FairPlay crypt offset (hex) for decrypt dylib |
| `SIMCTL_CHILD_DARKMACH_CRYPTSIZE` | Patching pipeline | FairPlay crypt size (hex) for decrypt dylib |
| `SIMCTL_CHILD_DARKMACH_DECRYPT_OUT` | Patching pipeline | Output path for decrypt dylib |

Note: `SIMCTL_CHILD_` is stripped by simctl; the process sees the variable without that prefix. So `SIMCTL_CHILD_DARKMACH_OUTPUT_DIR` becomes `DARKMACH_OUTPUT_DIR` inside the process.

---

## Building

From the project root:

```bash
make          # Build all dylibs + dump-region
make dylibs   # Build only the dylibs
make tools    # Build only dump-region
make sign     # Re-sign all dylibs with ad-hoc signature
make clean    # Remove all compiled outputs
```

The Makefile uses:
- Compiler: `clang`
- Target: `arm64-apple-ios16.0-simulator`
- SDK: iOS Simulator SDK (auto-detected via `xcrun`)
- Flags: `-shared -w`

Each dylib links only the frameworks it needs:

| Dylib | Frameworks / Libraries |
|-------|----------------------|
| `darkmach-net` | Foundation, objc |
| `darkmach-keychain` | Foundation, Security, objc |
| `darkmach-crypto` | Foundation, Security, objc |
| `darkmach-storage` | Foundation, objc |
| `darkmach-ssl` | Foundation, Security, objc |
| `darkmach-db` | Foundation, objc, sqlite3 |
| `darkmach-bridge` | Foundation, Security, objc, sqlite3 |
| `darkmach-decrypt` | (none) |
| `darkmach-metal-fix` | Foundation, objc |
| `darkmach-tls` | Foundation, Security, boringssl, objc |
