![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Language](https://img.shields.io/badge/language-C-lightgrey)
![Dependencies](https://img.shields.io/badge/dependencies-none-green)

# Interceptor Dylib Reference

Sphinx uses a suite of DYLD-injected C dylibs to capture runtime behavior from iOS apps running in the Simulator. All interceptors are written in C, compiled against the iOS Simulator SDK, and have zero external dependencies.

---

## Why Custom C Dylibs

SIP (System Integrity Protection) on Apple Silicon blocks Frida everywhere — its injection mechanism cannot attach to Simulator processes. Sphinx's approach bypasses this entirely:

- Dylibs are injected via `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES`, which is handled by `dyld_sim` inside the Simulator runtime
- `dyld_sim` does not enforce SIP restrictions on dylib injection
- DYLD interpose replaces C function symbols at the dyld level before any app code runs
- ObjC method swizzling replaces method implementations at the ObjC runtime level
- There is no known signature or fingerprint for these techniques

The interceptors are structurally undetectable: they do not create new threads with unusual names, do not attach via `task_for_pid`, and do not appear in any anti-tamper or anti-debugging check that operates against the process itself.

---

## Interceptor Table

| Dylib | Technique | What It Hooks |
|-------|-----------|--------------|
| `sphinx-net.dylib` | Method swizzle | `NSURLSession` |
| `sphinx-keychain.dylib` | DYLD interpose | `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete` |
| `sphinx-crypto.dylib` | DYLD interpose | `CCCrypt`, `CC_SHA256`, `CC_SHA1` |
| `sphinx-storage.dylib` | Method swizzle | `NSUserDefaults`, `UIPasteboard`, `NSFileManager`, `NSHTTPCookieStorage` |
| `sphinx-ssl.dylib` | DYLD interpose + method swizzle | `SecTrustEvaluateWithError`, `SecTrustEvaluateAsyncWithError` |
| `sphinx-db.dylib` | DYLD interpose | `sqlite3_open`, `sqlite3_open_v2`, `sqlite3_close`, `sqlite3_close_v2`, `sqlite3_exec`, `sqlite3_prepare_v2`, `sqlite3_prepare_v3`, `sqlite3_step`, `sqlite3_finalize` |
| `sphinx-bridge.dylib` | ObjC runtime introspection | Full runtime access via JSON command protocol |
| `sphinx-decrypt.dylib` | Self-memory read | FairPlay crypt region at `mach_vm_read` |
| `sphinx-metal-fix.dylib` | Method swizzle | Metal framework GPU compatibility |
| `sphinx-tls.dylib` | DYLD interpose | BoringSSL low-level TLS functions |

---

## sphinx-net.dylib

**Network interceptor.** Hooks `NSURLSession` to capture all HTTP and HTTPS traffic.

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

**Output file:** `sphinx-net.jsonl`

**Example log entry:**

```json
{"ts":"2026-03-23T14:32:01.423","mod":"net","evt":"request","url":"https://api.revenuecat.com/v1/subscribers","method":"POST","headers":{"Authorization":"Bearer appl_tAkyaq...","Content-Type":"application/json"},"body":"{\"app_user_id\":\"...\""}
```

---

## sphinx-keychain.dylib

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

**Output file:** `sphinx-keychain.jsonl`

**Example log entry:**

```json
{"ts":"2026-03-23T14:32:02.011","mod":"keychain","evt":"copy","class":"genp","service":"com.example.myapp","account":"user@example.com","data":"s3cr3t-session-token","status":0}
```

---

## sphinx-crypto.dylib

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

**Output file:** `sphinx-crypto.jsonl`

**Example log entry:**

```json
{"ts":"2026-03-23T14:32:03.112","mod":"crypto","evt":"crypt","op":"decrypt","alg":0,"key":"a3f4b2c1...","iv":"00000000...","input_hex":"e4f2...","output_hex":"7b22..."}
```

---

## sphinx-storage.dylib

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

**Output file:** `sphinx-storage.jsonl`

**Example log entries:**

```json
{"ts":"2026-03-23T14:32:04.211","mod":"storage","evt":"defaults_set","key":"session_token","value":"eyJ..."}
{"ts":"2026-03-23T14:32:04.389","mod":"storage","evt":"cookie_set","name":"auth","value":"tok_xyz","domain":".example.com"}
```

---

## sphinx-ssl.dylib

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

Set `SPHINX_SSL_BYPASS=1` (via `sphinx launch --ssl-bypass`) to make `SecTrustEvaluateWithError` always return `true`. This bypasses certificate pinning for any app that uses the standard Security framework trust evaluation path.

```bash
sphinx launch com.example.myapp --ssl-bypass
```

**Output file:** `sphinx-ssl.jsonl`

---

## sphinx-db.dylib

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

**Output file:** `sphinx-db.jsonl`

**Example log entries:**

```json
{"ts":"2026-03-23T14:32:05.001","mod":"db","evt":"open","path":"/var/mobile/Containers/Data/Application/.../Cache.db"}
{"ts":"2026-03-23T14:32:05.123","mod":"db","evt":"query","db":"/var/.../Cache.db","sql":"SELECT id, token, expires FROM sessions WHERE active=1"}
{"ts":"2026-03-23T14:32:05.124","mod":"db","evt":"row","db":"/var/.../Cache.db","sql":"SELECT id, token, expires FROM sessions WHERE active=1","row":{"id":"42","token":"eyJ...","expires":"2026-09-01"}}
```

---

## sphinx-bridge.dylib

**LLM runtime bridge.** Opens a Unix domain socket at `/tmp/sphinx-bridge.sock` inside the running app process. An external client (human or LLM) connects and sends JSON commands to introspect and interact with the live app.

This is Sphinx's most powerful capability. See [LLM Runtime Bridge](bridge.md) for complete documentation.

**Socket:** `/tmp/sphinx-bridge.sock`
**Protocol:** Newline-delimited JSON (request/response)
**Max response size:** 1MB

---

## sphinx-decrypt.dylib

**FairPlay crypt region extractor.** Used internally by the patching pipeline — not part of the standard interceptor set for `sphinx run` / `sphinx launch`.

Called via `xcrun simctl spawn` (not `simctl launch`) to bypass SpringBoard. Reads decrypted FairPlay bytes from the process's own memory and writes them to a file.

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `SIMCTL_CHILD_SPHINX_CRYPTOFF` | Hex offset of the crypt region in the binary (e.g., `0x4000`) |
| `SIMCTL_CHILD_SPHINX_CRYPTSIZE` | Hex size of the crypt region (e.g., `0x8000`) |
| `SIMCTL_CHILD_SPHINX_DECRYPT_OUT` | Absolute path for the output file |

The kernel decrypts FairPlay pages during page-in for Simulator processes. The dylib reads `cryptsize` bytes from the process's memory at the `cryptoff` address using `mach_vm_read`, and writes them to `SPHINX_DECRYPT_OUT`.

---

## sphinx-metal-fix.dylib

**Metal GPU compatibility shim.** Patches Metal framework calls to work correctly in the Simulator environment. Some apps make Metal API calls that assume device GPU presence; this dylib applies compatibility fixes to prevent crashes.

---

## sphinx-tls.dylib

**BoringSSL low-level TLS interceptor.** Hooks BoringSSL functions directly for apps that bypass the Security framework and use BoringSSL directly (common in React Native and Flutter apps).

Links against `libboringssl`.

---

## sphinx-core.h

All interceptors include `sphinx-core.h`, which provides shared infrastructure.

### Logging

```c
void sphinx_log_init(const char *module);
void sphinx_log(const char *module, const char *event, const char *json_data);
```

`sphinx_log_init` is called automatically on first use. It checks `SPHINX_OUTPUT_DIR` (set by the CLI) and writes to `$SPHINX_OUTPUT_DIR/sphinx-<module>.jsonl`. Falls back to `/tmp/sphinx-<module>.jsonl` if the env var is not set.

All writes are protected by a pthread mutex for thread safety.

### ObjC Helpers

```c
BOOL sphinx_isKindOfClass(id obj, const char *className);
const char *nsstring_to_c(id nsstr);
const char *nsobject_desc(id obj);
long nsnumber_long(id num);
```

`nsstring_to_c` safely extracts UTF-8 C strings from NSString objects. It uses `sphinx_isKindOfClass` to verify the object type before sending messages — this is critical because DYLD interpose and swizzle hooks may receive `CFStringRef` constants or other non-NSString types.

### JSON String Escaping

```c
void json_escape(const char *src, char *dst, size_t dst_size);
```

Escapes a C string for safe embedding in a JSON value — handles quotes, backslashes, newlines, carriage returns, tabs, and non-printable characters.

### Method Swizzling

```c
void sphinx_swizzle(Class cls, SEL orig_sel, SEL new_sel);
```

Exchanges two method implementations using the ObjC runtime. Uses `class_addMethod` + `class_replaceMethod` if the original method is inherited, or `method_exchangeImplementations` if it is already defined on the class.

---

## Injection

### Standard injection (sphinx run / sphinx launch)

The CLI injects all 8 standard interceptors automatically:

```bash
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=\
  /path/to/sphinx-metal-fix.dylib:\
  /path/to/sphinx-net.dylib:\
  /path/to/sphinx-keychain.dylib:\
  /path/to/sphinx-crypto.dylib:\
  /path/to/sphinx-storage.dylib:\
  /path/to/sphinx-ssl.dylib:\
  /path/to/sphinx-db.dylib:\
  /path/to/sphinx-bridge.dylib \
xcrun simctl launch <udid> <bundle-id>
```

### Manual injection

You can inject any subset of dylibs manually:

```bash
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=/path/to/sphinx/src/dylibs/sphinx-net.dylib \
SIMCTL_CHILD_SPHINX_OUTPUT_DIR=/tmp/myapp-logs \
xcrun simctl launch booted com.example.myapp
```

### Environment variables

| Variable | Set By | Description |
|----------|--------|-------------|
| `SIMCTL_CHILD_SPHINX_OUTPUT_DIR` | CLI (`SPHINX_OUTPUT_DIR` inside process) | Directory for JSONL output files |
| `SIMCTL_CHILD_SPHINX_SSL_BYPASS` | `sphinx launch --ssl-bypass` | Set to `1` to bypass SSL pinning |
| `SIMCTL_CHILD_SPHINX_CRYPTOFF` | Patching pipeline | FairPlay crypt offset (hex) for decrypt dylib |
| `SIMCTL_CHILD_SPHINX_CRYPTSIZE` | Patching pipeline | FairPlay crypt size (hex) for decrypt dylib |
| `SIMCTL_CHILD_SPHINX_DECRYPT_OUT` | Patching pipeline | Output path for decrypt dylib |

Note: `SIMCTL_CHILD_` is stripped by simctl; the process sees the variable without that prefix. So `SIMCTL_CHILD_SPHINX_OUTPUT_DIR` becomes `SPHINX_OUTPUT_DIR` inside the process.

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
| `sphinx-net` | Foundation, objc |
| `sphinx-keychain` | Foundation, Security, objc |
| `sphinx-crypto` | Foundation, Security, objc |
| `sphinx-storage` | Foundation, objc |
| `sphinx-ssl` | Foundation, Security, objc |
| `sphinx-db` | Foundation, objc, sqlite3 |
| `sphinx-bridge` | Foundation, Security, objc, sqlite3 |
| `sphinx-decrypt` | (none) |
| `sphinx-metal-fix` | Foundation, objc |
| `sphinx-tls` | Foundation, Security, boringssl, objc |
