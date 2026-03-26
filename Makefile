# ══════════════════════════════════════════════════════════════════
# Sphinx Dylib Build System — Modular Layout (Sprint 13.0A)
#
# Source files live in subdirectories under src/dylibs/:
#   bridge/       — LLM bridge (unity build)
#   interceptors/ — DYLD_INTERPOSE interceptor dylibs
#   compat/       — Simulator compatibility dylibs
#   stealth/      — Anti-detection (future)
#   tools/        — Host-side utilities
#
# All .dylib outputs go to src/dylibs/build/ — keeps compiled
# artifacts separate from source directories.
# ══════════════════════════════════════════════════════════════════

SDK     := $(shell xcrun --sdk iphonesimulator --show-sdk-path)
TARGET  := arm64-apple-ios16.0-simulator
CC      := clang
CFLAGS  := -shared -target $(TARGET) -isysroot $(SDK) -x objective-c -fobjc-exceptions -w

DYLIB_DIR := src/dylibs/build
SRC_DIR   := src/dylibs

# Include paths so #include "sphinx-core.h" and #include "sphinx-bridge.h"
# resolve correctly from any subdirectory
INCLUDES := -I$(SRC_DIR) -I$(SRC_DIR)/bridge

# ── All injectable dylibs (Simulator-targeted shared libraries) ──

DYLIBS := \
	$(DYLIB_DIR)/sphinx-bridge.dylib \
	$(DYLIB_DIR)/sphinx-net.dylib \
	$(DYLIB_DIR)/sphinx-tls.dylib \
	$(DYLIB_DIR)/sphinx-keychain.dylib \
	$(DYLIB_DIR)/sphinx-crypto.dylib \
	$(DYLIB_DIR)/sphinx-storage.dylib \
	$(DYLIB_DIR)/sphinx-ssl.dylib \
	$(DYLIB_DIR)/sphinx-db.dylib \
	$(DYLIB_DIR)/sphinx-metal-fix.dylib \
	$(DYLIB_DIR)/sphinx-decrypt.dylib \
	$(DYLIB_DIR)/sphinx-stealth.dylib

# Host-side utility (not Simulator-targeted)
DUMP_REGION := $(SRC_DIR)/tools/dump-region

.PHONY: all dylibs tools clean sign

all: dylibs tools

dylibs: $(DYLIBS)
	@echo "All dylibs built."

# ── Bridge (unity build) ─────────────────────────────────────────
#
# sphinx-bridge.c is the unity build root — it #includes all
# cmd-*.c files. Only one compile command is needed.
#
# Source: bridge/sphinx-bridge.c (includes cmd-recon.c, cmd-events.c,
#         cmd-trace.c, cmd-network.c, cmd-ui.c, cmd-analysis.c,
#         cmd-forensics.c, cmd-inject.c)
# Output: src/dylibs/sphinx-bridge.dylib

# ARM64 trampoline assembly — method trace shared stub (Sprint 13.3)
TRAMPOLINE_SRC := $(SRC_DIR)/bridge/sphinx-trampoline.S
TRAMPOLINE_OBJ := $(DYLIB_DIR)/sphinx-trampoline.o

$(TRAMPOLINE_OBJ): $(TRAMPOLINE_SRC)
	$(CC) -target $(TARGET) -isysroot $(SDK) -c -o $@ $<

# Bridge unity build — links trampoline.o for trace stub table
BRIDGE_DEPS := $(SRC_DIR)/bridge/sphinx-bridge.c $(wildcard $(SRC_DIR)/bridge/cmd-*.c) $(wildcard $(SRC_DIR)/bridge/*.h) $(SRC_DIR)/sphinx-core.h

$(DYLIB_DIR)/sphinx-bridge.dylib: $(BRIDGE_DEPS) $(TRAMPOLINE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -x none $(TRAMPOLINE_OBJ) \
		-framework Foundation -framework Security -lobjc -lsqlite3

# ── Interceptors ─────────────────────────────────────────────────
#
# Each interceptor compiles from interceptors/*.c to a flat .dylib
# at the DYLIB_DIR root. DYLD_INTERPOSE-based C function hooks.

$(DYLIB_DIR)/sphinx-net.dylib: $(SRC_DIR)/interceptors/sphinx-net.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -lobjc

$(DYLIB_DIR)/sphinx-tls.dylib: $(SRC_DIR)/interceptors/sphinx-tls.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -framework Security -lboringssl -lobjc

$(DYLIB_DIR)/sphinx-keychain.dylib: $(SRC_DIR)/interceptors/sphinx-keychain.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -framework Security -lobjc

$(DYLIB_DIR)/sphinx-crypto.dylib: $(SRC_DIR)/interceptors/sphinx-crypto.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -framework Security -lobjc

$(DYLIB_DIR)/sphinx-storage.dylib: $(SRC_DIR)/interceptors/sphinx-storage.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -lobjc

$(DYLIB_DIR)/sphinx-ssl.dylib: $(SRC_DIR)/interceptors/sphinx-ssl.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -framework Security -lobjc

$(DYLIB_DIR)/sphinx-db.dylib: $(SRC_DIR)/interceptors/sphinx-db.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -lobjc -lsqlite3

# ── Compat (Simulator compatibility) ─────────────────────────────
#
# Metal GPU stub and FairPlay decryption analysis.
# Note: sphinx-bootstrap.dylib is a pre-compiled binary in compat/
# — no build rule needed.

$(DYLIB_DIR)/sphinx-metal-fix.dylib: $(SRC_DIR)/compat/sphinx-metal-fix.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -lobjc

$(DYLIB_DIR)/sphinx-decrypt.dylib: $(SRC_DIR)/compat/sphinx-decrypt.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<
	codesign -s - --force $@

# ── Stealth (anti-detection) ─────────────────────────────────────

# Stealth dylib — anti-detection evasion (Sprint 13.4)
# Source file created in Sprint 13.4
$(DYLIB_DIR)/sphinx-stealth.dylib: $(SRC_DIR)/stealth/sphinx-stealth.c $(SRC_DIR)/sphinx-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -framework Security -lobjc

# ── Host tools (native macOS, not Simulator-targeted) ────────────

tools: $(DUMP_REGION)

$(DUMP_REGION): $(SRC_DIR)/tools/dump-region.c
	clang -o $@ $< -framework Security -w

# ── Utility targets ──────────────────────────────────────────────

sign: $(DYLIBS)
	@for f in $(DYLIBS); do codesign -s - --force $$f; done
	@echo "All dylibs signed."

clean:
	rm -f $(DYLIBS) $(DUMP_REGION) $(TRAMPOLINE_OBJ)
