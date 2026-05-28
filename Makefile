# ══════════════════════════════════════════════════════════════════
# Darkmach Dylib Build System — Modular Layout (Sprint 13.0A)
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

DYLIB_DIR := src/darkmach/dylibs/build
SRC_DIR   := src/darkmach/dylibs

# Include paths so #include "darkmach-core.h" and #include "darkmach-bridge.h"
# resolve correctly from any subdirectory
INCLUDES := -I$(SRC_DIR) -I$(SRC_DIR)/bridge

# ── All injectable dylibs (Simulator-targeted shared libraries) ──

DYLIBS := \
	$(DYLIB_DIR)/darkmach-bridge.dylib \
	$(DYLIB_DIR)/darkmach-net.dylib \
	$(DYLIB_DIR)/darkmach-tls.dylib \
	$(DYLIB_DIR)/darkmach-keychain.dylib \
	$(DYLIB_DIR)/darkmach-crypto.dylib \
	$(DYLIB_DIR)/darkmach-storage.dylib \
	$(DYLIB_DIR)/darkmach-ssl.dylib \
	$(DYLIB_DIR)/darkmach-db.dylib \
	$(DYLIB_DIR)/darkmach-metal-fix.dylib \
	$(DYLIB_DIR)/darkmach-decrypt.dylib \
	$(DYLIB_DIR)/darkmach-survival.dylib \
	$(DYLIB_DIR)/darkmach-stealth.dylib

# Host-side utility (not Simulator-targeted)
DUMP_REGION := $(SRC_DIR)/tools/dump-region

.PHONY: all dylibs tools clean sign

all: dylibs tools

dylibs: $(DYLIBS)
	@echo "All dylibs built."

# ── Bridge (unity build) ─────────────────────────────────────────
#
# darkmach-bridge.c is the unity build root — it #includes all
# cmd-*.c files. Only one compile command is needed.
#
# Source: bridge/darkmach-bridge.c (includes cmd-recon.c, cmd-events.c,
#         cmd-trace.c, cmd-network.c, cmd-ui.c, cmd-analysis.c,
#         cmd-forensics.c, cmd-inject.c)
# Output: src/dylibs/darkmach-bridge.dylib

# ARM64 trampoline assembly — method trace shared stub (Sprint 13.3)
TRAMPOLINE_SRC := $(SRC_DIR)/bridge/darkmach-trampoline.S
TRAMPOLINE_OBJ := $(DYLIB_DIR)/darkmach-trampoline.o

$(TRAMPOLINE_OBJ): $(TRAMPOLINE_SRC)
	$(CC) -target $(TARGET) -isysroot $(SDK) -c -o $@ $<

# Bridge unity build — links trampoline.o for trace stub table
BRIDGE_DEPS := $(SRC_DIR)/bridge/darkmach-bridge.c $(wildcard $(SRC_DIR)/bridge/cmd-*.c) $(wildcard $(SRC_DIR)/bridge/*.h) $(SRC_DIR)/darkmach-core.h

$(DYLIB_DIR)/darkmach-bridge.dylib: $(BRIDGE_DEPS) $(TRAMPOLINE_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -x none $(TRAMPOLINE_OBJ) \
		-framework Foundation -framework Security -lobjc -lsqlite3

# ── Interceptors ─────────────────────────────────────────────────
#
# Each interceptor compiles from interceptors/*.c to a flat .dylib
# at the DYLIB_DIR root. DYLD_INTERPOSE-based C function hooks.

$(DYLIB_DIR)/darkmach-net.dylib: $(SRC_DIR)/interceptors/darkmach-net.c $(SRC_DIR)/darkmach-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -lobjc

$(DYLIB_DIR)/darkmach-tls.dylib: $(SRC_DIR)/interceptors/darkmach-tls.c $(SRC_DIR)/darkmach-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -framework Security -lboringssl -lobjc

$(DYLIB_DIR)/darkmach-keychain.dylib: $(SRC_DIR)/interceptors/darkmach-keychain.c $(SRC_DIR)/darkmach-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -framework Security -lobjc

$(DYLIB_DIR)/darkmach-crypto.dylib: $(SRC_DIR)/interceptors/darkmach-crypto.c $(SRC_DIR)/darkmach-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -framework Security -lobjc

$(DYLIB_DIR)/darkmach-storage.dylib: $(SRC_DIR)/interceptors/darkmach-storage.c $(SRC_DIR)/darkmach-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -lobjc

$(DYLIB_DIR)/darkmach-ssl.dylib: $(SRC_DIR)/interceptors/darkmach-ssl.c $(SRC_DIR)/darkmach-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -framework Security -lobjc

$(DYLIB_DIR)/darkmach-db.dylib: $(SRC_DIR)/interceptors/darkmach-db.c $(SRC_DIR)/darkmach-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -lobjc -lsqlite3

# ── Compat (Simulator compatibility) ─────────────────────────────
#
# Metal GPU stub and FairPlay decryption analysis.
# Note: darkmach-bootstrap.dylib is a pre-compiled binary in compat/
# — no build rule needed.

$(DYLIB_DIR)/darkmach-metal-fix.dylib: $(SRC_DIR)/compat/darkmach-metal-fix.c $(SRC_DIR)/darkmach-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -lobjc

$(DYLIB_DIR)/darkmach-decrypt.dylib: $(SRC_DIR)/compat/darkmach-decrypt.c $(SRC_DIR)/darkmach-core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<
	codesign -s - --force $@

# Survival kit — Strategy A walls 4/5/6 mitigation (Round 4 promotion)
# Walls: __init_offsets SIGILL, Swift metadata SIGSEGV, UIKit-scene SIGSEGV
# Configurable via DARKMACH_SURVIVAL_FILTER env var
$(DYLIB_DIR)/darkmach-survival.dylib: $(SRC_DIR)/compat/darkmach-survival.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< \
		-framework Foundation -lobjc
	codesign -s - --force $@

# ── Stealth (anti-detection) ─────────────────────────────────────

# Stealth dylib — anti-detection evasion (Sprint 13.4)
# Source file created in Sprint 13.4
$(DYLIB_DIR)/darkmach-stealth.dylib: $(SRC_DIR)/stealth/darkmach-stealth.c $(SRC_DIR)/darkmach-core.h
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
