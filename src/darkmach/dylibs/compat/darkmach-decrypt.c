/*
 * darkmach-decrypt.c — FairPlay crypt region extractor
 *
 * Compiled as a dylib and injected via DYLD_INSERT_LIBRARIES into a Simulator
 * process loading a binary with cryptid=1. The kernel decrypts FairPlay pages
 * during page-in; this constructor reads the decrypted bytes from the crypt
 * region and writes them to an output file, then exits immediately.
 *
 * Environment variables:
 *   DARKMACH_CRYPTOFF   — offset of crypt region in binary (hex ok: 0x1f000)
 *   DARKMACH_CRYPTSIZE  — size of crypt region in bytes
 *   DARKMACH_DECRYPT_OUT — output file path for decrypted bytes
 *
 * Build:
 *   clang -shared -o darkmach-decrypt.dylib darkmach-decrypt.c \
 *     -target arm64-apple-ios16.0-simulator \
 *     -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path)
 *   codesign -s - --force darkmach-decrypt.dylib
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <unistd.h>

__attribute__((constructor))
static void decrypt_dump(void) {
    const char *off_s = getenv("DARKMACH_CRYPTOFF");
    const char *sz_s  = getenv("DARKMACH_CRYPTSIZE");
    const char *out   = getenv("DARKMACH_DECRYPT_OUT");
    if (!off_s || !sz_s || !out) {
        fprintf(stderr, "[darkmach-decrypt] need DARKMACH_CRYPTOFF, DARKMACH_CRYPTSIZE, DARKMACH_DECRYPT_OUT\n");
        return;  /* no-op when env vars not set — safe to co-load with other dylibs */
    }

    unsigned long cryptoff  = strtoul(off_s, NULL, 0);
    unsigned long cryptsize = strtoul(sz_s, NULL, 0);

    /* Find main executable header */
    const struct mach_header_64 *hdr = NULL;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (mh->filetype == MH_EXECUTE) {
            hdr = (const struct mach_header_64 *)mh;
            break;
        }
    }
    if (!hdr) { fprintf(stderr, "[darkmach-decrypt] no main exe\n"); _exit(98); }

    const uint8_t *region = (const uint8_t *)hdr + cryptoff;
    fprintf(stderr, "[darkmach-decrypt] hdr=%p crypt=%p off=0x%lx sz=0x%lx\n",
            hdr, region, cryptoff, cryptsize);
    fprintf(stderr, "[darkmach-decrypt] first 16: ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", region[i]);
    fprintf(stderr, "\n");

    FILE *f = fopen(out, "wb");
    if (!f) { fprintf(stderr, "[darkmach-decrypt] can't write %s\n", out); _exit(97); }
    fwrite(region, 1, cryptsize, f);
    fclose(f);
    fprintf(stderr, "[darkmach-decrypt] wrote %lu bytes to %s\n", cryptsize, out);
    _exit(0);
}
