/* Crypto interceptor: keys, algorithms, IVs via CommonCrypto/SecKey hooks. See docs/interceptors.md. */
#include "darkmach-core.h"
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>
#include <dlfcn.h>

#define MOD "crypto"

/* Read by darkmach-bridge's crypto_tap to tell "no crypto" from "nothing watched". */
int darkmach_crypto_hooks_installed = 0;

static void crypto_report_cccrypt(CCOperation op, CCAlgorithm alg, CCOptions opts,
                                  const void *key, size_t keyLength, const void *iv,
                                  size_t dataInLength, const void *dataOut,
                                  size_t dataOutLength, int status) {
    static void (*record)(uint32_t, uint32_t, uint32_t, const void *, size_t,
                          const void *, size_t, const void *, size_t, int) = NULL;
    if (!record)
        record = (void (*)(uint32_t, uint32_t, uint32_t, const void *, size_t,
                           const void *, size_t, const void *, size_t, int))
            dlsym(RTLD_DEFAULT, "darkmach_crypto_record_cccrypt");
    if (record) record(op, alg, opts, key, keyLength, iv,
                       dataInLength, dataOut, dataOutLength, status);
}

static void crypto_report_cchmac(CCHmacAlgorithm alg, const void *key, size_t keyLength,
                                 size_t dataLength, const void *macOut) {
    static void (*record)(uint32_t, const void *, size_t, size_t, const void *) = NULL;
    if (!record)
        record = (void (*)(uint32_t, const void *, size_t, size_t, const void *))
            dlsym(RTLD_DEFAULT, "darkmach_crypto_record_cchmac");
    if (record) record(alg, key, keyLength, dataLength, macOut);
}

static void crypto_report_digest(const char *algorithm, size_t dataLength) {
    static void (*record)(const char *, size_t) = NULL;
    if (!record)
        record = (void (*)(const char *, size_t))
            dlsym(RTLD_DEFAULT, "darkmach_crypto_record_digest");
    if (record) record(algorithm, dataLength);
}

static const char *cc_alg_name(CCAlgorithm alg) {
    switch (alg) {
        case kCCAlgorithmAES128: return "AES";
        case kCCAlgorithmDES:    return "DES";
        case kCCAlgorithm3DES:   return "3DES";
        case kCCAlgorithmCAST:   return "CAST";
        case kCCAlgorithmRC4:    return "RC4";
        case kCCAlgorithmRC2:    return "RC2";
        case kCCAlgorithmBlowfish: return "Blowfish";
        default: return "Unknown";
    }
}

static const char *cc_op_name(CCOperation op) {
    return op == kCCEncrypt ? "encrypt" : "decrypt";
}

static void hex_encode(const void *data, size_t len, char *buf, size_t bufsize) {
    if (!data || len == 0) { snprintf(buf, bufsize, "null"); return; }
    size_t pos = 0;
    pos += snprintf(buf + pos, bufsize - pos, "\"");
    size_t log_len = len > 64 ? 64 : len;
    for (size_t i = 0; i < log_len && pos < bufsize - 4; i++) {
        pos += snprintf(buf + pos, bufsize - pos, "%02x", ((const unsigned char *)data)[i]);
    }
    if (len > 64) pos += snprintf(buf + pos, bufsize - pos, "...");
    snprintf(buf + pos, bufsize - pos, "\"");
}

static CCCryptorStatus (*orig_CCCrypt)(
    CCOperation, CCAlgorithm, CCOptions,
    const void *, size_t,
    const void *,
    const void *, size_t,
    void *, size_t,
    size_t *) = NULL;

static CCCryptorStatus hooked_CCCrypt(
    CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength,
    const void *iv,
    const void *dataIn, size_t dataInLength,
    void *dataOut, size_t dataOutAvailable,
    size_t *dataOutMoved)
{
    char key_hex[256], iv_hex[256];
    hex_encode(key, keyLength, key_hex, sizeof(key_hex));
    hex_encode(iv, iv ? 16 : 0, iv_hex, sizeof(iv_hex));

    char input_hex[256];
    hex_encode(dataIn, dataInLength > 32 ? 32 : dataInLength, input_hex, sizeof(input_hex));

    CCCryptorStatus status = orig_CCCrypt(
        op, alg, options, key, keyLength, iv,
        dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);

    char output_hex[256] = "null";
    if (status == kCCSuccess && dataOut && dataOutMoved && *dataOutMoved > 0) {
        hex_encode(dataOut, *dataOutMoved > 32 ? 32 : *dataOutMoved,
                   output_hex, sizeof(output_hex));
    }

    char data[2048];
    snprintf(data, sizeof(data),
             "\"op\":\"%s\",\"alg\":\"%s\",\"keyLen\":%zu,\"key\":%s,"
             "\"iv\":%s,\"inLen\":%zu,\"input\":%s,"
             "\"outLen\":%zu,\"output\":%s,\"status\":%d",
             cc_op_name(op), cc_alg_name(alg), keyLength, key_hex,
             iv_hex, dataInLength, input_hex,
             dataOutMoved ? *dataOutMoved : 0, output_hex, (int)status);

    darkmach_log(MOD, "cccrypt", data);

    fprintf(stderr, "[darkmach-crypto] CCCrypt %s %s keyLen=%zu inLen=%zu status=%d\n",
            cc_op_name(op), cc_alg_name(alg), keyLength, dataInLength, (int)status);

    crypto_report_cccrypt(op, alg, options, key, keyLength, iv, dataInLength,
                          dataOut, dataOutMoved ? *dataOutMoved : 0, (int)status);

    return status;
}


static const char *cc_hmac_name(CCHmacAlgorithm alg) {
    switch (alg) {
        case kCCHmacAlgSHA1:   return "HMAC-SHA1";
        case kCCHmacAlgSHA224: return "HMAC-SHA224";
        case kCCHmacAlgSHA256: return "HMAC-SHA256";
        case kCCHmacAlgSHA384: return "HMAC-SHA384";
        case kCCHmacAlgSHA512: return "HMAC-SHA512";
        case kCCHmacAlgMD5:    return "HMAC-MD5";
        default:               return "HMAC-Unknown";
    }
}

static void (*orig_CCHmac)(CCHmacAlgorithm, const void *, size_t,
                           const void *, size_t, void *) = NULL;

static void hooked_CCHmac(CCHmacAlgorithm algorithm,
                          const void *key, size_t keyLength,
                          const void *data, size_t dataLength, void *macOut)
{
    orig_CCHmac(algorithm, key, keyLength, data, dataLength, macOut);

    char key_hex[256], input_hex[256];
    hex_encode(key, keyLength, key_hex, sizeof(key_hex));
    hex_encode(data, dataLength > 32 ? 32 : dataLength, input_hex, sizeof(input_hex));

    char log_data[1024];
    snprintf(log_data, sizeof(log_data),
             "\"alg\":\"%s\",\"keyLen\":%zu,\"key\":%s,\"inLen\":%zu,\"input\":%s",
             cc_hmac_name(algorithm), keyLength, key_hex, dataLength, input_hex);
    darkmach_log(MOD, "cchmac", log_data);

    fprintf(stderr, "[darkmach-crypto] CCHmac %s keyLen=%zu inLen=%zu\n",
            cc_hmac_name(algorithm), keyLength, dataLength);

    crypto_report_cchmac(algorithm, key, keyLength, dataLength, macOut);
}


static unsigned char *(*orig_CC_SHA256)(const void *, CC_LONG, unsigned char *) = NULL;

static unsigned char *hooked_CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_SHA256(data, len, md);

    char input_hex[256], output_hex[256];
    hex_encode(data, len > 64 ? 64 : len, input_hex, sizeof(input_hex));
    hex_encode(result, CC_SHA256_DIGEST_LENGTH, output_hex, sizeof(output_hex));

    char log_data[1024];
    snprintf(log_data, sizeof(log_data),
             "\"alg\":\"SHA256\",\"inLen\":%u,\"input\":%s,\"hash\":%s",
             len, input_hex, output_hex);
    darkmach_log(MOD, "hash", log_data);

    crypto_report_digest("CC_SHA256", len);

    return result;
}

static unsigned char *(*orig_CC_SHA1)(const void *, CC_LONG, unsigned char *) = NULL;

static unsigned char *hooked_CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *result = orig_CC_SHA1(data, len, md);

    char input_hex[256], output_hex[256];
    hex_encode(data, len > 64 ? 64 : len, input_hex, sizeof(input_hex));
    hex_encode(result, CC_SHA1_DIGEST_LENGTH, output_hex, sizeof(output_hex));

    char log_data[1024];
    snprintf(log_data, sizeof(log_data),
             "\"alg\":\"SHA1\",\"inLen\":%u,\"input\":%s,\"hash\":%s",
             len, input_hex, output_hex);
    darkmach_log(MOD, "hash", log_data);

    crypto_report_digest("CC_SHA1", len);

    return result;
}

struct interpose_pair {
    const void *replacement;
    const void *original;
};

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_pair interpose_pairs[] = {
    { (const void *)hooked_CCCrypt,    (const void *)CCCrypt },
    { (const void *)hooked_CCHmac,     (const void *)CCHmac },
    { (const void *)hooked_CC_SHA256,  (const void *)CC_SHA256 },
    { (const void *)hooked_CC_SHA1,    (const void *)CC_SHA1 },
};

__attribute__((constructor))
static void darkmach_crypto_init(void) {
    fprintf(stderr, "[darkmach-crypto] initializing crypto interceptor\n");
    darkmach_log_init(MOD);

    /* Direct references, never dlsym: dlsym returns this image's own interposed hook. */
    orig_CCCrypt = CCCrypt;
    orig_CCHmac = CCHmac;
    orig_CC_SHA256 = CC_SHA256;
    orig_CC_SHA1 = CC_SHA1;

    darkmach_crypto_hooks_installed =
        (orig_CCCrypt && orig_CCHmac && orig_CC_SHA256 && orig_CC_SHA1) ? 1 : 0;

    char data[256];
    snprintf(data, sizeof(data),
             "\"hooks\":[\"CCCrypt\",\"CCHmac\",\"CC_SHA256\",\"CC_SHA1\"],\"installed\":%s",
             darkmach_crypto_hooks_installed ? "true" : "false");
    darkmach_log(MOD, "init", data);

    fprintf(stderr, "[darkmach-crypto] ready — CommonCrypto %s\n",
            darkmach_crypto_hooks_installed ? "hooked (CCCrypt, CCHmac, SHA256, SHA1)"
                                            : "NOT hooked");
}
