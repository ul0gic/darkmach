/* Crypto interceptor: keys, algorithms, IVs via CommonCrypto/SecKey hooks. See docs/interceptors.md. */
#include "darkmach-core.h"
#include <CommonCrypto/CommonCrypto.h>
#include <dlfcn.h>

#define MOD "crypto"

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

    return status;
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

    return result;
}

struct interpose_pair {
    const void *replacement;
    const void *original;
};

__attribute__((used, section("__DATA,__interpose")))
static struct interpose_pair interpose_pairs[] = {
    { (const void *)hooked_CCCrypt,    (const void *)CCCrypt },
    { (const void *)hooked_CC_SHA256,  (const void *)CC_SHA256 },
    { (const void *)hooked_CC_SHA1,    (const void *)CC_SHA1 },
};

__attribute__((constructor))
static void darkmach_crypto_init(void) {
    fprintf(stderr, "[darkmach-crypto] initializing crypto interceptor\n");
    darkmach_log_init(MOD);

    orig_CCCrypt = CCCrypt;
    orig_CC_SHA256 = CC_SHA256;
    orig_CC_SHA1 = CC_SHA1;

    darkmach_log(MOD, "init",
               "\"hooks\":[\"CCCrypt\",\"CC_SHA256\",\"CC_SHA1\"]");
    fprintf(stderr, "[darkmach-crypto] ready — CCCrypt + SHA256 + SHA1 hooked\n");
}
