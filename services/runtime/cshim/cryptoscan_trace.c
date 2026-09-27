/*
 * cryptoscan_trace.c — LD_PRELOAD crypto-call tracer (ADR-012 path).
 *
 * Intercepts libcrypto EVP calls in any process (openssl CLI, a payment
 * gateway, a Java JNI service) and records one JSONL line per cryptographic
 * operation: cipher/mode/key-size, digest, signature algorithm, key
 * agreement, key generation, and TLS protocol/cipher configuration.
 *
 * Design rules:
 *  - OBSERVATION ONLY: every original argument is forwarded untouched; the
 *    real function always runs. Nothing is modified, blocked, or decrypted.
 *  - No key material is ever read or logged. We record the *algorithm*,
 *    *mode* and *key size* — never key bytes, IVs, or plaintext.
 *  - No OpenSSL headers required: all structs are opaque and every libcrypto
 *    function we call is obtained at runtime via dlsym (symbols present in
 *    OpenSSL 1.1.1 and 3.x).
 *  - The tracer must not call back into libcrypto: hooks only use libc
 *    (snprintf/write/flock) so there is no recursion.
 *
 * Enable per process:  LD_PRELOAD=/path/cryptoscan_trace.so \
 *                       CRYPTOSCAN_TRACE_LOG=/var/log/crypto-trace.jsonl \
 *                       <command>
 * Disable:              CRYPTOSCAN_TRACE_DISABLE=1 (used by the E2E tests
 *                       and by nested tool invocations).
 *
 * Compile: gcc -O2 -fPIC -shared -o cryptoscan_trace.so cryptoscan_trace.c -ldl
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

/* ---- opaque libcrypto types (ABI-compatible, header-free) ---- */
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct engine_st ENGINE;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ossl_param_st OSSL_PARAM;

/* ---- libcrypto functions we call through dlsym ---- */
typedef int (*fn_ctx_keylen)(const EVP_CIPHER_CTX *);
typedef int (*fn_ctx_gettype)(const void *);

static const char *(*sym_EVP_CIPHER_get0_name)(const EVP_CIPHER *) = NULL;
static const char *(*sym_EVP_MD_get0_name)(const EVP_MD *) = NULL;
static int (*sym_EVP_CIPHER_CTX_get_key_length)(const EVP_CIPHER_CTX *) = NULL;

/* ---- tracing state ---- */
static int trace_fd = -1;
static char proc_name[64] = "?";

static void trace_init(void) {
    if (trace_fd != -1) return;
    const char *log_path = getenv("CRYPTOSCAN_TRACE_LOG");
    if (log_path && log_path[0]) {
        trace_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    } else {
        trace_fd = -2; /* disabled: no log configured */
    }
    int fd = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, proc_name, sizeof(proc_name) - 1);
        if (n > 0) proc_name[n] = '\0';
        char *nl = strchr(proc_name, '\n');
        if (nl) *nl = '\0';
        close(fd);
    }
    /* Cast to each pointer's own declared signature, not to a generic
       const void* one: GCC 14 promoted -Wincompatible-pointer-types to an
       error, so a generic-signature cast failed the build outright and
       ensure_shim() reported it as "no C compiler". */
    sym_EVP_CIPHER_get0_name =
        (const char *(*)(const EVP_CIPHER *))dlsym(RTLD_NEXT, "EVP_CIPHER_get0_name");
    sym_EVP_MD_get0_name =
        (const char *(*)(const EVP_MD *))dlsym(RTLD_NEXT, "EVP_MD_get0_name");
    sym_EVP_CIPHER_CTX_get_key_length = (fn_ctx_keylen)dlsym(RTLD_NEXT, "EVP_CIPHER_CTX_get_key_length");
}

static void trace_line(const char *function, const char *algorithm,
                       const char *mode, long key_size, const char *extra) {
    if (getenv("CRYPTOSCAN_TRACE_DISABLE")) return;
    if (trace_fd == -1) trace_init();
    if (trace_fd < 0) return;
    char buf[1024];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int n = snprintf(buf, sizeof(buf),
                     "{\"ts\":%lld.%09ld,\"pid\":%ld,\"process\":\"%s\","
                     "\"function\":\"%s\",\"algorithm\":\"%s\",\"mode\":\"%s\","
                     "\"key_size\":%ld%s}\n",
                     (long long)ts.tv_sec, ts.tv_nsec, (long)getpid(), proc_name,
                     function,
                     algorithm ? algorithm : "",
                     mode ? mode : "",
                     key_size,
                     extra ? extra : "");
    if (n <= 0) return;
    flock(trace_fd, LOCK_EX);
    (void)write(trace_fd, buf, (size_t)n);
    flock(trace_fd, LOCK_UN);
}

/* ---- EVP cipher: enc/dec init (name or EVP_CIPHER*, key length from ctx) ---- */

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl,
                      const unsigned char *key, const unsigned char *iv, int enc) {
    static int (*real)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                       const unsigned char *, const unsigned char *, int) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_CipherInit_ex");
    int rc = real(ctx, type, impl, key, iv, enc);
    const char *name = NULL;
    if (type && sym_EVP_CIPHER_get0_name) name = sym_EVP_CIPHER_get0_name(type);
    long keylen = 0;
    if (ctx && sym_EVP_CIPHER_CTX_get_key_length) keylen = sym_EVP_CIPHER_CTX_get_key_length(ctx);
    trace_line("EVP_CipherInit_ex", name, NULL, keylen, NULL);
    return rc;
}

int EVP_CipherInit_ex2(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key,
                       const unsigned char *iv, int enc, const OSSL_PARAM *params) {
    static int (*real)(EVP_CIPHER_CTX *, const EVP_CIPHER *, const unsigned char *,
                       const unsigned char *, int, const OSSL_PARAM *) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_CipherInit_ex2");
    int rc = real(ctx, type, key, iv, enc, params);
    const char *name = NULL;
    if (type && sym_EVP_CIPHER_get0_name) name = sym_EVP_CIPHER_get0_name(type);
    long keylen = 0;
    if (ctx && sym_EVP_CIPHER_CTX_get_key_length) keylen = sym_EVP_CIPHER_CTX_get_key_length(ctx);
    trace_line("EVP_CipherInit_ex2", name, NULL, keylen, NULL);
    return rc;
}

/* ---- message digest ---- */

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
    static int (*real)(EVP_MD_CTX *, const EVP_MD *, ENGINE *) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_DigestInit_ex");
    int rc = real(ctx, type, impl);
    const char *name = NULL;
    if (type && sym_EVP_MD_get0_name) name = sym_EVP_MD_get0_name(type);
    trace_line("EVP_DigestInit_ex", name, NULL, 0, NULL);
    return rc;
}

int EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type, const OSSL_PARAM *params) {
    static int (*real)(EVP_MD_CTX *, const EVP_MD *, const OSSL_PARAM *) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_DigestInit_ex2");
    int rc = real(ctx, type, params);
    const char *name = NULL;
    if (type && sym_EVP_MD_get0_name) name = sym_EVP_MD_get0_name(type);
    trace_line("EVP_DigestInit_ex2", name, NULL, 0, NULL);
    return rc;
}

/* ---- PKEY operations (sign / verify / enc / dec / derive / keygen) ---- */

static const char *pkey_name(EVP_PKEY *pkey) {
    static const char *(*sym_name)(const EVP_PKEY *) = NULL;
    if (!sym_name)
        sym_name = (const char *(*)(const EVP_PKEY *))dlsym(RTLD_NEXT, "EVP_PKEY_get0_type_name");
    if (!sym_name || !pkey) return NULL;
    return sym_name(pkey);
}

int EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen) {
    static int (*real)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                       const unsigned char *, size_t) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_sign");
    int rc = real(ctx, sig, siglen, tbs, tbslen);
    EVP_PKEY *pkey = NULL;
    static EVP_PKEY *(*sym_pkey)(const EVP_PKEY_CTX *) = NULL;
    if (!sym_pkey) sym_pkey = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_CTX_get0_pkey");
    if (sym_pkey) pkey = sym_pkey(ctx);
    trace_line("EVP_PKEY_sign", pkey_name(pkey), NULL, 0, NULL);
    return rc;
}

int EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
                    const unsigned char *tbs, size_t tbslen) {
    static int (*real)(EVP_PKEY_CTX *, const unsigned char *, size_t,
                       const unsigned char *, size_t) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_verify");
    int rc = real(ctx, sig, siglen, tbs, tbslen);
    EVP_PKEY *pkey = NULL;
    static EVP_PKEY *(*sym_pkey)(const EVP_PKEY_CTX *) = NULL;
    if (!sym_pkey) sym_pkey = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_CTX_get0_pkey");
    if (sym_pkey) pkey = sym_pkey(ctx);
    trace_line("EVP_PKEY_verify", pkey_name(pkey), NULL, 0, NULL);
    return rc;
}

int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen) {
    static int (*real)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                       const unsigned char *, size_t) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_encrypt");
    int rc = real(ctx, out, outlen, in, inlen);
    EVP_PKEY *pkey = NULL;
    static EVP_PKEY *(*sym_pkey)(const EVP_PKEY_CTX *) = NULL;
    if (!sym_pkey) sym_pkey = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_CTX_get0_pkey");
    if (sym_pkey) pkey = sym_pkey(ctx);
    trace_line("EVP_PKEY_encrypt", pkey_name(pkey), NULL, 0, NULL);
    return rc;
}

int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                     const unsigned char *in, size_t inlen) {
    static int (*real)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                       const unsigned char *, size_t) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_decrypt");
    int rc = real(ctx, out, outlen, in, inlen);
    EVP_PKEY *pkey = NULL;
    static EVP_PKEY *(*sym_pkey)(const EVP_PKEY_CTX *) = NULL;
    if (!sym_pkey) sym_pkey = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_CTX_get0_pkey");
    if (sym_pkey) pkey = sym_pkey(ctx);
    trace_line("EVP_PKEY_decrypt", pkey_name(pkey), NULL, 0, NULL);
    return rc;
}

int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
    static int (*real)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_derive");
    int rc = real(ctx, key, keylen);
    EVP_PKEY *pkey = NULL;
    static EVP_PKEY *(*sym_pkey)(const EVP_PKEY_CTX *) = NULL;
    if (!sym_pkey) sym_pkey = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_CTX_get0_pkey");
    if (sym_pkey) pkey = sym_pkey(ctx);
    trace_line("EVP_PKEY_derive", pkey_name(pkey), NULL, 0, NULL);
    return rc;
}

int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) {
    static int (*real)(EVP_PKEY_CTX *, EVP_PKEY **) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_PKEY_keygen");
    int rc = real(ctx, ppkey);
    EVP_PKEY *pkey = NULL;
    if (ppkey) pkey = *ppkey;
    trace_line("EVP_PKEY_keygen", pkey_name(pkey), NULL, 0, NULL);
    return rc;
}

/* ---- TLS configuration hooks ---- */

int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, long version) {
    static int (*real)(SSL_CTX *, long) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "SSL_CTX_set_min_proto_version");
    int rc = real(ctx, version);
    char extra[128];
    snprintf(extra, sizeof(extra), ",\"tls_min_version\":%ld", version);
    trace_line("SSL_CTX_set_min_proto_version", "TLS", NULL, 0, extra);
    return rc;
}

int SSL_CTX_set_max_proto_version(SSL_CTX *ctx, long version) {
    static int (*real)(SSL_CTX *, long) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "SSL_CTX_set_max_proto_version");
    int rc = real(ctx, version);
    char extra[128];
    snprintf(extra, sizeof(extra), ",\"tls_max_version\":%ld", version);
    trace_line("SSL_CTX_set_max_proto_version", "TLS", NULL, 0, extra);
    return rc;
}

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
    static int (*real)(SSL_CTX *, const char *) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "SSL_CTX_set_cipher_list");
    int rc = real(ctx, str);
    char extra[1024];
    snprintf(extra, sizeof(extra), ",\"cipher_list\":\"%s\"", str ? str : "");
    trace_line("SSL_CTX_set_cipher_list", "TLS", NULL, 0, extra);
    return rc;
}
