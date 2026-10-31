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

/* Escape a value destined for a JSON string field. Policy strings and priority
   strings are user-supplied and may contain quotes or backslashes; pasting them
   into the line unescaped would corrupt the record and the parser would drop it
   as malformed — silently losing the very evidence the hook exists to collect. */
static void json_str(char *dst, size_t cap, const char *src) {
    size_t out = 0;
    if (!cap) return;
    dst[0] = '\0';
    if (!src) return;
    for (; *src && out + 2 < cap; src++) {
        unsigned char c = (unsigned char)*src;
        if (c == '"' || c == '\\') {
            dst[out++] = '\\';
            dst[out++] = (char)c;
        } else if (c < 0x20 || c == 0x7f) {
            dst[out++] = ' ';
        } else {
            dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
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
    /* Resolve metadata symbols before the first intercepted operation is logged. */
    if (trace_fd == -1) trace_init();
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
    if (trace_fd == -1) trace_init();
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
    if (trace_fd == -1) trace_init();
    const char *name = NULL;
    if (type && sym_EVP_MD_get0_name) name = sym_EVP_MD_get0_name(type);
    trace_line("EVP_DigestInit_ex", name, NULL, 0, NULL);
    return rc;
}

int EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type, const OSSL_PARAM *params) {
    static int (*real)(EVP_MD_CTX *, const EVP_MD *, const OSSL_PARAM *) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "EVP_DigestInit_ex2");
    int rc = real(ctx, type, params);
    if (trace_fd == -1) trace_init();
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
    char extra[1024], escaped[768];
    json_str(escaped, sizeof(escaped), str);
    snprintf(extra, sizeof(extra), ",\"cipher_list\":\"%s\"", escaped);
    trace_line("SSL_CTX_set_cipher_list", "TLS", NULL, 0, extra);
    return rc;
}

/* TLS 1.3 suites are configured through a *different* setter than TLS 1.2 and
   below: a process that only calls set_ciphersuites was recorded as having set
   no cipher policy at all. */
int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str) {
    static int (*real)(SSL_CTX *, const char *) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "SSL_CTX_set_ciphersuites");
    if (!real) return 0;
    int rc = real(ctx, str);
    char extra[1024], escaped[768];
    json_str(escaped, sizeof(escaped), str);
    snprintf(extra, sizeof(extra), ",\"ciphersuites\":\"%s\"", escaped);
    trace_line("SSL_CTX_set_ciphersuites", "TLS", NULL, 0, extra);
    return rc;
}

/* ====================================================================== */
/* GnuTLS — a second native TLS stack, hooked at the same level           */
/* ====================================================================== */
/*
 * OpenSSL is the stack a bank's C services usually link, but not the only one:
 * wget, exim, cups, libvirt, gnome-keyring, MariaDB's TLS, many distro builds of
 * curl and PHP all link libgnutls and link **no** libcrypto at all. Before this
 * section a perfectly observable process using GnuTLS produced nothing, and
 * "nothing observed" then read the same as "nothing ran".
 *
 * Same rule as the OpenSSL hooks: forward every argument untouched, never read
 * key material. The key buffer handed to gnutls_cipher_init / gnutls_hmac_init
 * is measured (`key->size`, `keylen`) and never dereferenced past its length.
 *
 * Enums in GnuTLS are small integers, so algorithm names come from the stack's
 * own getters through dlsym — the shim carries no GnuTLS table that could drift
 * from the library it is tracing. Every getter is optional: an older libgnutls
 * simply yields an empty name, never a guessed one.
 */

typedef struct gnutls_datum_st {
    unsigned int size;
    unsigned char *data;
} gnutls_datum_t;

static const char *(*sym_gnutls_cipher_get_name)(int) = NULL;
static const char *(*sym_gnutls_hash_get_name)(int) = NULL;
static const char *(*sym_gnutls_mac_get_name)(int) = NULL;
static const char *(*sym_gnutls_protocol_get_name)(int) = NULL;
static const char *(*sym_gnutls_kx_get_name)(int) = NULL;
static int (*sym_gnutls_cipher_get)(void *) = NULL;
static int (*sym_gnutls_protocol_get_version)(void *) = NULL;
static int (*sym_gnutls_kx_get)(void *) = NULL;

static void gnutls_meta_init(void) {
    if (sym_gnutls_cipher_get_name) return;
    sym_gnutls_cipher_get_name =
        (const char *(*)(int))dlsym(RTLD_NEXT, "gnutls_cipher_get_name");
    sym_gnutls_hash_get_name = (const char *(*)(int))dlsym(RTLD_NEXT, "gnutls_hash_get_name");
    sym_gnutls_mac_get_name = (const char *(*)(int))dlsym(RTLD_NEXT, "gnutls_mac_get_name");
    sym_gnutls_protocol_get_name =
        (const char *(*)(int))dlsym(RTLD_NEXT, "gnutls_protocol_get_name");
    sym_gnutls_kx_get_name = (const char *(*)(int))dlsym(RTLD_NEXT, "gnutls_kx_get_name");
    sym_gnutls_cipher_get = (int (*)(void *))dlsym(RTLD_NEXT, "gnutls_cipher_get");
    sym_gnutls_protocol_get_version =
        (int (*)(void *))dlsym(RTLD_NEXT, "gnutls_protocol_get_version");
    sym_gnutls_kx_get = (int (*)(void *))dlsym(RTLD_NEXT, "gnutls_kx_get");
}

/* Forwarding to a NULL pointer is not an option: if the symbol cannot be
   resolved the call returns a documented GnuTLS error (-64,
   GNUTLS_E_UNIMPLEMENTED_FEATURE) instead of pretending it succeeded. */
#define GNUTLS_UNRESOLVED (-64)

int gnutls_priority_set_direct(void *session, const char *priorities, const char **err_pos) {
    static int (*real)(void *, const char *, const char **) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "gnutls_priority_set_direct");
    if (!real) return GNUTLS_UNRESOLVED;
    int rc = real(session, priorities, err_pos);
    char extra[1024], escaped[768];
    json_str(escaped, sizeof(escaped), priorities);
    snprintf(extra, sizeof(extra), ",\"priority\":\"%s\",\"priority_accepted\":%s",
             escaped, rc == 0 ? "true" : "false");
    trace_line("gnutls_priority_set_direct", "GnuTLS", NULL, 0, extra);
    return rc;
}

int gnutls_handshake(void *session) {
    static int (*real)(void *) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "gnutls_handshake");
    if (!real) return GNUTLS_UNRESOLVED;
    int rc = real(session);
    /* Only a completed handshake has a negotiated suite. Reading the getters
       after a failed or interrupted handshake would report the default
       "unknown" cipher as if it were negotiated. */
    if (rc == 0) {
        gnutls_meta_init();
        const char *cipher = sym_gnutls_cipher_get_name && sym_gnutls_cipher_get
                                 ? sym_gnutls_cipher_get_name(sym_gnutls_cipher_get(session))
                                 : NULL;
        const char *proto = sym_gnutls_protocol_get_name && sym_gnutls_protocol_get_version
                                ? sym_gnutls_protocol_get_name(sym_gnutls_protocol_get_version(session))
                                : NULL;
        const char *kx = sym_gnutls_kx_get_name && sym_gnutls_kx_get
                             ? sym_gnutls_kx_get_name(sym_gnutls_kx_get(session))
                             : NULL;
        char extra[512], ep[192], ek[192];
        json_str(ep, sizeof(ep), proto);
        json_str(ek, sizeof(ek), kx);
        snprintf(extra, sizeof(extra), ",\"tls_version\":\"%s\",\"key_exchange\":\"%s\"", ep, ek);
        trace_line("gnutls_handshake", cipher ? cipher : "GnuTLS", NULL, 0, extra);
    }
    return rc;
}

int gnutls_cipher_init(void **handle, int cipher, const gnutls_datum_t *key,
                       const gnutls_datum_t *iv) {
    static int (*real)(void **, int, const gnutls_datum_t *, const gnutls_datum_t *) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "gnutls_cipher_init");
    if (!real) return GNUTLS_UNRESOLVED;
    int rc = real(handle, cipher, key, iv);
    gnutls_meta_init();
    const char *name = sym_gnutls_cipher_get_name ? sym_gnutls_cipher_get_name(cipher) : NULL;
    /* the key *length* only — the key itself is never read */
    long keylen = key ? (long)key->size : 0;
    trace_line("gnutls_cipher_init", name, NULL, keylen, NULL);
    return rc;
}

int gnutls_hash_init(void **dig, int algorithm) {
    static int (*real)(void **, int) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "gnutls_hash_init");
    if (!real) return GNUTLS_UNRESOLVED;
    int rc = real(dig, algorithm);
    gnutls_meta_init();
    const char *name = sym_gnutls_hash_get_name ? sym_gnutls_hash_get_name(algorithm) : NULL;
    trace_line("gnutls_hash_init", name, NULL, 0, NULL);
    return rc;
}

int gnutls_hmac_init(void **dig, int algorithm, const void *key, size_t keylen) {
    static int (*real)(void **, int, const void *, size_t) = NULL;
    if (!real) real = (void *)dlsym(RTLD_NEXT, "gnutls_hmac_init");
    if (!real) return GNUTLS_UNRESOLVED;
    int rc = real(dig, algorithm, key, keylen);
    gnutls_meta_init();
    const char *name = sym_gnutls_mac_get_name ? sym_gnutls_mac_get_name(algorithm) : NULL;
    trace_line("gnutls_hmac_init", name, NULL, (long)keylen, NULL);
    return rc;
}
