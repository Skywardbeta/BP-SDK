/*
 * bp_key_provider.c - Default and file-backed BPSec key providers.
 *
 * Both providers honour an "expected usage" hint (BP_KEY_USAGE_HMAC vs
 * BP_KEY_USAGE_AES) so that a session asking for an integrity key cannot
 * accidentally pull a confidentiality key (or vice versa). Expired keys
 * are filtered as well, even if the keystore has not yet purged them.
 *
 * Time units:
 *   The provider contract (bp_key_provider_t.get_key_expiry) returns
 *   DTN milliseconds, matching BPv7 lifetime units used by the session.
 *   The legacy bpsec_keystore_t API stores expires_at as DTN seconds;
 *   the keystore-backed wrapper here converts seconds -> ms on read.
 *   The file-backed provider stores DTN milliseconds as written.
 */
#include "bp_key_provider.h"
#include "bp_utils.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION mutex_t;
typedef INIT_ONCE        once_t;
#define ONCE_INIT INIT_ONCE_STATIC_INIT
static BOOL CALLBACK once_thunk(PINIT_ONCE o, PVOID p, PVOID *c) {
    (void)o; (void)c;
    ((void (*)(void))p)();
    return TRUE;
}
static void run_once(once_t *o, void (*fn)(void)) {
    InitOnceExecuteOnce(o, once_thunk, (PVOID)fn, NULL);
}
#define mutex_init(m)    InitializeCriticalSection(m)
#define mutex_lock(m)    EnterCriticalSection(m)
#define mutex_unlock(m)  LeaveCriticalSection(m)
#else
#include <pthread.h>
typedef pthread_mutex_t mutex_t;
typedef pthread_once_t  once_t;
#define ONCE_INIT PTHREAD_ONCE_INIT
static void run_once(once_t *o, void (*fn)(void)) { pthread_once(o, fn); }
#define mutex_init(m)    pthread_mutex_init(m, NULL)
#define mutex_lock(m)    pthread_mutex_lock(m)
#define mutex_unlock(m)  pthread_mutex_unlock(m)
#endif

static int usage_matches(uint8_t entry_type, int requested_usage) {
    if (requested_usage == BP_KEY_USAGE_ANY) return 1;
    if (requested_usage == BP_KEY_USAGE_HMAC) return entry_type == BPSEC_KEY_TYPE_HMAC;
    if (requested_usage == BP_KEY_USAGE_AES)  return entry_type == BPSEC_KEY_TYPE_AES;
    return 0;
}

static uint64_t now_dtn_ms(void) {
    return bp_time_now_dtn() * 1000ULL;
}

static int entry_is_live(const bpsec_key_entry_t *e) {
    if (e->expires_at == 0) return 1;
    return e->expires_at > bp_time_now_dtn();
}

static int ks_get_key(void *pctx, const char *key_ref, int usage,
                      uint8_t *key_buf, size_t buf_size, size_t *key_len) {
    if (!pctx || !key_ref || !key_buf || !key_len) return -1;
    bpsec_keystore_t *ks = pctx;
    bpsec_key_entry_t entry;
    int rc = -1;
    if (bpsec_keystore_get(ks, key_ref, &entry) == 0
        && usage_matches(entry.type, usage)
        && entry_is_live(&entry)
        && entry.data_len <= buf_size) {
        memcpy(key_buf, entry.data, entry.data_len);
        *key_len = entry.data_len;
        rc = 0;
    }
    memset(&entry, 0, sizeof(entry));
    return rc;
}

static int ks_key_available(void *pctx, const char *key_ref, int usage) {
    if (!pctx || !key_ref) return -1;
    bpsec_keystore_t *ks = pctx;
    bpsec_key_entry_t entry;
    int rc = -1;
    if (bpsec_keystore_get(ks, key_ref, &entry) == 0
        && usage_matches(entry.type, usage)
        && entry_is_live(&entry)) {
        rc = 0;
    }
    memset(&entry, 0, sizeof(entry));
    return rc;
}

static int ks_get_key_expiry(void *pctx, const char *key_ref, uint64_t *expiry_ms) {
    if (!pctx || !key_ref || !expiry_ms) return -1;
    bpsec_keystore_t *ks = pctx;
    bpsec_key_entry_t entry;
    if (bpsec_keystore_get(ks, key_ref, &entry) < 0) return -1;
    uint64_t secs = entry.expires_at;
    memset(&entry, 0, sizeof(entry));
    if (secs == 0) { *expiry_ms = 0; return 0; }
    if (secs > UINT64_MAX / 1000ULL) { *expiry_ms = UINT64_MAX; return 0; }
    *expiry_ms = secs * 1000ULL;
    return 0;
}

bp_key_provider_t bp_key_provider_keystore(bpsec_keystore_t *ks) {
    bp_key_provider_t p = {0};
    p.get_key        = ks_get_key;
    p.key_available  = ks_key_available;
    p.get_key_expiry = ks_get_key_expiry;
    p.provider_ctx   = ks;
    return p;
}

typedef struct {
    char    *id;
    uint8_t  type;
    uint8_t  data[BP_KEY_PROVIDER_MAX_KEY_LEN];
    size_t   data_len;
    uint64_t expires_at;
} file_key_t;

struct bp_key_provider_file {
    file_key_t *keys;
    size_t      count;
    size_t      capacity;
};

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len == 0 || (hex_len % 2) != 0) return -1;
    size_t bytes = hex_len / 2;
    if (bytes > out_cap) return -1;
    for (size_t i = 0; i < bytes; i++) {
        int hi = hex_nibble((unsigned char)hex[i * 2]);
        int lo = hex_nibble((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = bytes;
    return 0;
}

static int file_keys_grow(bp_key_provider_file_t *p) {
    size_t new_cap = p->capacity ? p->capacity * 2 : 8;
    file_key_t *nk = bp_realloc(p->keys, new_cap * sizeof(*nk));
    if (!nk) return -1;
    memset(nk + p->capacity, 0, (new_cap - p->capacity) * sizeof(*nk));
    p->keys = nk;
    p->capacity = new_cap;
    return 0;
}

static char *trim_inplace(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
    return s;
}

static int parse_key_type(const char *tok, uint8_t *out) {
    if (!tok) return -1;
    if (strcmp(tok, "hmac") == 0) { *out = BPSEC_KEY_TYPE_HMAC; return 0; }
    if (strcmp(tok, "aes")  == 0) { *out = BPSEC_KEY_TYPE_AES;  return 0; }
    return -1;
}

/*
 * File format (one key per line):
 *
 *     <key_id> <type> <hex_bytes> [<expiry_dtn_ms>]
 *
 * `type` is the literal token `hmac` or `aes`. Length-based guessing
 * was removed because it misclassifies common 32-byte HMAC-SHA-256 keys
 * as AES. Lines beginning with '#' and blank lines are ignored.
 */
bp_key_provider_file_t *bp_key_provider_file_create(const char *path) {
    if (!path) return NULL;
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;

    bp_key_provider_file_t *p = bp_alloc(sizeof(*p));
    if (!p) { fclose(fp); return NULL; }
    memset(p, 0, sizeof(*p));

    char line[1024];
    int line_no = 0;
    while (fgets(line, sizeof(line), fp)) {
        line_no++;
        char *t = trim_inplace(line);
        if (*t == '\0' || *t == '#') continue;
        char id[BPSEC_KEY_MAX_ID_LEN];
        char type_tok[8];
        char hex[BP_KEY_PROVIDER_MAX_KEY_LEN * 2 + 1];
        unsigned long long expiry = 0;
        int n = sscanf(t, "%63s %7s %256s %llu", id, type_tok, hex, &expiry);
        if (n < 3) {
            bp_log(BP_LOG_WARN, "key provider %s:%d: malformed line", path, line_no);
            continue;
        }
        uint8_t key_type;
        if (parse_key_type(type_tok, &key_type) < 0) {
            bp_log(BP_LOG_WARN,
                   "key provider %s:%d: unknown type '%s' (expected hmac or aes)",
                   path, line_no, type_tok);
            continue;
        }
        uint8_t bytes[BP_KEY_PROVIDER_MAX_KEY_LEN];
        size_t bytes_len = 0;
        if (hex_decode(hex, bytes, sizeof(bytes), &bytes_len) < 0) {
            bp_log(BP_LOG_WARN, "key provider %s:%d: invalid hex", path, line_no);
            memset(bytes, 0, sizeof(bytes));
            continue;
        }
        if (p->count >= p->capacity && file_keys_grow(p) < 0) {
            memset(bytes, 0, sizeof(bytes));
            goto fail;
        }
        file_key_t *k = &p->keys[p->count];
        memset(k, 0, sizeof(*k));
        memcpy(k->data, bytes, bytes_len);
        k->data_len = bytes_len;
        memset(bytes, 0, sizeof(bytes));
        k->id = bp_strdup(id);
        if (!k->id) { memset(k->data, 0, sizeof(k->data)); goto fail; }
        k->type = key_type;
        k->expires_at = (uint64_t)expiry;
        p->count++;
    }
    fclose(fp);
    return p;

fail:
    fclose(fp);
    bp_key_provider_file_destroy(p);
    return NULL;
}

void bp_key_provider_file_destroy(bp_key_provider_file_t *p) {
    if (!p) return;
    for (size_t i = 0; i < p->count; i++) {
        memset(p->keys[i].data, 0, sizeof(p->keys[i].data));
        bp_free(p->keys[i].id);
    }
    bp_free(p->keys);
    bp_free(p);
}

static const file_key_t *file_lookup(const bp_key_provider_file_t *p,
                                     const char *key_ref) {
    if (!p || !key_ref) return NULL;
    for (size_t i = 0; i < p->count; i++) {
        if (p->keys[i].id && strcmp(p->keys[i].id, key_ref) == 0) {
            return &p->keys[i];
        }
    }
    return NULL;
}

static int file_key_live(const file_key_t *k) {
    return k->expires_at == 0 || k->expires_at > now_dtn_ms();
}

static int file_get_key(void *pctx, const char *key_ref, int usage,
                        uint8_t *key_buf, size_t buf_size, size_t *key_len) {
    const file_key_t *k = file_lookup(pctx, key_ref);
    if (!k || !file_key_live(k)) return -1;
    if (!usage_matches(k->type, usage)) return -1;
    if (k->data_len > buf_size) return -1;
    memcpy(key_buf, k->data, k->data_len);
    *key_len = k->data_len;
    return 0;
}

static int file_key_available(void *pctx, const char *key_ref, int usage) {
    const file_key_t *k = file_lookup(pctx, key_ref);
    if (!k || !file_key_live(k)) return -1;
    if (!usage_matches(k->type, usage)) return -1;
    return 0;
}

static int file_get_key_expiry(void *pctx, const char *key_ref, uint64_t *expiry_ms) {
    const file_key_t *k = file_lookup(pctx, key_ref);
    if (!k) return -1;
    *expiry_ms = k->expires_at;
    return 0;
}

bp_key_provider_t bp_key_provider_file_make(bp_key_provider_file_t *p) {
    bp_key_provider_t kp = {0};
    kp.get_key        = file_get_key;
    kp.key_available  = file_key_available;
    kp.get_key_expiry = file_get_key_expiry;
    kp.provider_ctx   = p;
    return kp;
}

static once_t            g_init_once = ONCE_INIT;
static mutex_t           g_mutex;
static bpsec_keystore_t *g_default_ks = NULL;
static bp_key_provider_t g_default_provider;
static bp_key_provider_t g_active_provider;
static int               g_active_set = 0;
static int               g_default_provider_set = 0;

static void init_globals(void) {
    mutex_init(&g_mutex);
}

bpsec_keystore_t *bpsdk_default_keystore(void) {
    run_once(&g_init_once, init_globals);
    mutex_lock(&g_mutex);
    if (!g_default_ks) g_default_ks = bpsec_keystore_create(16);
    bpsec_keystore_t *ks = g_default_ks;
    mutex_unlock(&g_mutex);
    return ks;
}

int bpsdk_register_key_provider(const bp_key_provider_t *provider) {
    run_once(&g_init_once, init_globals);
    if (provider && (!provider->get_key || !provider->key_available)) return -1;

    mutex_lock(&g_mutex);
    if (provider) {
        g_active_provider = *provider;
        g_active_set = 1;
    } else {
        memset(&g_active_provider, 0, sizeof(g_active_provider));
        g_active_set = 0;
    }
    mutex_unlock(&g_mutex);
    return 0;
}

const bp_key_provider_t *bpsdk_get_key_provider(void) {
    run_once(&g_init_once, init_globals);

    mutex_lock(&g_mutex);
    if (g_active_set) {
        const bp_key_provider_t *p = &g_active_provider;
        mutex_unlock(&g_mutex);
        return p;
    }
    mutex_unlock(&g_mutex);

    bpsec_keystore_t *ks = bpsdk_default_keystore();

    mutex_lock(&g_mutex);
    if (!g_default_provider_set && ks) {
        g_default_provider = bp_key_provider_keystore(ks);
        g_default_provider_set = 1;
    }
    const bp_key_provider_t *p = g_default_provider_set ? &g_default_provider : NULL;
    mutex_unlock(&g_mutex);
    return p;
}
