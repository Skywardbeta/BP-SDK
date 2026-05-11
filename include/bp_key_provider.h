/*
 * bp_key_provider.h - Pluggable key source for BPSec.
 *
 * SecurityService never stores raw key bytes itself; all key material is
 * fetched on demand through a registered key provider so the SDK stays
 * decoupled from the key management protocol (DTKA, BERMUDA, BPSec-MLS,
 * KMS adapters, etc.).
 *
 * Two reference providers are shipped:
 *   - keystore: thin wrapper over the in-process bpsec_keystore_t.
 *   - file:     loads `<key_id> <hmac|aes> <hex_bytes> [<expiry_dtn_ms>]`
 *               lines from a UTF-8 text file. The type token is required;
 *               there is no length-based heuristic. Lines beginning with
 *               '#' and blank lines are ignored.
 */
#ifndef BP_KEY_PROVIDER_H
#define BP_KEY_PROVIDER_H

#include <stdint.h>
#include <stddef.h>

#include "bp_bpsec_keys.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BP_KEY_PROVIDER_MAX_KEY_LEN 64

#define BP_KEY_USAGE_ANY  0
#define BP_KEY_USAGE_HMAC 1
#define BP_KEY_USAGE_AES  2

typedef struct {
    int (*get_key)(void *provider_ctx,
                   const char *key_ref, int usage,
                   uint8_t *key_buf, size_t buf_size, size_t *key_len);

    int (*key_available)(void *provider_ctx, const char *key_ref, int usage);

    /*
     * Report key expiry in DTN milliseconds since the BPv7 epoch, or 0
     * if the key never expires. Used by the session to compare against
     * the bundle's lifetime.
     */
    int (*get_key_expiry)(void *provider_ctx,
                          const char *key_ref, uint64_t *expiry_ms);

    void *provider_ctx;
} bp_key_provider_t;

/*
 * Install a provider globally. The struct is copied; the caller may pass
 * a stack-allocated value. Pass NULL to revert to the default keystore-
 * backed provider.
 *
 * NOTE: register the provider BEFORE the first bp_session_open() and
 * keep the same provider installed for the lifetime of every open
 * session. Sessions resolve the active provider lazily, so a runtime
 * swap while sessions are live can break key resolution mid-flight.
 * Per-session provider snapshots are deferred to a later phase.
 */
int bpsdk_register_key_provider(const bp_key_provider_t *provider);

const bp_key_provider_t *bpsdk_get_key_provider(void);

bpsec_keystore_t *bpsdk_default_keystore(void);

bp_key_provider_t bp_key_provider_keystore(bpsec_keystore_t *ks);

typedef struct bp_key_provider_file bp_key_provider_file_t;

bp_key_provider_file_t *bp_key_provider_file_create(const char *path);
void                    bp_key_provider_file_destroy(bp_key_provider_file_t *p);
bp_key_provider_t       bp_key_provider_file_make(bp_key_provider_file_t *p);

#ifdef __cplusplus
}
#endif

#endif
