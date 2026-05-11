/*
 * secure_send - Demonstrate the BPSec session API end-to-end.
 *
 * Provisions an AES-256-GCM key, opens a session bound to a source EID,
 * declares a BCB-AES-GCM-256 policy on the payload, encodes one bundle
 * to wire bytes, then immediately re-processes those bytes through the
 * same session to recover the plaintext. No external peer is required.
 */
#include "bp_sdk.h"
#include "bp_session.h"
#include "bp_key_provider.h"
#include "bp_bpsec_keys.h"
#include "bp_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int provision_demo_key(void) {
    uint8_t key[32];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)i;
    return bpsec_keystore_add(bpsdk_default_keystore(),
                              "demo-bcb-key", BPSEC_KEY_TYPE_AES,
                              key, sizeof(key), NULL, 0);
}

int main(void) {
    if (bp_init("ipn:1.0", NULL) != BP_SUCCESS) return 1;
    if (provision_demo_key() != 0) { bp_shutdown(); return 1; }

    bp_session_t *s = bp_session_open("uplink");
    if (!s) { bp_shutdown(); return 1; }

    if (bp_session_set_source(s, "ipn:1.1") != BPSEC_SUCCESS) {
        bp_session_close(s); bp_shutdown(); return 1;
    }

    bp_security_policy_t policy = {
        .mode        = BPSEC_MODE_BCB_ONLY,
        .bcb_context = BPSEC_CTX_AES_GCM_256,
        .bcb_targets = BPSEC_TARGET_PAYLOAD,
        .bcb_scope   = BPSEC_SCOPE_BTSD_ONLY,
        .bcb_key_ref = "demo-bcb-key",
    };
    int rc = bp_session_set_security(s, &policy);
    if (rc != BPSEC_SUCCESS) {
        fprintf(stderr, "set_security: %s\n", bp_session_strerror(rc));
        bp_session_close(s); bp_shutdown(); return 1;
    }

    const char *payload = "secret telemetry";
    bp_delivery_opts_t opts = {
        .dest_eid    = "ipn:2.1",
        .lifetime_ms = 60000,
    };

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    rc = bp_session_secure_encode(s, (const uint8_t *)payload, strlen(payload),
                                  &opts, &wire, &wire_len);
    if (rc != BPSEC_SUCCESS) {
        fprintf(stderr, "encode: %s\n", bp_session_strerror(rc));
        bp_session_close(s); bp_shutdown(); return 1;
    }
    printf("encoded %zu wire bytes\n", wire_len);

    bp_bundle_t *delivered = NULL;
    rc = bp_session_process_wire(s, wire, wire_len, &delivered);
    if (rc != BPSEC_SUCCESS) {
        fprintf(stderr, "process_wire: %s\n", bp_session_strerror(rc));
        bp_free(wire); bp_session_close(s); bp_shutdown(); return 1;
    }

    printf("recovered \"%.*s\" from %s\n",
           (int)delivered->payload_len, (char *)delivered->payload,
           delivered->source_eid);

    bp_session_stats_t stats;
    bp_session_get_stats(s, &stats);
    printf("stats: secured=%llu decrypted=%llu iv_counter=%llu\n",
           (unsigned long long)stats.bundles_secured,
           (unsigned long long)stats.bundles_decrypted,
           (unsigned long long)stats.iv_counter);

    bp_bundle_free(delivered);
    bp_free(wire);
    bp_session_close(s);
    bp_shutdown();
    return 0;
}
