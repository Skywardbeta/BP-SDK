/*
 * secure_intent - The same roundtrip as secure_send, driven by intent.
 *
 * The application declares only what it wants (confidentiality on the
 * payload) and a key reference; BP-SDK chooses the RFC 9173 context and
 * scope. No wire-level vocabulary (BCB, AES-GCM, BTSD) appears here.
 */
#include "bp_sdk.h"
#include "bp_security_intent.h"
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
                              "demo-key", BPSEC_KEY_TYPE_AES,
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

    bp_security_intent_t intent = {
        .service = BP_SEC_INTENT_CONFIDENTIAL,
        .target  = BP_SEC_TARGET_PAYLOAD,
        .key_ref = "demo-key",
    };
    int rc = bp_session_set_security_intent(s, &intent);
    if (rc != BPSEC_SUCCESS) {
        fprintf(stderr, "set_security_intent: %s\n", bp_session_strerror(rc));
        bp_session_close(s); bp_shutdown(); return 1;
    }

    const char *payload = "secret telemetry";
    bp_delivery_opts_t opts = { .dest_eid = "ipn:2.1", .lifetime_ms = 60000 };

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

    bp_bundle_free(delivered);
    bp_free(wire);
    bp_session_close(s);
    bp_shutdown();
    return 0;
}
