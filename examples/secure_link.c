/*
 * secure_link - Drive a stack's native BPSec engine through the adapter.
 *
 * The same application code targets ION-DTN (bpsecadmin) or uD3TN (AAP):
 * only the stack name on the command line changes. The developer declares
 * intent + key references once; the SDK lowers and registers the policy with
 * the host BPA, which owns BIB/BCB and forwarding.
 *
 *   secure_link ion    rc=node.bpsecrc
 *   secure_link ud3tn  host=127.0.0.1;port=4242;agent=app
 */
#include "bp_adapter.h"
#include "bp_session.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *stack  = argc > 1 ? argv[1] : "ion";
    const char *config = argc > 2 ? argv[2] : NULL;

    bp_secure_link_t *link = bp_secure_link_open(stack, config);
    if (!link) {
        fprintf(stderr, "cannot open '%s' link\n", stack);
        return 1;
    }

    if (bp_secure_link_set_source(link, "dtn://sat-1/telemetry") != BPSEC_SUCCESS) {
        bp_secure_link_close(link);
        return 1;
    }

    bp_security_policy_t policy = {
        .mode        = BPSEC_MODE_BIB_BCB,
        .bib_context = BPSEC_CTX_HMAC_SHA2_256,
        .bib_targets = BPSEC_TARGET_PAYLOAD,
        .bib_scope   = BPSEC_SCOPE_BTSD_ONLY,
        .bib_key_ref = "ground-int-key",
        .bcb_context = BPSEC_CTX_AES_GCM_256,
        .bcb_targets = BPSEC_TARGET_PAYLOAD,
        .bcb_scope   = BPSEC_SCOPE_BTSD_ONLY,
        .bcb_key_ref = "ground-conf-key",
    };
    int rc = bp_secure_link_set_security(link, &policy);
    if (rc != BPSEC_SUCCESS) {
        fprintf(stderr, "set_security: %s\n", bp_session_strerror(rc));
        bp_secure_link_close(link);
        return 1;
    }

    const char *msg = "secure telemetry frame";
    rc = bp_secure_link_send(link, "dtn://ground/sink",
                             (const uint8_t *)msg, strlen(msg), NULL);
    if (rc != BPSEC_SUCCESS) {
        fprintf(stderr, "send (%s): %s\n", bp_secure_link_stack(link),
                bp_session_strerror(rc));
        bp_secure_link_close(link);
        return 1;
    }

    printf("[%s] declared BIB+BCB intent and handed payload to the BPA\n",
           bp_secure_link_stack(link));
    bp_secure_link_close(link);
    return 0;
}
