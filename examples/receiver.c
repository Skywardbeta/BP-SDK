/*
 * receiver.c - Receive bundles on a local endpoint
 * Usage: receiver <local_eid>
 */
#include "bp_sdk.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <local_eid>\n", argv[0]);
        printf("Example: %s ipn:2.1\n", argv[0]);
        return 1;
    }

    const char *local = argv[1];

    if (bp_init("ipn:2.0", NULL) != BP_SUCCESS) {
        fprintf(stderr, "Failed to initialize SDK\n");
        return 1;
    }

    bp_endpoint_t *ep;
    if (bp_endpoint_create(local, &ep) != BP_SUCCESS) {
        fprintf(stderr, "Failed to create endpoint\n");
        bp_shutdown();
        return 1;
    }

    printf("Listening on %s (port 4556)...\n", local);

    bp_bundle_t *bundle;
    int rc = bp_receive(ep, &bundle, 60000);
    if (rc == BP_SUCCESS) {
        printf("Received from %s: %.*s\n", bundle->source_eid, (int)bundle->payload_len, (char*)bundle->payload);
        bp_bundle_free(bundle);
    } else {
        printf("bp_receive: %s\n", bp_strerror(rc));
    }

    bp_endpoint_destroy(ep);
    bp_shutdown();
    return rc == BP_SUCCESS ? 0 : 1;
}
