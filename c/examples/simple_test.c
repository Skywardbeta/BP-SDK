/*
 * Simple test: Initialize SDK, send a bundle, shutdown.
 */
#include "bp_sdk.h"
#include <stdio.h>

int main(void) {
    int rc = bp_init("ipn:1.0", NULL);
    if (rc != BP_SUCCESS) {
        printf("bp_init failed: %s\n", bp_strerror(rc));
        return 1;
    }
    printf("SDK initialized.\n");

    rc = bp_send("ipn:1.1", "ipn:2.1", "Hello DTN", 9, BP_PRIORITY_STANDARD, BP_CUSTODY_NONE, 3600, NULL);
    printf("bp_send: %s\n", bp_strerror(rc));

    bp_shutdown();
    printf("SDK shutdown.\n");
    return 0;
}
