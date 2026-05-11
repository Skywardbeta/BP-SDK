/*
 * hello_send - Smoke-test the SDK lifecycle: init -> send -> shutdown.
 * The bundle is dropped if no peer is listening on the default TCPCL
 * port; the example only verifies the SDK and its POSIX backend load.
 */
#include "bp_sdk.h"
#include <stdio.h>

int main(void) {
    int rc = bp_init("ipn:1.0", NULL);
    if (rc != BP_SUCCESS) {
        fprintf(stderr, "bp_init: %s\n", bp_strerror(rc));
        return 1;
    }

    rc = bp_send("ipn:1.1", "ipn:2.1",
                 "Hello DTN", 9,
                 BP_PRIORITY_STANDARD, BP_CUSTODY_NONE,
                 3600, NULL);
    printf("bp_send: %s\n", bp_strerror(rc));

    bp_shutdown();
    return rc == BP_SUCCESS ? 0 : 1;
}
