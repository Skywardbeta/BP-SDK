/*
 * sender.c - Send a bundle to a receiver
 * Usage: sender <dest_eid> <message>
 */
#include "bp_sdk.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <dest_eid> <message>\n", argv[0]);
        printf("Example: %s ipn:2.1 \"Hello DTN\"\n", argv[0]);
        return 1;
    }

    const char *dest = argv[1];
    const char *msg = argv[2];

    if (bp_init("ipn:1.0", NULL) != BP_SUCCESS) {
        fprintf(stderr, "Failed to initialize SDK\n");
        return 1;
    }

    int rc = bp_send("ipn:1.1", dest, msg, strlen(msg), BP_PRIORITY_STANDARD, BP_CUSTODY_NONE, 3600, NULL);
    printf("bp_send: %s\n", bp_strerror(rc));

    bp_shutdown();
    return rc == BP_SUCCESS ? 0 : 1;
}
