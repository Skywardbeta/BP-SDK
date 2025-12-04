#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bp_sdk.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <source_eid> <dest_eid> <message>\n", argv[0]);
        return 1;
    }

    // Initialize BP-SDK
    int result = bp_init(argv[1], NULL);
    if (result != BP_SUCCESS) {
        printf("Failed to initialize: %s\n", bp_strerror(result));
        return 1;
    }

    // Send bundle
    result = bp_send(argv[1], argv[2], argv[3], strlen(argv[3]), 
                     BP_PRIORITY_STANDARD, BP_CUSTODY_NONE, 3600, NULL);
    
    printf("Send %s: %s\n", (result == BP_SUCCESS) ? "OK" : "FAILED", 
           (result == BP_SUCCESS) ? "Bundle sent" : bp_strerror(result));

    bp_shutdown();
    return (result == BP_SUCCESS) ? 0 : 1;
} 