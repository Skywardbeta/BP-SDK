#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bp_sdk.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <endpoint_id>\n", argv[0]);
        printf("Example: %s ipn:2.1\n", argv[0]);
        return 1;
    }

    const char *endpoint_id = argv[1];

    printf("Initializing BP-SDK...\n");
    int result = bp_init(endpoint_id, NULL);
    if (result != BP_SUCCESS) {
        printf("Failed to initialize BP-SDK: %s\n", bp_strerror(result));
        return 1;
    }

    bp_endpoint_t *endpoint;
    result = bp_endpoint_create(endpoint_id, &endpoint);
    if (result != BP_SUCCESS) {
        printf("Failed to create endpoint: %s\n", bp_strerror(result));
        bp_shutdown();
        return 1;
    }

    result = bp_endpoint_register(endpoint);
    if (result != BP_SUCCESS) {
        printf("Failed to register endpoint: %s\n", bp_strerror(result));
        bp_endpoint_destroy(endpoint);
        bp_shutdown();
        return 1;
    }

    printf("Listening for bundles on endpoint %s...\n", endpoint_id);
    printf("Press Ctrl+C to stop.\n");

    while (1) {
        bp_bundle_t *bundle;
        result = bp_receive(endpoint, &bundle, 5000);
        
        if (result == BP_SUCCESS) {
            printf("\nReceived bundle:\n");
            printf("  Source EID: %s\n", bundle->source_eid ? bundle->source_eid : "unknown");
            printf("  Creation Time: %llu.%u\n", bundle->creation_time.msec, bundle->creation_time.count);
            printf("  TTL: %u seconds\n", bundle->ttl);
            printf("  Priority: %d\n", bundle->priority);
            printf("  Payload Length: %zu bytes\n", bundle->payload_len);
            
            if (bundle->payload_len > 0) {
                printf("  Message: ");
                fwrite(bundle->payload, 1, bundle->payload_len, stdout);
                printf("\n");
            }
            
            bp_bundle_free(bundle);
        } else if (result == BP_ERROR_TIMEOUT) {
            printf(".");
            fflush(stdout);
        } else {
            printf("Failed to receive bundle: %s\n", bp_strerror(result));
            break;
        }
    }

    printf("\nShutting down BP-SDK...\n");
    bp_endpoint_unregister(endpoint);
    bp_endpoint_destroy(endpoint);
    bp_shutdown();

    return 0;
} 