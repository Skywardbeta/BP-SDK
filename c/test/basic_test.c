#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "bp_sdk.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s\n", message); \
            return 0; \
        } else { \
            printf("PASS: %s\n", message); \
        } \
    } while(0)

int test_initialization() {
    printf("\n=== Testing Initialization ===\n");
    
    int result = bp_init("ipn:1.1", NULL);
    TEST_ASSERT(result == BP_SUCCESS, "BP-SDK initialization");
    
    int is_init = bp_is_initialized();
    TEST_ASSERT(is_init == 1, "BP-SDK is initialized check");
    
    result = bp_shutdown();
    TEST_ASSERT(result == BP_SUCCESS, "BP-SDK shutdown");
    
    is_init = bp_is_initialized();
    TEST_ASSERT(is_init == 0, "BP-SDK is not initialized after shutdown");
    
    return 1;
}

int test_error_handling() {
    printf("\n=== Testing Error Handling ===\n");
    
    int result = bp_send(NULL, "ipn:2.1", "test", 4, BP_PRIORITY_STANDARD, 
                         BP_CUSTODY_NONE, 3600, NULL);
    TEST_ASSERT(result == BP_ERROR_INVALID_ARGS, "Invalid args error for NULL source");
    
    result = bp_send("ipn:1.1", "ipn:2.1", "test", 4, BP_PRIORITY_STANDARD, 
                     BP_CUSTODY_NONE, 3600, NULL);
    TEST_ASSERT(result == BP_ERROR_NOT_INITIALIZED, "Not initialized error");
    
    const char *error_msg = bp_strerror(BP_ERROR_INVALID_ARGS);
    TEST_ASSERT(error_msg != NULL, "Error message retrieval");
    TEST_ASSERT(strlen(error_msg) > 0, "Error message not empty");
    
    return 1;
}

int test_endpoint_management() {
    printf("\n=== Testing Endpoint Management ===\n");
    
    int result = bp_init("ipn:1.1", NULL);
    TEST_ASSERT(result == BP_SUCCESS, "BP-SDK initialization for endpoint test");
    
    bp_endpoint_t *endpoint;
    result = bp_endpoint_create("ipn:1.1", &endpoint);
    TEST_ASSERT(result == BP_SUCCESS, "Endpoint creation");
    TEST_ASSERT(endpoint != NULL, "Endpoint not NULL");
    TEST_ASSERT(endpoint->endpoint_id != NULL, "Endpoint ID set");
    TEST_ASSERT(strcmp(endpoint->endpoint_id, "ipn:1.1") == 0, "Endpoint ID correct");
    
    result = bp_endpoint_register(endpoint);
    TEST_ASSERT(result == BP_SUCCESS, "Endpoint registration");
    
    result = bp_endpoint_unregister(endpoint);
    TEST_ASSERT(result == BP_SUCCESS, "Endpoint unregistration");
    
    result = bp_endpoint_destroy(endpoint);
    TEST_ASSERT(result == BP_SUCCESS, "Endpoint destruction");
    
    bp_shutdown();
    return 1;
}

int test_cla_management() {
    printf("\n=== Testing CLA Management ===\n");
    
    int result = bp_init("ipn:1.1", NULL);
    TEST_ASSERT(result == BP_SUCCESS, "BP-SDK initialization for CLA test");
    
    bp_cla_t *cla;
    result = bp_cla_create_udp("127.0.0.1", 4556, &cla);
    TEST_ASSERT(result == BP_SUCCESS, "UDP CLA creation");
    TEST_ASSERT(cla != NULL, "CLA not NULL");
    TEST_ASSERT(cla->protocol_name != NULL, "CLA protocol name set");
    TEST_ASSERT(strcmp(cla->protocol_name, "udp") == 0, "CLA protocol name correct");
    
    result = bp_cla_register(cla);
    TEST_ASSERT(result == BP_SUCCESS, "CLA registration");
    
    char **protocol_names;
    int count;
    result = bp_cla_list(&protocol_names, &count);
    TEST_ASSERT(result == BP_SUCCESS, "CLA list retrieval");
    TEST_ASSERT(count == 1, "CLA count correct");
    TEST_ASSERT(strcmp(protocol_names[0], "udp") == 0, "Listed CLA name correct");
    
    for (int i = 0; i < count; i++) {
        free(protocol_names[i]);
    }
    free(protocol_names);
    
    result = bp_cla_unregister("udp");
    TEST_ASSERT(result == BP_SUCCESS, "CLA unregistration");
    
    result = bp_cla_destroy(cla);
    TEST_ASSERT(result == BP_SUCCESS, "CLA destruction");
    
    bp_shutdown();
    return 1;
}

int test_routing_management() {
    printf("\n=== Testing Routing Management ===\n");
    
    int result = bp_init("ipn:1.1", NULL);
    TEST_ASSERT(result == BP_SUCCESS, "BP-SDK initialization for routing test");
    
    bp_routing_t *routing;
    result = bp_routing_create_static(&routing);
    TEST_ASSERT(result == BP_SUCCESS, "Static routing creation");
    TEST_ASSERT(routing != NULL, "Routing not NULL");
    TEST_ASSERT(routing->algorithm_name != NULL, "Routing algorithm name set");
    TEST_ASSERT(strcmp(routing->algorithm_name, "static") == 0, "Routing algorithm name correct");
    
    result = bp_routing_register(routing);
    TEST_ASSERT(result == BP_SUCCESS, "Routing registration");
    
    result = bp_routing_unregister("static");
    TEST_ASSERT(result == BP_SUCCESS, "Routing unregistration");
    
    result = bp_routing_destroy(routing);
    TEST_ASSERT(result == BP_SUCCESS, "Routing destruction");
    
    bp_shutdown();
    return 1;
}

int test_route_creation() {
    printf("\n=== Testing Route Creation ===\n");
    
    bp_route_t *route;
    int result = bp_route_create("ipn:2.1", "ipn:3.1", 100, 0.9, 
                                time(NULL) + 3600, &route);
    TEST_ASSERT(result == BP_SUCCESS, "Route creation");
    TEST_ASSERT(route != NULL, "Route not NULL");
    TEST_ASSERT(route->dest_eid != NULL, "Route destination EID set");
    TEST_ASSERT(strcmp(route->dest_eid, "ipn:2.1") == 0, "Route destination EID correct");
    TEST_ASSERT(route->next_hop != NULL, "Route next hop set");
    TEST_ASSERT(strcmp(route->next_hop, "ipn:3.1") == 0, "Route next hop correct");
    TEST_ASSERT(route->cost == 100, "Route cost correct");
    TEST_ASSERT(route->confidence == 0.9f, "Route confidence correct");
    
    result = bp_route_destroy(route);
    TEST_ASSERT(result == BP_SUCCESS, "Route destruction");
    
    return 1;
}

int test_memory_management() {
    printf("\n=== Testing Memory Management ===\n");
    
    bp_bundle_t *bundle = malloc(sizeof(bp_bundle_t));
    memset(bundle, 0, sizeof(bp_bundle_t));
    
    bundle->eid = strdup("ipn:1.1");
    bundle->source_eid = strdup("ipn:2.1");
    bundle->dest_eid = strdup("ipn:3.1");
    bundle->payload = malloc(100);
    bundle->payload_len = 100;
    
    int result = bp_bundle_free(bundle);
    TEST_ASSERT(result == BP_SUCCESS, "Bundle memory cleanup");
    
    return 1;
}

int run_all_tests() {
    printf("Running BP-SDK Test Suite\n");
    printf("========================\n");
    
    int passed = 0;
    int total = 0;
    
    total++; if (test_initialization()) passed++;
    total++; if (test_error_handling()) passed++;
    total++; if (test_endpoint_management()) passed++;
    total++; if (test_cla_management()) passed++;
    total++; if (test_routing_management()) passed++;
    total++; if (test_route_creation()) passed++;
    total++; if (test_memory_management()) passed++;
    
    printf("\n=== Test Results ===\n");
    printf("Passed: %d/%d tests\n", passed, total);
    
    if (passed == total) {
        printf("ALL TESTS PASSED!\n");
        return 0;
    } else {
        printf("SOME TESTS FAILED!\n");
        return 1;
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("BP-SDK Basic Test Suite\n");
        printf("Usage: %s [--help]\n", argv[0]);
        printf("\nThis test suite validates basic BP-SDK functionality.\n");
        printf("Note: Some tests may fail if ION-DTN is not properly configured.\n");
        return 0;
    }
    
    return run_all_tests();
} 