/*
 * bp_backend.h - Backend abstraction.
 *
 * A backend implements the bundle-level send/receive contract on top of
 * a concrete convergence layer (TCPCL, AF_BP socket, ION daemon, ...).
 * Backends are selected by name in bp_init()'s config string.
 *
 * Only the function pointers actually exercised by the SDK are listed
 * here. Earlier revisions exposed CLA / routing / storage / security
 * plugin slots that no backend implemented; those have been removed in
 * favour of the dedicated public APIs (bp_session, bp_key_provider, etc.).
 */
#ifndef BP_BACKEND_H
#define BP_BACKEND_H

#include "bp_sdk.h"
#include <stddef.h>

typedef struct {
    const char *name;

    int (*init)(const char *config);
    int (*shutdown)(void);

    int (*send)(const char *source_eid, const char *dest_eid,
                const void *payload, size_t payload_len,
                bp_priority_t priority, bp_custody_t custody,
                uint32_t ttl, const char *report_to_eid);

    int (*send_raw)(const void *wire_bundle, size_t wire_len);

    int (*receive)(const char *local_eid, bp_bundle_t **bundle,
                   int timeout_ms);

    int (*receive_raw)(const char *local_eid, uint8_t **wire,
                       size_t *wire_len, int timeout_ms);

    int (*bundle_free)(bp_bundle_t *bundle);
} bp_backend_t;

#endif
