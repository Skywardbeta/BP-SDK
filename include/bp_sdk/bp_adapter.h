/*
 * bp_adapter.h - Adapter Contract and the bp_secure_link developer facade.
 *
 * The Adapter Contract is the lowest abstraction in BP-SDK. Every adapter
 * sits above a host Bundle Protocol Agent (BPA) and never performs crypto or
 * pushes bundles to a convergence layer itself: it lowers the declared,
 * stack-independent security policy onto the host's native BPSec
 * configuration path and then hands application data to that BPA, which owns
 * BIB/BCB construction and forwarding.
 *
 *   - ION adapter   : lowers policy to bpsecadmin rules (see bp_ion_policy.h).
 *   - uD3TN adapter : registers an endpoint and ships data over AAP
 *                     (see bp_aap.h); per-flow security is enforced by the
 *                     node's own BPSec configuration.
 *
 * bp_secure_link is the single developer-facing surface: pick a stack by
 * name, declare intent + key references once, and the same application code
 * drives either stack's native BPSec engine.
 */
#ifndef BP_ADAPTER_H
#define BP_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "bp_session.h"
#include "bp_security_intent.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Unused function-pointer slots may be NULL (treated as unsupported op). */
typedef struct {
    const char *name;

    int  (*open)(const char *config, void **state);
    void (*close)(void *state);

    int  (*set_source)(void *state, const char *source_eid);

    int  (*validate_policy)(const bp_security_policy_t *policy);

    int  (*register_security)(void *state,
                              const char *source_eid, const char *dest_eid,
                              const bp_security_policy_t *policy);

    int  (*send)(void *state,
                 const char *source_eid, const char *dest_eid,
                 const uint8_t *data, size_t len,
                 const bp_delivery_opts_t *opts);

    int  (*recv)(void *state, const char *local_eid,
                 uint8_t **out, size_t *out_len, int timeout_ms);
} bp_adapter_t;

/* The contract struct must outlive the registry (use a static instance). */
int                 bp_adapter_register(const bp_adapter_t *adapter);
const bp_adapter_t *bp_adapter_find(const char *name);

int bp_secure_policy_validate(const bp_security_policy_t *policy);

typedef struct bp_secure_link bp_secure_link_t;
bp_secure_link_t *bp_secure_link_open(const char *stack, const char *config);

int  bp_secure_link_set_source(bp_secure_link_t *link, const char *source_eid);

/* Fail-fast: rejected here (before any send) if the policy cannot apply. */
int  bp_secure_link_set_security(bp_secure_link_t *link,
                                 const bp_security_policy_t *policy);

/* Intent variant: lowers to a default policy, then set_security applies it. */
int  bp_secure_link_set_security_intent(bp_secure_link_t *link,
                                        const bp_security_intent_t *intent);

int  bp_secure_link_send(bp_secure_link_t *link, const char *dest_eid,
                         const uint8_t *data, size_t len,
                         const bp_delivery_opts_t *opts);

int  bp_secure_link_recv(bp_secure_link_t *link,
                         uint8_t **out, size_t *out_len, int timeout_ms);

const char *bp_secure_link_stack(const bp_secure_link_t *link);

int  bp_secure_link_close(bp_secure_link_t *link);

#ifdef __cplusplus
}
#endif

#endif
