/*
 * bp_ion_policy.h - Declarative policy lowering for ION-DTN.
 *
 * Translates a stack-independent bp_security_policy_t into the bpsecadmin
 * rule script (event set + policyrule commands) that ION's native BPSec
 * engine accepts via bpsecadmin / .bpsecrc. The SDK only emits the rule
 * text; ION owns BIB/BCB construction and the crypto.
 *
 * BP-SDK's ION lowering currently emits only key_name in sc_parms; it therefore
 * intentionally supports only ION's default contexts: BIB-HMAC-SHA2 SHA-256
 * (sc_id 1) and BCB-AES-GCM AES-256 (sc_id 2). Other variants are rejected by
 * validation rather than silently downgraded to the default. All functions are
 * pure and unit testable without a running node.
 */
#ifndef BP_ION_POLICY_H
#define BP_ION_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include "bp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 9173 / IANA security context identifiers used by ION. */
#define BP_ION_SCID_BIB_HMAC_SHA2 1
#define BP_ION_SCID_BCB_AES_GCM   2

/* BPv7 payload block type (RFC 9171 sec. 4.3.3). */
#define BP_ION_BLOCK_TYPE_PAYLOAD 1

int bp_ion_policy_validate(const bp_security_policy_t *policy);

/* Lowers to a NUL-terminated bpsecadmin script (BIB=rule_id_base, BCB=+1).
 * Returns script length, or a negative bpsec_error_t. */
int bp_ion_policy_lower(const bp_security_policy_t *policy,
                        const char *source_eid, const char *dest_eid,
                        const char *eventset_name, uint16_t rule_id_base,
                        char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif
