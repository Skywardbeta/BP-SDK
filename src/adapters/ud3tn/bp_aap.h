/*
 * bp_aap.h - uD3TN Application Agent Protocol (AAP v1) client.
 *
 * uD3TN has no standalone security admin tool; applications interact with
 * the node over the AAP socket. The SDK acts as an AAP client: it connects,
 * registers an endpoint, and hands application data to uD3TN's BPA, which
 * applies BPSec and forwards the bundle. The SDK never builds security
 * blocks itself on this path.
 *
 * The wire codec (bp_aap_serialize / bp_aap_parse) is pure and depends only
 * on the buffer arguments, so it is unit testable without a live node. The
 * client handle wraps a TCP socket to the AAP listener.
 */
#ifndef BP_AAP_H
#define BP_AAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BP_AAP_ACK         = 0x0,
    BP_AAP_NACK        = 0x1,
    BP_AAP_REGISTER    = 0x2,
    BP_AAP_SENDBUNDLE  = 0x3,
    BP_AAP_RECVBUNDLE  = 0x4,
    BP_AAP_SENDCONFIRM = 0x5,
    BP_AAP_CANCELBUNDLE= 0x6,
    BP_AAP_WELCOME     = 0x7,
    BP_AAP_PING        = 0x8,
    BP_AAP_SENDBIBE    = 0x9,
    BP_AAP_RECVBIBE    = 0xA,
    BP_AAP_INVALID     = 0xFF
} bp_aap_type_t;

typedef enum {
    BP_AAP_OK        = 0,
    BP_AAP_ERR       = -1,
    BP_AAP_NEED_MORE = -2
} bp_aap_status_t;

typedef struct {
    bp_aap_type_t type;
    char         *eid;          /* owned */
    size_t        eid_len;
    uint8_t      *payload;      /* owned */
    size_t        payload_len;
    uint64_t      bundle_id;
} bp_aap_msg_t;

size_t bp_aap_serialized_size(const bp_aap_msg_t *msg);

int bp_aap_serialize(const bp_aap_msg_t *msg, uint8_t *out, size_t out_size,
                     size_t *written);

/* Returns BP_AAP_NEED_MORE on a partial frame; caller frees *out. */
int bp_aap_parse(const uint8_t *in, size_t len, bp_aap_msg_t *out,
                 size_t *consumed);

void bp_aap_msg_free(bp_aap_msg_t *msg);

typedef struct bp_aap_client bp_aap_client_t;

bp_aap_client_t *bp_aap_connect(const char *host, uint16_t port);
int bp_aap_register(bp_aap_client_t *c, const char *agent_id);
int bp_aap_send_bundle(bp_aap_client_t *c, const char *dest_eid,
                       const uint8_t *payload, size_t payload_len);
int bp_aap_recv(bp_aap_client_t *c, bp_aap_msg_t *out, int timeout_ms);
const char *bp_aap_node_eid(const bp_aap_client_t *c);
void bp_aap_disconnect(bp_aap_client_t *c);

#ifdef __cplusplus
}
#endif

#endif
