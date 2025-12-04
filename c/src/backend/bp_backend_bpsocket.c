/* bp_backend_bpsocket.c - Linux AF_BP Socket Backend */
#include "bp_backend.h"

#ifdef __linux__
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define AF_BP 28

typedef enum { BP_SCHEME_IPN = 1, BP_SCHEME_DTN = 2 } bp_scheme_t;

struct sockaddr_bp {
    sa_family_t bp_family;
    bp_scheme_t bp_scheme;
    union { struct { uint32_t node_id; uint32_t service_id; } ipn; } bp_addr;
};

#define MSG_ACK_REQUESTED       0x00000001
#define MSG_BP_BULK_PRIORITY    0x00000100
#define MSG_BP_STD_PRIORITY     0x00000200
#define MSG_BP_EXPEDITED_PRIORITY 0x00000400

static int g_bpsock_fd = -1;
static uint32_t g_local_node = 0;
static uint32_t g_local_service = 0;

static int parse_ipn_eid(const char *eid, uint32_t *node, uint32_t *service) {
    if (!eid || !node || !service) return -1;
    if (sscanf(eid, "ipn:%u.%u", node, service) == 2) return 0;
    return -1;
}

static int bpsocket_init(const char *config) {
    (void)config;
    g_bpsock_fd = socket(AF_BP, SOCK_DGRAM, 0);
    if (g_bpsock_fd < 0) { perror("[BP-Socket] socket failed"); return BP_ERROR_PROTOCOL; }
    return BP_SUCCESS;
}

static int bpsocket_shutdown(void) {
    if (g_bpsock_fd >= 0) { close(g_bpsock_fd); g_bpsock_fd = -1; }
    return BP_SUCCESS;
}

static int bpsocket_send(const char *source_eid, const char *dest_eid, const void *payload, size_t payload_len,
                         bp_priority_t priority, bp_custody_t custody, uint32_t ttl, const char *report_to_eid) {
    (void)custody; (void)ttl; (void)report_to_eid;
    if (g_bpsock_fd < 0) return BP_ERROR_NOT_INITIALIZED;

    uint32_t src_node, src_service, dst_node, dst_service;
    if (parse_ipn_eid(source_eid, &src_node, &src_service) < 0) return BP_ERROR_INVALID_ARGS;
    if (parse_ipn_eid(dest_eid, &dst_node, &dst_service) < 0) return BP_ERROR_INVALID_ARGS;

    if (src_node != g_local_node || src_service != g_local_service) {
        struct sockaddr_bp src_addr = {0};
        src_addr.bp_family = AF_BP;
        src_addr.bp_scheme = BP_SCHEME_IPN;
        src_addr.bp_addr.ipn.node_id = src_node;
        src_addr.bp_addr.ipn.service_id = src_service;
        if (bind(g_bpsock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
            perror("[BP-Socket] bind failed");
            return BP_ERROR_PROTOCOL;
        }
        g_local_node = src_node; g_local_service = src_service;
    }

    struct sockaddr_bp dest_addr = {0};
    dest_addr.bp_family = AF_BP;
    dest_addr.bp_scheme = BP_SCHEME_IPN;
    dest_addr.bp_addr.ipn.node_id = dst_node;
    dest_addr.bp_addr.ipn.service_id = dst_service;

    int flags = 0;
    if (priority == BP_PRIORITY_EXPEDITED) flags |= MSG_BP_EXPEDITED_PRIORITY;
    else if (priority == BP_PRIORITY_BULK) flags |= MSG_BP_BULK_PRIORITY;
    else flags |= MSG_BP_STD_PRIORITY;

    ssize_t sent = sendto(g_bpsock_fd, payload, payload_len, flags,
                          (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (sent < 0) { perror("[BP-Socket] sendto failed"); return BP_ERROR_PROTOCOL; }
    return BP_SUCCESS;
}

static int bpsocket_receive(const char *local_eid, bp_bundle_t **bundle, int timeout_ms) {
    if (g_bpsock_fd < 0 || !bundle) return BP_ERROR_NOT_INITIALIZED;

    uint32_t node, service;
    if (parse_ipn_eid(local_eid, &node, &service) < 0) return BP_ERROR_INVALID_ARGS;

    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(g_bpsock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buffer[65536];
    struct sockaddr_bp src_addr = {0};
    struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_name = &src_addr, .msg_namelen = sizeof(src_addr) };

    ssize_t n = recvmsg(g_bpsock_fd, &msg, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return BP_ERROR_TIMEOUT;
        return BP_ERROR_PROTOCOL;
    }

    bp_bundle_t *b = calloc(1, sizeof(bp_bundle_t));
    b->payload = malloc(n);
    memcpy(b->payload, buffer, n);
    b->payload_len = n;

    char src_eid[64];
    snprintf(src_eid, sizeof(src_eid), "ipn:%u.%u", src_addr.bp_addr.ipn.node_id, src_addr.bp_addr.ipn.service_id);
    b->source_eid = strdup(src_eid);

    *bundle = b;
    return BP_SUCCESS;
}

static int bpsocket_bundle_free(bp_bundle_t *bundle) {
    if (!bundle) return BP_ERROR_INVALID_ARGS;
    free(bundle->eid); free(bundle->source_eid); free(bundle->dest_eid);
    free(bundle->report_to_eid); free(bundle->payload); free(bundle);
    return BP_SUCCESS;
}

bp_backend_t g_bpsocket_backend = {
    .name = "bpsocket",
    .init = bpsocket_init,
    .shutdown = bpsocket_shutdown,
    .send = bpsocket_send,
    .receive = bpsocket_receive,
    .bundle_free = bpsocket_bundle_free,
};

#else
bp_backend_t g_bpsocket_backend = { .name = "bpsocket" };
#endif
