/* bp_backend_posix.c - POSIX Socket Backend */
#include "bp_backend.h"
#include "bp_bundle.h"
#include "bp_tcpcl.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

static tcpcl_session_t g_session = {0};
static int g_listen_fd = -1;
static char g_local_node[64] = {0};

static int posix_init(const char *config) {
    (void)config;
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    return BP_SUCCESS;
}

static int posix_shutdown(void) {
    if (g_session.connected) tcpcl_session_close(&g_session);
    if (g_listen_fd >= 0) {
#ifdef _WIN32
        closesocket(g_listen_fd);
#else
        close(g_listen_fd);
#endif
        g_listen_fd = -1;
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return BP_SUCCESS;
}

static int posix_connect(const char *host, uint16_t port) {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    struct hostent *he = gethostbyname(host);
    if (!he) return -1;
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        return -1;
    }

    tcpcl_session_init(&g_session, fd);
    if (tcpcl_send_contact_header(fd) < 0) return -1;
    if (tcpcl_recv_contact_header(fd) < 0) return -1;
    if (tcpcl_send_sess_init(&g_session) < 0) return -1;
    if (tcpcl_recv_sess_init(&g_session) < 0) return -1;
    return 0;
}

static int posix_send(const char *source_eid, const char *dest_eid, const void *payload, size_t payload_len,
                      bp_priority_t priority, bp_custody_t custody, uint32_t ttl, const char *report_to_eid) {
    (void)priority; (void)custody; (void)report_to_eid;

    bp_bundle_full_t bundle = {0};
    bundle.primary.version = 7;
    bundle.primary.crc_type = BP_CRC_NONE;
    bundle.primary.lifetime_ms = ttl * 1000;

    bp_eid_parse(dest_eid, &bundle.primary.dest_scheme, bundle.primary.dest_ssp, &bundle.primary.dest_uri);
    bp_eid_parse(source_eid, &bundle.primary.source_scheme, bundle.primary.source_ssp, &bundle.primary.source_uri);
    bundle.primary.report_scheme = bundle.primary.source_scheme;
    bundle.primary.report_ssp[0] = bundle.primary.source_ssp[0];
    bundle.primary.report_ssp[1] = bundle.primary.source_ssp[1];

    bundle.payload = (uint8_t *)payload;
    bundle.payload_len = payload_len;

    uint8_t wire[65536];
    int wire_len = bp_bundle_encode(&bundle, wire, sizeof(wire));
    if (wire_len < 0) {
        printf("[POSIX] Bundle encode failed\n");
        return BP_ERROR_PROTOCOL;
    }

    if (!g_session.connected && posix_connect("127.0.0.1", 4556) < 0) {
        printf("[POSIX] send %zu bytes (no peer): %s -> %s\n", payload_len, source_eid, dest_eid);
        return BP_SUCCESS;
    }

    if (tcpcl_send_bundle(&g_session, wire, wire_len) < 0) {
        printf("[POSIX] TCPCL send failed\n");
        return BP_ERROR_PROTOCOL;
    }

    printf("[POSIX] sent %d bytes: %s -> %s\n", wire_len, source_eid, dest_eid);
    return BP_SUCCESS;
}

static int posix_receive(const char *local_eid, bp_bundle_t **bundle, int timeout_ms) {
    (void)timeout_ms;

    if (!g_session.connected) {
        if (g_listen_fd < 0) {
            g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (g_listen_fd < 0) return BP_ERROR_PROTOCOL;

            int opt = 1;
            setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(4556);

            if (bind(g_listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return BP_ERROR_PROTOCOL;
            listen(g_listen_fd, 1);
            strncpy(g_local_node, local_eid, sizeof(g_local_node) - 1);
        }

        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd = accept(g_listen_fd, (struct sockaddr*)&peer, &peer_len);
        if (client_fd < 0) return BP_ERROR_TIMEOUT;

        tcpcl_session_init(&g_session, client_fd);
        tcpcl_recv_contact_header(client_fd);
        tcpcl_send_contact_header(client_fd);
        tcpcl_recv_sess_init(&g_session);
        tcpcl_send_sess_init(&g_session);
        g_session.connected = 1;
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (tcpcl_recv_bundle(&g_session, &wire, &wire_len) < 0) return BP_ERROR_TIMEOUT;

    bp_bundle_full_t full = {0};
    if (bp_bundle_decode(wire, wire_len, &full) < 0) { free(wire); return BP_ERROR_PROTOCOL; }
    free(wire);

    bp_bundle_t *b = calloc(1, sizeof(bp_bundle_t));
    char eid_buf[128];
    bp_eid_format(full.primary.source_scheme, full.primary.source_ssp, full.primary.source_uri, eid_buf, sizeof(eid_buf));
    b->source_eid = strdup(eid_buf);
    bp_eid_format(full.primary.dest_scheme, full.primary.dest_ssp, full.primary.dest_uri, eid_buf, sizeof(eid_buf));
    b->dest_eid = strdup(eid_buf);
    b->payload = malloc(full.payload_len);
    memcpy(b->payload, full.payload, full.payload_len);
    b->payload_len = full.payload_len;
    b->ttl = full.primary.lifetime_ms / 1000;

    bp_bundle_full_free(&full);
    *bundle = b;
    printf("[POSIX] received %zu bytes from %s\n", b->payload_len, b->source_eid);
    return BP_SUCCESS;
}

static int posix_bundle_free(bp_bundle_t *bundle) {
    if (!bundle) return BP_ERROR_INVALID_ARGS;
    free(bundle->eid); free(bundle->source_eid); free(bundle->dest_eid);
    free(bundle->report_to_eid); free(bundle->payload); free(bundle);
    return BP_SUCCESS;
}

bp_backend_t g_posix_backend = {
    .name = "posix",
    .init = posix_init,
    .shutdown = posix_shutdown,
    .send = posix_send,
    .receive = posix_receive,
    .bundle_free = posix_bundle_free,
};
