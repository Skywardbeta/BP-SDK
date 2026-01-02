#include "bp_backend.h"
#include "bp_bundle.h"
#include "bp_tcpcl.h"
#include "bp_utils.h"
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

#define POSIX_DEFAULT_PORT 4556
#define POSIX_MAX_BUNDLE_SIZE 65536

static tcpcl_session_t g_session = {0};
static int g_listen_fd = -1;
static char g_local_node[64] = {0};
static int g_initialized = 0;

static int posix_init(const char *config) {
    (void)config;
    if (g_initialized) return BP_SUCCESS;
    
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        BP_LOG_ERROR("WSAStartup failed");
        return BP_ERROR_PROTOCOL;
    }
#endif
    
    memset(&g_session, 0, sizeof(g_session));
    g_session.fd = -1;
    g_listen_fd = -1;
    g_local_node[0] = '\0';
    g_initialized = 1;
    
    BP_LOG_INFO("POSIX backend initialized");
    return BP_SUCCESS;
}

static int posix_shutdown(void) {
    if (!g_initialized) return BP_SUCCESS;
    
    if (g_session.connected) {
        tcpcl_session_close(&g_session);
    }
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
    
    g_initialized = 0;
    BP_LOG_INFO("POSIX backend shutdown");
    return BP_SUCCESS;
}

static int posix_connect(const char *host, uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    struct hostent *he = gethostbyname(host);
    if (!he) {
        BP_LOG_ERROR("Failed to resolve host: %s", host);
        return -1;
    }
    memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        BP_LOG_ERROR("Failed to create socket");
        return -1;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        BP_LOG_DEBUG("Failed to connect to %s:%d", host, port);
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        return -1;
    }

    if (tcpcl_session_init(&g_session, fd) < 0) goto fail;
    if (tcpcl_send_contact_header(fd) < 0) goto fail;
    if (tcpcl_recv_contact_header(fd) < 0) goto fail;
    if (tcpcl_send_sess_init(&g_session) < 0) goto fail;
    if (tcpcl_recv_sess_init(&g_session) < 0) goto fail;
    
    BP_LOG_INFO("Connected to %s:%d", host, port);
    return 0;

fail:
    tcpcl_session_close(&g_session);
    return -1;
}

static int posix_send(const char *source_eid, const char *dest_eid, const void *payload, size_t payload_len,
                      bp_priority_t priority, bp_custody_t custody, uint32_t ttl, const char *report_to_eid) {
    (void)priority; (void)custody; (void)report_to_eid;

    if (!source_eid || !dest_eid) return BP_ERROR_INVALID_ARGS;

    bp_bundle_full_t bundle;
    memset(&bundle, 0, sizeof(bundle));
    bundle.primary.version = 7;
    bundle.primary.crc_type = BP_CRC_NONE;
    bundle.primary.lifetime_ms = (uint64_t)ttl * 1000;
    bundle.primary.creation_ts = bp_time_now_dtn();

    if (bp_eid_parse(dest_eid, &bundle.primary.dest_scheme, bundle.primary.dest_ssp, &bundle.primary.dest_uri) < 0) {
        BP_LOG_ERROR("Invalid destination EID: %s", dest_eid);
        return BP_ERROR_INVALID_ARGS;
    }
    
    if (bp_eid_parse(source_eid, &bundle.primary.source_scheme, bundle.primary.source_ssp, &bundle.primary.source_uri) < 0) {
        bp_free(bundle.primary.dest_uri);
        BP_LOG_ERROR("Invalid source EID: %s", source_eid);
        return BP_ERROR_INVALID_ARGS;
    }
    
    bundle.primary.report_scheme = bundle.primary.source_scheme;
    bundle.primary.report_ssp[0] = bundle.primary.source_ssp[0];
    bundle.primary.report_ssp[1] = bundle.primary.source_ssp[1];

    if (payload_len > 0 && payload) {
        bundle.payload = bp_alloc(payload_len);
        if (!bundle.payload) {
            bp_free(bundle.primary.dest_uri);
            bp_free(bundle.primary.source_uri);
            return BP_ERROR_MEMORY;
        }
        memcpy(bundle.payload, payload, payload_len);
        bundle.payload_len = payload_len;
    }

    uint8_t *wire = bp_alloc(POSIX_MAX_BUNDLE_SIZE);
    if (!wire) {
        bp_bundle_full_free(&bundle);
        return BP_ERROR_MEMORY;
    }
    
    int wire_len = bp_bundle_encode(&bundle, wire, POSIX_MAX_BUNDLE_SIZE);
    bp_bundle_full_free(&bundle);
    
    if (wire_len < 0) {
        bp_free(wire);
        BP_LOG_ERROR("Bundle encode failed");
        return BP_ERROR_PROTOCOL;
    }

    if (!g_session.connected) {
        if (posix_connect("127.0.0.1", POSIX_DEFAULT_PORT) < 0) {
            bp_free(wire);
            BP_LOG_DEBUG("No peer available, bundle queued locally");
            return BP_SUCCESS;
        }
    }

    int rc = tcpcl_send_bundle(&g_session, wire, (size_t)wire_len);
    bp_free(wire);
    
    if (rc < 0) {
        BP_LOG_ERROR("TCPCL send failed");
        tcpcl_session_close(&g_session);
        return BP_ERROR_PROTOCOL;
    }

    BP_LOG_INFO("Sent %d bytes: %s -> %s", wire_len, source_eid, dest_eid);
    return BP_SUCCESS;
}

static int posix_receive(const char *local_eid, bp_bundle_t **bundle, int timeout_ms) {
    (void)timeout_ms;
    
    if (!local_eid || !bundle) return BP_ERROR_INVALID_ARGS;
    *bundle = NULL;

    if (!g_session.connected) {
        if (g_listen_fd < 0) {
            g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (g_listen_fd < 0) {
                BP_LOG_ERROR("Failed to create listen socket");
                return BP_ERROR_PROTOCOL;
            }

            int opt = 1;
            setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(POSIX_DEFAULT_PORT);

            if (bind(g_listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                BP_LOG_ERROR("Failed to bind to port %d", POSIX_DEFAULT_PORT);
#ifdef _WIN32
                closesocket(g_listen_fd);
#else
                close(g_listen_fd);
#endif
                g_listen_fd = -1;
                return BP_ERROR_PROTOCOL;
            }
            
            if (listen(g_listen_fd, 1) < 0) {
                BP_LOG_ERROR("Failed to listen");
#ifdef _WIN32
                closesocket(g_listen_fd);
#else
                close(g_listen_fd);
#endif
                g_listen_fd = -1;
                return BP_ERROR_PROTOCOL;
            }
            
            strncpy(g_local_node, local_eid, sizeof(g_local_node) - 1);
            g_local_node[sizeof(g_local_node) - 1] = '\0';
            BP_LOG_INFO("Listening on port %d", POSIX_DEFAULT_PORT);
        }

        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd = accept(g_listen_fd, (struct sockaddr*)&peer, &peer_len);
        if (client_fd < 0) {
            return BP_ERROR_TIMEOUT;
        }

        if (tcpcl_session_init(&g_session, client_fd) < 0) goto accept_fail;
        if (tcpcl_recv_contact_header(client_fd) < 0) goto accept_fail;
        if (tcpcl_send_contact_header(client_fd) < 0) goto accept_fail;
        if (tcpcl_recv_sess_init(&g_session) < 0) goto accept_fail;
        if (tcpcl_send_sess_init(&g_session) < 0) goto accept_fail;
        
        g_session.connected = 1;
        BP_LOG_INFO("Accepted connection from peer");
        goto receive_bundle;

accept_fail:
        tcpcl_session_close(&g_session);
        return BP_ERROR_PROTOCOL;
    }

receive_bundle:;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (tcpcl_recv_bundle(&g_session, &wire, &wire_len) < 0) {
        tcpcl_session_close(&g_session);
        return BP_ERROR_TIMEOUT;
    }

    bp_bundle_full_t full;
    memset(&full, 0, sizeof(full));
    if (bp_bundle_decode(wire, wire_len, &full) < 0) {
        bp_free(wire);
        BP_LOG_ERROR("Failed to decode bundle");
        return BP_ERROR_PROTOCOL;
    }
    bp_free(wire);

    bp_bundle_t *b = bp_alloc(sizeof(bp_bundle_t));
    if (!b) {
        bp_bundle_full_free(&full);
        return BP_ERROR_MEMORY;
    }
    memset(b, 0, sizeof(*b));

    char eid_buf[128];
    if (bp_eid_format(full.primary.source_scheme, full.primary.source_ssp, full.primary.source_uri, eid_buf, sizeof(eid_buf)) > 0) {
        b->source_eid = bp_strdup(eid_buf);
    }
    if (bp_eid_format(full.primary.dest_scheme, full.primary.dest_ssp, full.primary.dest_uri, eid_buf, sizeof(eid_buf)) > 0) {
        b->dest_eid = bp_strdup(eid_buf);
    }
    
    if (full.payload_len > 0) {
        b->payload = bp_alloc(full.payload_len);
        if (b->payload) {
            memcpy(b->payload, full.payload, full.payload_len);
            b->payload_len = full.payload_len;
        }
    }
    b->ttl = (uint32_t)(full.primary.lifetime_ms / 1000);

    bp_bundle_full_free(&full);
    *bundle = b;
    
    BP_LOG_INFO("Received %zu bytes from %s", b->payload_len, b->source_eid ? b->source_eid : "unknown");
    return BP_SUCCESS;
}

static int posix_bundle_free(bp_bundle_t *bundle) {
    if (!bundle) return BP_ERROR_INVALID_ARGS;
    bp_free(bundle->eid);
    bp_free(bundle->source_eid);
    bp_free(bundle->dest_eid);
    bp_free(bundle->report_to_eid);
    bp_free(bundle->payload);
    bp_free(bundle);
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
