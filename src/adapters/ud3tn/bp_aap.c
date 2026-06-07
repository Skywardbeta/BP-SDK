#include "bp_aap.h"
#include "bp_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int socklen_t;
#define BP_CLOSESOCK(fd) closesocket(fd)
#define BP_INVALID_SOCK  INVALID_SOCKET
typedef SOCKET bp_socket_t;
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#define BP_CLOSESOCK(fd) close(fd)
#define BP_INVALID_SOCK  (-1)
typedef int bp_socket_t;
#endif

#define BP_AAP_VERSION 0x1

static int type_has_eid(bp_aap_type_t t) {
    return t == BP_AAP_REGISTER || t == BP_AAP_SENDBUNDLE ||
           t == BP_AAP_RECVBUNDLE || t == BP_AAP_SENDBIBE ||
           t == BP_AAP_RECVBIBE || t == BP_AAP_WELCOME;
}

static int type_has_payload(bp_aap_type_t t) {
    return t == BP_AAP_SENDBUNDLE || t == BP_AAP_RECVBUNDLE ||
           t == BP_AAP_SENDBIBE || t == BP_AAP_RECVBIBE;
}

static int type_has_bundle_id(bp_aap_type_t t) {
    return t == BP_AAP_SENDCONFIRM || t == BP_AAP_CANCELBUNDLE;
}

static int type_is_known(bp_aap_type_t t) {
    return t <= BP_AAP_RECVBIBE;
}

static void put_u64(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t get_u64(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

static int add_ovf(size_t *acc, size_t add) {
    if (*acc > SIZE_MAX - add) return 1;
    *acc += add;
    return 0;
}

size_t bp_aap_serialized_size(const bp_aap_msg_t *msg) {
    if (!msg || !type_is_known(msg->type)) return 0;
    size_t n = 1;
    if (type_has_eid(msg->type) &&
        (add_ovf(&n, 2) || add_ovf(&n, msg->eid_len))) return 0;
    if (type_has_payload(msg->type) &&
        (add_ovf(&n, 8) || add_ovf(&n, msg->payload_len))) return 0;
    if (type_has_bundle_id(msg->type) && add_ovf(&n, 8)) return 0;
    return n;
}

int bp_aap_serialize(const bp_aap_msg_t *msg, uint8_t *out, size_t out_size,
                     size_t *written) {
    if (!msg || !out) return BP_AAP_ERR;
    if (!type_is_known(msg->type)) return BP_AAP_ERR;
    if (type_has_eid(msg->type) && msg->eid_len > 0xFFFF) return BP_AAP_ERR;

    size_t need = bp_aap_serialized_size(msg);
    if (need == 0 || need > out_size) return BP_AAP_ERR;

    size_t off = 0;
    out[off++] = (uint8_t)((BP_AAP_VERSION << 4) | (msg->type & 0xF));

    if (type_has_eid(msg->type)) {
        out[off++] = (uint8_t)(msg->eid_len >> 8);
        out[off++] = (uint8_t)(msg->eid_len);
        if (msg->eid_len) {
            if (!msg->eid) return BP_AAP_ERR;
            memcpy(out + off, msg->eid, msg->eid_len);
            off += msg->eid_len;
        }
    }
    if (type_has_payload(msg->type)) {
        put_u64(out + off, msg->payload_len);
        off += 8;
        if (msg->payload_len) {
            if (!msg->payload) return BP_AAP_ERR;
            memcpy(out + off, msg->payload, msg->payload_len);
            off += msg->payload_len;
        }
    }
    if (type_has_bundle_id(msg->type)) {
        put_u64(out + off, msg->bundle_id);
        off += 8;
    }

    if (written) *written = off;
    return BP_AAP_OK;
}

int bp_aap_parse(const uint8_t *in, size_t len, bp_aap_msg_t *out,
                 size_t *consumed) {
    if (!in || !out) return BP_AAP_ERR;
    if (len < 1) return BP_AAP_NEED_MORE;

    if ((in[0] >> 4) != BP_AAP_VERSION) return BP_AAP_ERR;
    bp_aap_type_t type = (bp_aap_type_t)(in[0] & 0xF);
    if (!type_is_known(type)) return BP_AAP_ERR;

    size_t off = 1;
    size_t eid_len = 0, payload_len = 0;

    if (type_has_eid(type)) {
        if (len - off < 2) return BP_AAP_NEED_MORE;
        eid_len = ((size_t)in[off] << 8) | in[off + 1];
        off += 2;
        if (eid_len > len - off) return BP_AAP_NEED_MORE;
    }
    size_t eid_start = off;
    off += eid_len;

    size_t payload_start = 0;
    if (type_has_payload(type)) {
        if (len - off < 8) return BP_AAP_NEED_MORE;
        uint64_t raw = get_u64(in + off);
        off += 8;
        if (raw > (uint64_t)(len - off)) return BP_AAP_NEED_MORE;
        payload_len = (size_t)raw;
        payload_start = off;
        off += payload_len;
    }

    uint64_t bundle_id = 0;
    if (type_has_bundle_id(type)) {
        if (len - off < 8) return BP_AAP_NEED_MORE;
        bundle_id = get_u64(in + off);
        off += 8;
    }

    bp_aap_msg_t m = {0};
    m.type = type;
    m.bundle_id = bundle_id;
    if (eid_len) {
        m.eid = bp_alloc(eid_len + 1);
        if (!m.eid) return BP_AAP_ERR;
        memcpy(m.eid, in + eid_start, eid_len);
        m.eid[eid_len] = '\0';
        m.eid_len = eid_len;
    }
    if (payload_len) {
        m.payload = bp_alloc(payload_len);
        if (!m.payload) { bp_free(m.eid); return BP_AAP_ERR; }
        memcpy(m.payload, in + payload_start, payload_len);
        m.payload_len = payload_len;
    }

    *out = m;
    if (consumed) *consumed = off;
    return BP_AAP_OK;
}

void bp_aap_msg_free(bp_aap_msg_t *msg) {
    if (!msg) return;
    bp_free(msg->eid);
    bp_free(msg->payload);
    msg->eid = NULL;
    msg->payload = NULL;
    msg->eid_len = 0;
    msg->payload_len = 0;
}

struct bp_aap_client {
    bp_socket_t fd;
    char       *node_eid;
    uint8_t    *rx;
    size_t      rx_len;
    size_t      rx_cap;
};

static int sock_send_all(bp_socket_t fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = (int)send(fd, (const char *)buf + sent,
                          (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int send_msg(bp_aap_client_t *c, const bp_aap_msg_t *msg) {
    size_t need = bp_aap_serialized_size(msg);
    if (need == 0) return BP_AAP_ERR;
    uint8_t stack_buf[512];
    uint8_t *buf = stack_buf;
    if (need > sizeof(stack_buf)) {
        buf = bp_alloc(need);
        if (!buf) return BP_AAP_ERR;
    }
    size_t written = 0;
    int rc = bp_aap_serialize(msg, buf, need, &written);
    if (rc == BP_AAP_OK)
        rc = sock_send_all(c->fd, buf, written) == 0 ? BP_AAP_OK : BP_AAP_ERR;
    if (buf != stack_buf) bp_free(buf);
    return rc;
}

static int wait_readable(bp_socket_t fd, int timeout_ms) {
    if (timeout_ms < 0) return 1;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select((int)fd + 1, &rfds, NULL, NULL, &tv);
    return r > 0 ? 1 : 0;
}

static int recv_msg(bp_aap_client_t *c, bp_aap_msg_t *out, int timeout_ms) {
    for (;;) {
        if (c->rx_len > 0) {
            size_t consumed = 0;
            int rc = bp_aap_parse(c->rx, c->rx_len, out, &consumed);
            if (rc == BP_AAP_OK) {
                memmove(c->rx, c->rx + consumed, c->rx_len - consumed);
                c->rx_len -= consumed;
                return BP_AAP_OK;
            }
            if (rc == BP_AAP_ERR) return BP_AAP_ERR;
        }

        if (!wait_readable(c->fd, timeout_ms)) return BP_AAP_ERR;

        if (c->rx_len + 4096 > c->rx_cap) {
            size_t ncap = c->rx_cap ? c->rx_cap * 2 : 8192;
            while (ncap < c->rx_len + 4096) ncap *= 2;
            uint8_t *nb = bp_realloc(c->rx, ncap);
            if (!nb) return BP_AAP_ERR;
            c->rx = nb;
            c->rx_cap = ncap;
        }
        int n = (int)recv(c->fd, (char *)c->rx + c->rx_len, 4096, 0);
        if (n <= 0) return BP_AAP_ERR;
        c->rx_len += (size_t)n;
    }
}

bp_aap_client_t *bp_aap_connect(const char *host, uint16_t port) {
    if (!host) return NULL;
#ifdef _WIN32
    WSADATA wsa;
    static int wsa_started = 0;
    if (!wsa_started) { WSAStartup(MAKEWORD(2, 2), &wsa); wsa_started = 1; }
#endif

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return NULL;

    bp_socket_t fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == BP_INVALID_SOCK) { freeaddrinfo(res); return NULL; }
    if (connect(fd, res->ai_addr, (socklen_t)res->ai_addrlen) != 0) {
        BP_CLOSESOCK(fd);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);

    bp_aap_client_t *c = bp_alloc(sizeof(*c));
    if (!c) { BP_CLOSESOCK(fd); return NULL; }
    memset(c, 0, sizeof(*c));
    c->fd = fd;

    bp_aap_msg_t welcome = {0};
    if (recv_msg(c, &welcome, 5000) != BP_AAP_OK ||
        welcome.type != BP_AAP_WELCOME) {
        bp_aap_msg_free(&welcome);
        bp_aap_disconnect(c);
        return NULL;
    }
    if (welcome.eid) c->node_eid = bp_strdup(welcome.eid);
    bp_aap_msg_free(&welcome);
    return c;
}

const char *bp_aap_node_eid(const bp_aap_client_t *c) {
    return c ? c->node_eid : NULL;
}

static int expect_ack(bp_aap_client_t *c) {
    bp_aap_msg_t reply = {0};
    int rc = recv_msg(c, &reply, 5000);
    if (rc != BP_AAP_OK) return BP_AAP_ERR;
    int ok = (reply.type == BP_AAP_ACK);
    bp_aap_msg_free(&reply);
    return ok ? BP_AAP_OK : BP_AAP_ERR;
}

int bp_aap_register(bp_aap_client_t *c, const char *agent_id) {
    if (!c || !agent_id) return BP_AAP_ERR;
    bp_aap_msg_t m = {0};
    m.type = BP_AAP_REGISTER;
    m.eid = (char *)agent_id;
    m.eid_len = strlen(agent_id);
    if (send_msg(c, &m) != BP_AAP_OK) return BP_AAP_ERR;
    return expect_ack(c);
}

int bp_aap_send_bundle(bp_aap_client_t *c, const char *dest_eid,
                       const uint8_t *payload, size_t payload_len) {
    if (!c || !dest_eid || (!payload && payload_len)) return BP_AAP_ERR;
    bp_aap_msg_t m = {0};
    m.type = BP_AAP_SENDBUNDLE;
    m.eid = (char *)dest_eid;
    m.eid_len = strlen(dest_eid);
    m.payload = (uint8_t *)payload;
    m.payload_len = payload_len;
    if (send_msg(c, &m) != BP_AAP_OK) return BP_AAP_ERR;

    bp_aap_msg_t reply = {0};
    int rc = recv_msg(c, &reply, 5000);
    if (rc != BP_AAP_OK) return BP_AAP_ERR;
    int ok = (reply.type == BP_AAP_SENDCONFIRM);
    bp_aap_msg_free(&reply);
    return ok ? BP_AAP_OK : BP_AAP_ERR;
}

int bp_aap_recv(bp_aap_client_t *c, bp_aap_msg_t *out, int timeout_ms) {
    if (!c || !out) return BP_AAP_ERR;
    return recv_msg(c, out, timeout_ms);
}

void bp_aap_disconnect(bp_aap_client_t *c) {
    if (!c) return;
    if (c->fd != BP_INVALID_SOCK) BP_CLOSESOCK(c->fd);
    bp_free(c->node_eid);
    bp_free(c->rx);
    bp_free(c);
}
