/*
 * bp_tcpcl.c - TCPCLv4 (RFC 9174)
 * Includes socket timeouts and stricter frame validation.
 */
#include "bp_tcpcl.h"
#include "bp_utils.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#endif

static const uint8_t TCPCL_MAGIC[4] = {'d', 't', 'n', '!'};
#define TCPCL_VERSION 4
#define TCPCL_MAX_NODE_ID_LEN   1024
#define TCPCL_MAX_SEGMENT_SIZE  (16 * 1024 * 1024)
#define TCPCL_MAX_TRANSFER_SIZE (256 * 1024 * 1024)
#define TCPCL_DEFAULT_TIMEOUT_MS 30000

static int set_socket_timeout(int fd, int timeout_ms) {
#ifdef _WIN32
    DWORD tv = (DWORD)timeout_ms;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char*)(buf + sent), (int)(len - sent), 0);
        if (n < 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAETIMEDOUT) return -2;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -2;
#endif
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, (char*)(buf + got), (int)(len - got), 0);
        if (n < 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAETIMEDOUT) return -2;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -2;
#endif
            return -1;
        }
        if (n == 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

static int encode_uint64(uint8_t *buf, uint64_t val) {
    for (int i = 7; i >= 0; i--) buf[7 - i] = (val >> (i * 8)) & 0xFF;
    return 8;
}

static uint64_t decode_uint64(const uint8_t *buf) {
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) val = (val << 8) | buf[i];
    return val;
}

int tcpcl_send_contact_header(int fd) {
    uint8_t hdr[6];
    memcpy(hdr, TCPCL_MAGIC, 4);
    hdr[4] = TCPCL_VERSION; hdr[5] = 0;
    return write_all(fd, hdr, 6);
}

int tcpcl_recv_contact_header(int fd) {
    uint8_t hdr[6];
    if (read_all(fd, hdr, 6) < 0) return -1;
    if (memcmp(hdr, TCPCL_MAGIC, 4) != 0) return -1;
    if (hdr[4] != TCPCL_VERSION) return -1;
    return 0;
}

int tcpcl_send_sess_init(tcpcl_session_t *sess) {
    uint8_t msg[64];
    size_t pos = 0;

    msg[pos++] = TCPCL_MSG_SESS_INIT;
    msg[pos++] = (sess->keepalive_interval >> 8) & 0xFF;
    msg[pos++] = sess->keepalive_interval & 0xFF;
    pos += encode_uint64(msg + pos, sess->segment_mru);
    pos += encode_uint64(msg + pos, sess->transfer_mru);

    const char *node_id = "ipn:0.0";
    uint16_t nid_len = (uint16_t)strlen(node_id);
    msg[pos++] = (nid_len >> 8) & 0xFF;
    msg[pos++] = nid_len & 0xFF;
    memcpy(msg + pos, node_id, nid_len);
    pos += nid_len;
    msg[pos++] = 0; msg[pos++] = 0; msg[pos++] = 0; msg[pos++] = 0;

    return write_all(sess->fd, msg, pos);
}

int tcpcl_recv_sess_init(tcpcl_session_t *sess) {
    uint8_t hdr[32];
    if (read_all(sess->fd, hdr, 1) < 0) return -1;
    if (hdr[0] != TCPCL_MSG_SESS_INIT) return -1;

    if (read_all(sess->fd, hdr, 2) < 0) return -1;
    uint16_t peer_keepalive = (hdr[0] << 8) | hdr[1];
    if (peer_keepalive > 0 && peer_keepalive < sess->keepalive_interval)
        sess->keepalive_interval = peer_keepalive;

    if (read_all(sess->fd, hdr, 16) < 0) return -1;
    uint64_t peer_seg_mru = decode_uint64(hdr);
    uint64_t peer_xfer_mru = decode_uint64(hdr + 8);
    if (peer_seg_mru < sess->segment_mru) sess->segment_mru = peer_seg_mru;
    if (peer_xfer_mru < sess->transfer_mru) sess->transfer_mru = peer_xfer_mru;

    if (read_all(sess->fd, hdr, 2) < 0) return -1;
    uint16_t nid_len = (hdr[0] << 8) | hdr[1];
    if (nid_len > TCPCL_MAX_NODE_ID_LEN) return -1;
    if (nid_len > 0) {
        uint8_t *nid = bp_alloc(nid_len);
        if (!nid) return -1;
        if (read_all(sess->fd, nid, nid_len) < 0) { bp_free(nid); return -1; }
        bp_free(nid);
    }
    if (read_all(sess->fd, hdr, 4) < 0) return -1;

    sess->connected = 1;
    return 0;
}

int tcpcl_send_bundle(tcpcl_session_t *sess, const uint8_t *data, size_t len) {
    if (!sess || !sess->connected || !data || len == 0) return -1;
    if (len > sess->transfer_mru) return -1;

    uint64_t transfer_id = sess->next_transfer_id++;
    size_t offset = 0;
    int rc;

    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > sess->segment_mru) chunk = sess->segment_mru;

        uint8_t flags = 0;
        if (offset == 0) flags |= TCPCL_SEG_START;
        if (offset + chunk >= len) flags |= TCPCL_SEG_END;

        uint8_t hdr[18];
        hdr[0] = TCPCL_MSG_XFER_SEG;
        hdr[1] = flags;
        encode_uint64(hdr + 2, transfer_id);
        encode_uint64(hdr + 10, chunk);

        rc = write_all(sess->fd, hdr, 18);
        if (rc < 0) return rc;
        rc = write_all(sess->fd, data + offset, chunk);
        if (rc < 0) return rc;
        offset += chunk;
    }

    uint8_t ack[18];
    rc = read_all(sess->fd, ack, 18);
    if (rc < 0) return rc;
    if (ack[0] == TCPCL_MSG_SESS_TERM) {
        sess->connected = 0;
        return -1;
    }
    if (ack[0] != TCPCL_MSG_XFER_ACK) return -1;
    return 0;
}

int tcpcl_recv_bundle(tcpcl_session_t *sess, uint8_t **data, size_t *len) {
    if (!sess || !sess->connected || !data || !len) return -1;

    uint8_t *buf = NULL;
    size_t buf_len = 0;
    uint64_t expected_tid = 0;
    int first_segment = 1;
    int done = 0;
    int rc;

    while (!done) {
        uint8_t hdr[18];
        rc = read_all(sess->fd, hdr, 18);
        if (rc < 0) { bp_free(buf); return rc; }

        uint8_t msg_type = hdr[0];
        if (msg_type == TCPCL_MSG_SESS_TERM) {
            bp_free(buf);
            sess->connected = 0;
            return -1;
        }
        if (msg_type == TCPCL_MSG_KEEPALIVE) {
            continue;
        }
        if (msg_type != TCPCL_MSG_XFER_SEG) { bp_free(buf); return -1; }

        uint8_t flags = hdr[1];
        uint64_t tid = decode_uint64(hdr + 2);
        uint64_t seg_len = decode_uint64(hdr + 10);

        if (first_segment) {
            if (!(flags & TCPCL_SEG_START)) { bp_free(buf); return -1; }
            expected_tid = tid;
            first_segment = 0;
        } else {
            if (flags & TCPCL_SEG_START) { bp_free(buf); return -1; }
            if (tid != expected_tid) { bp_free(buf); return -1; }
        }

        if (seg_len > TCPCL_MAX_SEGMENT_SIZE) { bp_free(buf); return -1; }
        if (buf_len + seg_len > TCPCL_MAX_TRANSFER_SIZE) { bp_free(buf); return -1; }
        if (seg_len > sess->segment_mru) { bp_free(buf); return -1; }

        uint8_t *new_buf = bp_realloc(buf, buf_len + (size_t)seg_len);
        if (!new_buf) { bp_free(buf); return -1; }
        buf = new_buf;

        rc = read_all(sess->fd, buf + buf_len, (size_t)seg_len);
        if (rc < 0) { bp_free(buf); return rc; }
        buf_len += (size_t)seg_len;

        if (flags & TCPCL_SEG_END) done = 1;
    }

    uint8_t ack[18];
    ack[0] = TCPCL_MSG_XFER_ACK;
    ack[1] = TCPCL_SEG_END;
    encode_uint64(ack + 2, expected_tid);
    encode_uint64(ack + 10, buf_len);
    write_all(sess->fd, ack, 18);

    *data = buf;
    *len = buf_len;
    return 0;
}

int tcpcl_session_init(tcpcl_session_t *sess, int fd) {
    memset(sess, 0, sizeof(*sess));
    sess->fd = fd;
    sess->keepalive_interval = 30;
    sess->segment_mru = 65536;
    sess->transfer_mru = 1024 * 1024;
    sess->next_transfer_id = 1;
    set_socket_timeout(fd, TCPCL_DEFAULT_TIMEOUT_MS);
    return 0;
}

int tcpcl_session_close(tcpcl_session_t *sess) {
    if (sess->connected) {
        uint8_t term[3] = { TCPCL_MSG_SESS_TERM, 0, 0 };
        write_all(sess->fd, term, 3);
    }
#ifdef _WIN32
    closesocket(sess->fd);
#else
    close(sess->fd);
#endif
    sess->fd = -1;
    sess->connected = 0;
    return 0;
}

int tcpcl_send_keepalive(tcpcl_session_t *sess) {
    uint8_t ka = TCPCL_MSG_KEEPALIVE;
    return write_all(sess->fd, &ka, 1);
}
