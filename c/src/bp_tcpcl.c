/* bp_tcpcl.c - TCPCLv4 (RFC 9174) */
#include "bp_tcpcl.h"
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
#endif

static const uint8_t TCPCL_MAGIC[4] = {'d', 't', 'n', '!'};
#define TCPCL_VERSION 4

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const char*)(buf + sent), (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, (char*)(buf + got), (int)(len - got), 0);
        if (n <= 0) return -1;
        got += n;
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
    uint8_t *nid = malloc(nid_len);
    if (read_all(sess->fd, nid, nid_len) < 0) { free(nid); return -1; }
    free(nid);
    if (read_all(sess->fd, hdr, 4) < 0) return -1;

    sess->connected = 1;
    return 0;
}

int tcpcl_send_bundle(tcpcl_session_t *sess, const uint8_t *data, size_t len) {
    if (!sess->connected) return -1;

    uint64_t transfer_id = sess->next_transfer_id++;
    size_t offset = 0;

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

        if (write_all(sess->fd, hdr, 18) < 0) return -1;
        if (write_all(sess->fd, data + offset, chunk) < 0) return -1;
        offset += chunk;
    }

    uint8_t ack[18];
    if (read_all(sess->fd, ack, 18) < 0) return -1;
    if (ack[0] != TCPCL_MSG_XFER_ACK) return -1;
    return 0;
}

int tcpcl_recv_bundle(tcpcl_session_t *sess, uint8_t **data, size_t *len) {
    if (!sess->connected) return -1;

    uint8_t *buf = NULL;
    size_t buf_len = 0;
    uint64_t transfer_id = 0;
    int done = 0;

    while (!done) {
        uint8_t hdr[18];
        if (read_all(sess->fd, hdr, 18) < 0) { free(buf); return -1; }
        if (hdr[0] != TCPCL_MSG_XFER_SEG) { free(buf); return -1; }

        uint8_t flags = hdr[1];
        transfer_id = decode_uint64(hdr + 2);
        uint64_t seg_len = decode_uint64(hdr + 10);

        buf = realloc(buf, buf_len + seg_len);
        if (read_all(sess->fd, buf + buf_len, seg_len) < 0) { free(buf); return -1; }
        buf_len += seg_len;
        if (flags & TCPCL_SEG_END) done = 1;
    }

    uint8_t ack[18];
    ack[0] = TCPCL_MSG_XFER_ACK;
    ack[1] = TCPCL_SEG_END;
    encode_uint64(ack + 2, transfer_id);
    encode_uint64(ack + 10, buf_len);
    write_all(sess->fd, ack, 18);

    *data = buf; *len = buf_len;
    return 0;
}

int tcpcl_session_init(tcpcl_session_t *sess, int fd) {
    memset(sess, 0, sizeof(*sess));
    sess->fd = fd;
    sess->keepalive_interval = 30;
    sess->segment_mru = 65536;
    sess->transfer_mru = 1024 * 1024;
    sess->next_transfer_id = 1;
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
