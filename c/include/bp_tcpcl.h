/* bp_tcpcl.h - TCPCLv4 Session (RFC 9174) */
#ifndef BP_TCPCL_H
#define BP_TCPCL_H

#include <stdint.h>
#include <stddef.h>

#define TCPCL_MSG_SESS_INIT   0x07
#define TCPCL_MSG_SESS_TERM   0x05
#define TCPCL_MSG_XFER_SEG    0x01
#define TCPCL_MSG_XFER_ACK    0x02
#define TCPCL_MSG_XFER_REFUSE 0x03
#define TCPCL_MSG_KEEPALIVE   0x04
#define TCPCL_MSG_REJECT      0x06

#define TCPCL_SEG_END         0x01
#define TCPCL_SEG_START       0x02

typedef struct {
    int fd;
    uint16_t keepalive_interval;
    uint64_t segment_mru;
    uint64_t transfer_mru;
    uint64_t next_transfer_id;
    int connected;
} tcpcl_session_t;

int tcpcl_send_contact_header(int fd);
int tcpcl_recv_contact_header(int fd);
int tcpcl_send_sess_init(tcpcl_session_t *sess);
int tcpcl_recv_sess_init(tcpcl_session_t *sess);
int tcpcl_send_bundle(tcpcl_session_t *sess, const uint8_t *data, size_t len);
int tcpcl_recv_bundle(tcpcl_session_t *sess, uint8_t **data, size_t *len);
int tcpcl_session_init(tcpcl_session_t *sess, int fd);
int tcpcl_session_close(tcpcl_session_t *sess);
int tcpcl_send_keepalive(tcpcl_session_t *sess);

#endif
