/*
 * test_ud3tn_adapter.c - uD3TN adapter driven against an in-process mock AAP
 * server: registration sub-EID derivation, source-change re-registration,
 * fail-fast on invalid sub-EIDs, WELCOME handshake, and a send stress loop.
 */
#include "bp_adapter.h"
#include "bp_adapter_ud3tn.h"
#include "bp_aap.h"
#include "bp_session.h"
#include "bp_utils.h"
#include "test_harness.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef int socklen_t;
typedef SOCKET sock_t;
#define CLOSESOCK closesocket
#define BAD_SOCK INVALID_SOCKET
#define THREAD_T HANDLE
#define THREAD_CREATE(t, fn, arg) (t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(fn), (arg), 0, NULL)
#define THREAD_JOIN(t) WaitForSingleObject((t), INFINITE)
typedef DWORD thread_ret_t;
static void msleep(int ms) { Sleep(ms); }
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
typedef int sock_t;
#define CLOSESOCK close
#define BAD_SOCK (-1)
#define THREAD_T pthread_t
#define THREAD_CREATE(t, fn, arg) pthread_create(&(t), NULL, (fn), (arg))
#define THREAD_JOIN(t) pthread_join((t), NULL)
typedef void *thread_ret_t;
static void msleep(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}
#endif

static const bp_security_policy_t POLICY_BCB256 = {
    .mode = BPSEC_MODE_BCB_ONLY,
    .bcb_context = BPSEC_CTX_AES_GCM_256,
    .bcb_targets = BPSEC_TARGET_PAYLOAD,
    .bcb_scope = BPSEC_SCOPE_BTSD_ONLY,
    .bcb_key_ref = "conf-key",
};

typedef struct {
    volatile int ready;
    volatile int port;
    volatile int bundles;
    volatile int stop;
    volatile int no_welcome;
    volatile int registers;
    char         agent[64];
} mock_aap_t;

static void srv_send_msg(sock_t fd, const bp_aap_msg_t *m) {
    uint8_t buf[1024];
    size_t w = 0;
    if (bp_aap_serialize(m, buf, sizeof(buf), &w) == BP_AAP_OK)
        send(fd, (const char *)buf, (int)w, 0);
}

static thread_ret_t mock_aap_server(void *arg) {
    mock_aap_t *s = arg;
    sock_t lfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = 0;
    bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(lfd, 1);
    socklen_t alen = sizeof(addr);
    getsockname(lfd, (struct sockaddr *)&addr, &alen);
    s->port = ntohs(addr.sin_port);
    s->ready = 1;

    sock_t cfd = accept(lfd, NULL, NULL);
    CLOSESOCK(lfd);
    if (cfd == BAD_SOCK) return (thread_ret_t)0;

    if (s->no_welcome) {
        bp_aap_msg_t ack = {0};
        ack.type = BP_AAP_ACK;
        srv_send_msg(cfd, &ack);
    } else {
        bp_aap_msg_t welcome = {0};
        welcome.type = BP_AAP_WELCOME;
        welcome.eid = "dtn://mock/";
        welcome.eid_len = strlen(welcome.eid);
        srv_send_msg(cfd, &welcome);
    }

    uint8_t *rx = malloc(1 << 16);
    size_t rx_len = 0, rx_cap = 1 << 16;
    uint64_t next_id = 1;
    for (;;) {
        bp_aap_msg_t msg = {0};
        size_t consumed = 0;
        int rc = bp_aap_parse(rx, rx_len, &msg, &consumed);
        if (rc == BP_AAP_OK) {
            memmove(rx, rx + consumed, rx_len - consumed);
            rx_len -= consumed;
            if (msg.type == BP_AAP_REGISTER) {
                s->registers++;
                if (msg.eid) snprintf(s->agent, sizeof(s->agent), "%s", msg.eid);
                else s->agent[0] = '\0';
                bp_aap_msg_t ack = {0}; ack.type = BP_AAP_ACK;
                srv_send_msg(cfd, &ack);
            } else if (msg.type == BP_AAP_SENDBUNDLE) {
                s->bundles++;
                bp_aap_msg_t conf = {0};
                conf.type = BP_AAP_SENDCONFIRM;
                conf.bundle_id = next_id++;
                srv_send_msg(cfd, &conf);
            }
            bp_aap_msg_free(&msg);
            continue;
        }
        if (rc == BP_AAP_ERR) break;
        if (rx_len + 4096 > rx_cap) {
            rx_cap *= 2;
            uint8_t *nb = realloc(rx, rx_cap);
            if (!nb) break;
            rx = nb;
        }
        int n = (int)recv(cfd, (char *)rx + rx_len, 4096, 0);
        if (n <= 0) break;
        rx_len += (size_t)n;
    }
    free(rx);
    CLOSESOCK(cfd);
    return (thread_ret_t)0;
}

static int start_mock_server(mock_aap_t *s, THREAD_T *th, int no_welcome) {
    memset(s, 0, sizeof(*s));
    s->no_welcome = no_welcome;
    THREAD_CREATE(*th, mock_aap_server, s);
    for (int i = 0; i < 2000 && !s->ready; i++) msleep(1);
    return s->ready ? s->port : 0;
}

static void test_ud3tn_aap_send(void) {
    mock_aap_t srv;
    THREAD_T th;
    int port = start_mock_server(&srv, &th, 0);
    ASSERT(port > 0);

    char config[128];
    snprintf(config, sizeof(config), "host=127.0.0.1;port=%d;agent=app", port);
    bp_secure_link_t *link = bp_secure_link_open("ud3tn", config);
    ASSERT(link != NULL);
    ASSERT(bp_secure_link_set_source(link, "dtn://sat/app") == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_set_security(link, &POLICY_BCB256) == BPSEC_SUCCESS);

    const uint8_t d[] = "hello ud3tn";
    ASSERT(bp_secure_link_send(link, "dtn://gs/sink", d, sizeof(d) - 1, NULL) == BPSEC_SUCCESS);

    bp_secure_link_close(link);
    THREAD_JOIN(th);
    ASSERT(srv.bundles == 1);
    PASS();
}

static void test_ud3tn_agent_demux(void) {
    mock_aap_t srv;
    THREAD_T th;
    int port = start_mock_server(&srv, &th, 0);
    ASSERT(port > 0);

    char config[128];
    snprintf(config, sizeof(config), "host=127.0.0.1;port=%d", port);
    bp_secure_link_t *link = bp_secure_link_open("ud3tn", config);
    ASSERT(link != NULL);
    ASSERT(bp_secure_link_set_source(link, "dtn://sat/telemetry") == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_set_security(link, &POLICY_BCB256) == BPSEC_SUCCESS);

    const uint8_t d[] = "x";
    ASSERT(bp_secure_link_send(link, "dtn://gs/sink", d, 1, NULL) == BPSEC_SUCCESS);
    bp_secure_link_close(link);
    THREAD_JOIN(th);
    ASSERT(strcmp(srv.agent, "telemetry") == 0);
    PASS();
}

static void test_ud3tn_agent_demux_ipn(void) {
    mock_aap_t srv;
    THREAD_T th;
    int port = start_mock_server(&srv, &th, 0);
    ASSERT(port > 0);

    char config[128];
    snprintf(config, sizeof(config), "host=127.0.0.1;port=%d", port);
    bp_secure_link_t *link = bp_secure_link_open("ud3tn", config);
    ASSERT(link != NULL);
    ASSERT(bp_secure_link_set_source(link, "ipn:5.3") == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_set_security(link, &POLICY_BCB256) == BPSEC_SUCCESS);

    const uint8_t d[] = "x";
    ASSERT(bp_secure_link_send(link, "ipn:9.1", d, 1, NULL) == BPSEC_SUCCESS);
    bp_secure_link_close(link);
    THREAD_JOIN(th);
    ASSERT(strcmp(srv.agent, "3") == 0);
    PASS();
}

static void test_ud3tn_source_change_reregisters(void) {
    mock_aap_t srv;
    THREAD_T th;
    int port = start_mock_server(&srv, &th, 0);
    ASSERT(port > 0);

    char config[128];
    snprintf(config, sizeof(config), "host=127.0.0.1;port=%d", port);
    bp_secure_link_t *link = bp_secure_link_open("ud3tn", config);
    ASSERT(link != NULL);
    ASSERT(bp_secure_link_set_security(link, &POLICY_BCB256) == BPSEC_SUCCESS);

    const uint8_t d[] = "x";
    ASSERT(bp_secure_link_set_source(link, "dtn://sat/a") == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_send(link, "dtn://gs/sink", d, 1, NULL) == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_set_source(link, "dtn://sat/b") == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_send(link, "dtn://gs/sink", d, 1, NULL) == BPSEC_SUCCESS);

    bp_secure_link_close(link);
    THREAD_JOIN(th);
    ASSERT(srv.registers == 2);
    ASSERT(strcmp(srv.agent, "b") == 0);
    PASS();
}

static void test_ud3tn_empty_demux_fails(void) {
    bp_secure_link_t *link = bp_secure_link_open("ud3tn", "host=127.0.0.1;port=4242");
    ASSERT(link != NULL);
    ASSERT(bp_secure_link_set_source(link, "dtn://sat") == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_set_security(link, &POLICY_BCB256) == BPSEC_SUCCESS);

    const uint8_t d[] = "x";
    ASSERT(bp_secure_link_send(link, "dtn://gs/sink", d, 1, NULL) == BPSEC_ERR_INVALID_POLICY);
    bp_secure_link_close(link);
    PASS();
}

static void test_ud3tn_invalid_demux_fails(void) {
    const uint8_t d[] = "x";
    /* ipn service that is not decimal, and a dtn demux with a space (< 0x21):
     * both are syntactically invalid sub-EIDs and must fail before connecting. */
    const char *bad_sources[] = { "ipn:5.abc", "dtn://sat/a b" };
    for (size_t i = 0; i < sizeof(bad_sources) / sizeof(bad_sources[0]); i++) {
        bp_secure_link_t *link =
            bp_secure_link_open("ud3tn", "host=127.0.0.1;port=4242");
        ASSERT(link != NULL);
        ASSERT(bp_secure_link_set_source(link, bad_sources[i]) == BPSEC_SUCCESS);
        ASSERT(bp_secure_link_set_security(link, &POLICY_BCB256) == BPSEC_SUCCESS);
        ASSERT(bp_secure_link_send(link, "dtn://gs/sink", d, 1, NULL) ==
               BPSEC_ERR_INVALID_POLICY);
        bp_secure_link_close(link);
    }
    PASS();
}

static void test_ud3tn_missing_welcome_fails(void) {
    mock_aap_t srv;
    THREAD_T th;
    int port = start_mock_server(&srv, &th, 1);
    ASSERT(port > 0);

    char config[128];
    snprintf(config, sizeof(config), "host=127.0.0.1;port=%d;agent=app", port);
    bp_secure_link_t *link = bp_secure_link_open("ud3tn", config);
    ASSERT(link != NULL);
    ASSERT(bp_secure_link_set_source(link, "dtn://sat/app") == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_set_security(link, &POLICY_BCB256) == BPSEC_SUCCESS);

    const uint8_t d[] = "x";
    ASSERT(bp_secure_link_send(link, "dtn://gs/sink", d, 1, NULL) != BPSEC_SUCCESS);
    bp_secure_link_close(link);
    THREAD_JOIN(th);
    PASS();
}

#define STRESS_SENDS 2000

static void test_ud3tn_stress(void) {
    mock_aap_t srv;
    THREAD_T th;
    int port = start_mock_server(&srv, &th, 0);
    ASSERT(port > 0);

    char config[128];
    snprintf(config, sizeof(config), "host=127.0.0.1;port=%d;agent=app", port);
    bp_secure_link_t *link = bp_secure_link_open("ud3tn", config);
    ASSERT(link != NULL);
    ASSERT(bp_secure_link_set_source(link, "dtn://sat/app") == BPSEC_SUCCESS);

    uint8_t payload[256];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)i;

    int ok = 1;
    for (int i = 0; i < STRESS_SENDS; i++) {
        char dest[64];
        snprintf(dest, sizeof(dest), "dtn://gs%d/sink", i % 7);
        if (bp_secure_link_send(link, dest, payload, sizeof(payload), NULL) != BPSEC_SUCCESS) {
            ok = 0;
            break;
        }
    }
    bp_secure_link_close(link);
    THREAD_JOIN(th);
    ASSERT(ok);
    ASSERT(srv.bundles == STRESS_SENDS);
    PASS();
}

int main(void) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    bp_log_set_level(BP_LOG_ERROR);

    printf("=== uD3TN adapter (mock AAP server) tests ===\n");
    RUN_TEST(ud3tn_aap_send);
    RUN_TEST(ud3tn_agent_demux);
    RUN_TEST(ud3tn_agent_demux_ipn);
    RUN_TEST(ud3tn_source_change_reregisters);
    RUN_TEST(ud3tn_empty_demux_fails);
    RUN_TEST(ud3tn_invalid_demux_fails);
    RUN_TEST(ud3tn_missing_welcome_fails);
    RUN_TEST(ud3tn_stress);
    TEST_SUMMARY();
#ifdef _WIN32
    WSACleanup();
#endif
    return tests_failed == 0 ? 0 : 1;
}
