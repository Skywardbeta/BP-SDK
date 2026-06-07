/*
 * test_facade.c - bp_secure_link facade semantics over a mock adapter:
 * registration-once-per-destination, fail-fast set_security, and unknown stack.
 */
#include "bp_adapter.h"
#include "bp_session.h"
#include "bp_utils.h"
#include "test_harness.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const bp_security_policy_t POLICY_BIB_BCB = {
    .mode        = BPSEC_MODE_BIB_BCB,
    .bib_context = BPSEC_CTX_HMAC_SHA2_256,
    .bib_targets = BPSEC_TARGET_PAYLOAD,
    .bib_scope   = BPSEC_SCOPE_BTSD_ONLY,
    .bib_key_ref = "int-key",
    .bcb_context = BPSEC_CTX_AES_GCM_256,
    .bcb_targets = BPSEC_TARGET_PAYLOAD,
    .bcb_scope   = BPSEC_SCOPE_BTSD_ONLY,
    .bcb_key_ref = "conf-key",
};

typedef struct {
    int opened;
    int closed;
    int register_calls;
    int send_calls;
    char last_dest[64];
} mock_ctx_t;

static mock_ctx_t g_mock;

static int mock_open(const char *config, void **state) {
    (void)config;
    g_mock.opened++;
    *state = &g_mock;
    return BPSEC_SUCCESS;
}
static void mock_close(void *state) { ((mock_ctx_t *)state)->closed++; }
static int mock_register(void *state, const char *src, const char *dst,
                         const bp_security_policy_t *p) {
    (void)src; (void)p;
    mock_ctx_t *m = state;
    m->register_calls++;
    snprintf(m->last_dest, sizeof(m->last_dest), "%s", dst);
    return BPSEC_SUCCESS;
}
static int mock_send(void *state, const char *src, const char *dst,
                     const uint8_t *d, size_t n, const bp_delivery_opts_t *o) {
    (void)src; (void)dst; (void)d; (void)n; (void)o;
    ((mock_ctx_t *)state)->send_calls++;
    return BPSEC_SUCCESS;
}
static const bp_adapter_t MOCK_ADAPTER = {
    .name = "mock",
    .open = mock_open,
    .close = mock_close,
    .register_security = mock_register,
    .send = mock_send,
};

static void test_facade_register_once(void) {
    memset(&g_mock, 0, sizeof(g_mock));
    ASSERT(bp_adapter_register(&MOCK_ADAPTER) == BPSEC_SUCCESS);

    bp_secure_link_t *link = bp_secure_link_open("mock", NULL);
    ASSERT(link != NULL);
    ASSERT(strcmp(bp_secure_link_stack(link), "mock") == 0);

    const uint8_t d[] = "hi";
    ASSERT(bp_secure_link_send(link, "dtn://b/x", d, 2, NULL) != BPSEC_SUCCESS);

    ASSERT(bp_secure_link_set_source(link, "dtn://a/app") == BPSEC_SUCCESS);

    bp_security_policy_t bad = { .mode = BPSEC_MODE_BCB_ONLY };
    ASSERT(bp_secure_link_set_security(link, &bad) != BPSEC_SUCCESS);

    ASSERT(bp_secure_link_set_security(link, &POLICY_BIB_BCB) == BPSEC_SUCCESS);

    ASSERT(bp_secure_link_send(link, "dtn://b/x", d, 2, NULL) == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_send(link, "dtn://b/x", d, 2, NULL) == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_send(link, "dtn://c/y", d, 2, NULL) == BPSEC_SUCCESS);

    ASSERT(g_mock.register_calls == 2);
    ASSERT(g_mock.send_calls == 3);

    bp_secure_link_close(link);
    ASSERT(g_mock.closed == 1);
    PASS();
}

static void test_facade_unknown_stack(void) {
    ASSERT(bp_secure_link_open("does-not-exist", NULL) == NULL);
    PASS();
}

int main(void) {
    bp_log_set_level(BP_LOG_ERROR);
    printf("=== bp_secure_link facade tests ===\n");
    RUN_TEST(facade_register_once);
    RUN_TEST(facade_unknown_stack);
    TEST_SUMMARY();
    return tests_failed == 0 ? 0 : 1;
}
