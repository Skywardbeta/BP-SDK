/*
 * test_ion_policy.c - ION lowering, fail-fast validation, and the ION adapter.
 *
 * Covers bpsecadmin rule generation, default-variant restriction, injection
 * guards, and the rules an ION secure_link writes to a temp .bpsecrc.
 */
#include "bp_adapter.h"
#include "bp_adapter_ion.h"
#include "bp_ion_policy.h"
#include "bp_session.h"
#include "bp_utils.h"
#include "test_harness.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

static void test_lower_bcb_only(void) {
    bp_security_policy_t p = {
        .mode        = BPSEC_MODE_BCB_ONLY,
        .bcb_context = BPSEC_CTX_AES_GCM_256,
        .bcb_targets = BPSEC_TARGET_PAYLOAD,
        .bcb_scope   = BPSEC_SCOPE_BTSD_ONLY,
        .bcb_key_ref = "k1",
    };
    char buf[2048];
    int n = bp_ion_policy_lower(&p, "ipn:1.1", "ipn:2.1", "es1", 1, buf, sizeof(buf));
    ASSERT(n > 0);
    ASSERT(strstr(buf, "\"event_set\"") != NULL);
    ASSERT(strstr(buf, "\"policyrule\"") != NULL);
    ASSERT(strstr(buf, "bcb-confidentiality") != NULL);
    ASSERT(strstr(buf, "\"sc_id\":2") != NULL);
    ASSERT(strstr(buf, "\"key_name\":\"k1\"") != NULL);
    ASSERT(strstr(buf, "\"src\":\"ipn:1.1\"") != NULL);
    ASSERT(strstr(buf, "\"dest\":\"ipn:2.1\"") != NULL);
    ASSERT(strstr(buf, "bib-integrity") == NULL);
    PASS();
}

static void test_lower_bib_bcb(void) {
    char buf[2048];
    int n = bp_ion_policy_lower(&POLICY_BIB_BCB, "dtn://a/x", "dtn://b/y",
                                "esX", 10, buf, sizeof(buf));
    ASSERT(n > 0);
    ASSERT(strstr(buf, "bib-integrity") != NULL);
    ASSERT(strstr(buf, "bcb-confidentiality") != NULL);
    ASSERT(strstr(buf, "\"sc_id\":1") != NULL);
    ASSERT(strstr(buf, "\"sc_id\":2") != NULL);
    ASSERT(strstr(buf, "\"rule_id\":10") != NULL);
    ASSERT(strstr(buf, "\"rule_id\":11") != NULL);
    ASSERT(strstr(buf, "\"key_name\":\"int-key\"") != NULL);
    ASSERT(strstr(buf, "\"key_name\":\"conf-key\"") != NULL);
    PASS();
}

static void test_lower_buffer_too_small(void) {
    char buf[16];
    int n = bp_ion_policy_lower(&POLICY_BIB_BCB, "ipn:1.1", "ipn:2.1",
                                "es", 1, buf, sizeof(buf));
    ASSERT(n == BPSEC_ERR_INTERNAL);
    PASS();
}

static void test_validate_fail_fast(void) {
    bp_security_policy_t no_key = {
        .mode = BPSEC_MODE_BCB_ONLY,
        .bcb_context = BPSEC_CTX_AES_GCM_256,
        .bcb_targets = BPSEC_TARGET_PAYLOAD,
        .bcb_scope = BPSEC_SCOPE_BTSD_ONLY,
        .bcb_key_ref = NULL,
    };
    ASSERT(bp_ion_policy_validate(&no_key) == BPSEC_ERR_INVALID_POLICY);

    bp_security_policy_t bad_ctx = no_key;
    bad_ctx.bcb_context = BPSEC_CTX_HMAC_SHA2_256;
    bad_ctx.bcb_key_ref = "k";
    ASSERT(bp_ion_policy_validate(&bad_ctx) == BPSEC_ERR_INVALID_CONTEXT);

    bp_security_policy_t bad_tgt = no_key;
    bad_tgt.bcb_key_ref = "k";
    bad_tgt.bcb_targets = BPSEC_TARGET_PRIMARY;
    ASSERT(bp_ion_policy_validate(&bad_tgt) == BPSEC_ERR_INVALID_POLICY);

    bp_security_policy_t inject = no_key;
    inject.bcb_key_ref = "k\"; evil";
    ASSERT(bp_ion_policy_validate(&inject) == BPSEC_ERR_INVALID_POLICY);

    ASSERT(bp_ion_policy_validate(NULL) == BPSEC_ERR_INVALID_POLICY);

    char buf[512];
    int n = bp_ion_policy_lower(&POLICY_BIB_BCB, "ipn:1.1\"x", "ipn:2.1",
                                "es", 1, buf, sizeof(buf));
    ASSERT(n == BPSEC_ERR_INVALID_POLICY);
    PASS();
}

static char *slurp(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    if (out_len) *out_len = rd;
    return buf;
}

static void test_ion_adapter_writes_rules(void) {
    const char *rc = "test_ion.bpsecrc";
    remove(rc);
    char config[128];
    snprintf(config, sizeof(config), "rc=%s;exec=0", rc);

    bp_secure_link_t *link = bp_secure_link_open("ion", config);
    ASSERT(link != NULL);
    ASSERT(bp_secure_link_set_source(link, "ipn:1.1") == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_set_security(link, &POLICY_BIB_BCB) == BPSEC_SUCCESS);

    const uint8_t d[] = "telemetry";
    ASSERT(bp_secure_link_send(link, "ipn:2.1", d, sizeof(d) - 1, NULL) == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_send(link, "ipn:3.1", d, sizeof(d) - 1, NULL) == BPSEC_SUCCESS);

    bp_secure_link_close(link);

    size_t len = 0;
    char *script = slurp(rc, &len);
    ASSERT(script != NULL);
    ASSERT(strstr(script, "bib-integrity") != NULL);
    ASSERT(strstr(script, "bcb-confidentiality") != NULL);
    ASSERT(strstr(script, "\"dest\":\"ipn:2.1\"") != NULL);
    ASSERT(strstr(script, "\"dest\":\"ipn:3.1\"") != NULL);
    ASSERT(strstr(script, "bpsdk_es_1") != NULL);
    ASSERT(strstr(script, "bpsdk_es_3") != NULL);
    free(script);
    remove(rc);
    PASS();
}

static void test_ion_rejects_nondefault_variants(void) {
    bp_security_policy_t sha384 = POLICY_BIB_BCB;
    sha384.bib_context = BPSEC_CTX_HMAC_SHA2_384;
    bp_security_policy_t aes128 = POLICY_BIB_BCB;
    aes128.bcb_context = BPSEC_CTX_AES_GCM_128;

    ASSERT(bp_secure_policy_validate(&sha384) == BPSEC_SUCCESS);
    ASSERT(bp_secure_policy_validate(&aes128) == BPSEC_SUCCESS);

    bp_secure_link_t *link = bp_secure_link_open("ion", "rc=test_ion_var.bpsecrc;exec=0");
    ASSERT(link != NULL);
    ASSERT(bp_secure_link_set_source(link, "ipn:1.1") == BPSEC_SUCCESS);
    ASSERT(bp_secure_link_set_security(link, &sha384) == BPSEC_ERR_INVALID_CONTEXT);
    ASSERT(bp_secure_link_set_security(link, &aes128) == BPSEC_ERR_INVALID_CONTEXT);
    ASSERT(bp_secure_link_set_security(link, &POLICY_BIB_BCB) == BPSEC_SUCCESS);
    bp_secure_link_close(link);
    remove("test_ion_var.bpsecrc");
    PASS();
}

static void test_lower_stress(void) {
    for (int i = 0; i < 100000; i++) {
        char buf[1024];
        char src[32], dst[32], es[32];
        snprintf(src, sizeof(src), "ipn:%d.%d", i % 100, i % 7);
        snprintf(dst, sizeof(dst), "ipn:%d.%d", (i + 1) % 100, i % 5);
        snprintf(es, sizeof(es), "es_%d", i);
        int n = bp_ion_policy_lower(&POLICY_BIB_BCB, src, dst, es,
                                    (uint16_t)(i & 0x7FFF), buf, sizeof(buf));
        if (n <= 0 || buf[n] != '\0' || (size_t)n != strlen(buf)) {
            printf("FAIL\n    iteration %d produced n=%d\n", i, n);
            tests_failed++;
            return;
        }
    }
    PASS();
}

int main(void) {
    bp_log_set_level(BP_LOG_ERROR);
    printf("=== ION policy lowering / adapter tests ===\n");
    RUN_TEST(lower_bcb_only);
    RUN_TEST(lower_bib_bcb);
    RUN_TEST(lower_buffer_too_small);
    RUN_TEST(validate_fail_fast);
    RUN_TEST(ion_adapter_writes_rules);
    RUN_TEST(ion_rejects_nondefault_variants);
    RUN_TEST(lower_stress);
    TEST_SUMMARY();
    return tests_failed == 0 ? 0 : 1;
}
