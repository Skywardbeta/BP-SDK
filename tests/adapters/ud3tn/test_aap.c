/*
 * test_aap.c - AAP v1 codec: serialize/parse roundtrip and hard bounds.
 *
 * Pure codec coverage (no sockets): roundtrips per message type, partial and
 * malformed frames, and the parse/serialize overflow guards.
 */
#include "bp_aap.h"
#include "test_harness.h"

#include <stdint.h>
#include <string.h>

static int aap_roundtrip(bp_aap_type_t type, const char *eid,
                         const uint8_t *pl, size_t pl_len, uint64_t bid) {
    bp_aap_msg_t in = {0};
    in.type = type;
    in.eid = (char *)eid;
    in.eid_len = eid ? strlen(eid) : 0;
    in.payload = (uint8_t *)pl;
    in.payload_len = pl_len;
    in.bundle_id = bid;

    uint8_t buf[1024];
    size_t written = 0;
    if (bp_aap_serialize(&in, buf, sizeof(buf), &written) != BP_AAP_OK) return 0;
    if (written != bp_aap_serialized_size(&in)) return 0;

    bp_aap_msg_t out = {0};
    size_t consumed = 0;
    int rc = bp_aap_parse(buf, written, &out, &consumed);
    int ok = (rc == BP_AAP_OK) && (consumed == written) && (out.type == type) &&
             (out.bundle_id == bid) && (out.payload_len == pl_len) &&
             (out.eid_len == (eid ? strlen(eid) : 0));
    if (ok && eid) ok = (strcmp(out.eid, eid) == 0);
    if (ok && pl_len) ok = (memcmp(out.payload, pl, pl_len) == 0);
    bp_aap_msg_free(&out);
    return ok;
}

static void test_aap_roundtrip(void) {
    ASSERT(aap_roundtrip(BP_AAP_REGISTER, "app", NULL, 0, 0));
    ASSERT(aap_roundtrip(BP_AAP_WELCOME, "dtn://node/", NULL, 0, 0));
    const uint8_t pl[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11};
    ASSERT(aap_roundtrip(BP_AAP_SENDBUNDLE, "dtn://b/sink", pl, sizeof(pl), 0));
    ASSERT(aap_roundtrip(BP_AAP_RECVBUNDLE, "dtn://a/src", pl, sizeof(pl), 0));
    ASSERT(aap_roundtrip(BP_AAP_SENDCONFIRM, NULL, NULL, 0, 42));
    ASSERT(aap_roundtrip(BP_AAP_ACK, NULL, NULL, 0, 0));
    PASS();
}

static void test_aap_partial_and_malformed(void) {
    bp_aap_msg_t in = {0};
    in.type = BP_AAP_SENDBUNDLE;
    in.eid = "dtn://b/x";
    in.eid_len = strlen(in.eid);
    uint8_t pl[32];
    memset(pl, 0xAB, sizeof(pl));
    in.payload = pl;
    in.payload_len = sizeof(pl);

    uint8_t buf[256];
    size_t written = 0;
    ASSERT(bp_aap_serialize(&in, buf, sizeof(buf), &written) == BP_AAP_OK);

    bp_aap_msg_t out = {0};
    size_t consumed = 0;
    for (size_t cut = 1; cut < written; cut++) {
        int rc = bp_aap_parse(buf, cut, &out, &consumed);
        ASSERT(rc == BP_AAP_NEED_MORE);
    }
    ASSERT(bp_aap_parse(buf, written, &out, &consumed) == BP_AAP_OK);
    bp_aap_msg_free(&out);

    uint8_t bad[4] = {0x20, 0, 0, 0};
    ASSERT(bp_aap_parse(bad, sizeof(bad), &out, &consumed) == BP_AAP_ERR);

    ASSERT(bp_aap_serialize(&in, buf, 3, &written) == BP_AAP_ERR);
    PASS();
}

static void test_aap_overflow_guard(void) {
    /* SENDBUNDLE header claiming a 2^60-byte payload must not be accepted or
     * over-read; only NEED_MORE is valid until the bytes actually arrive. */
    uint8_t frame[1 + 2 + 3 + 8];
    size_t off = 0;
    frame[off++] = (0x1 << 4) | BP_AAP_SENDBUNDLE;
    frame[off++] = 0; frame[off++] = 3;
    frame[off++] = 'a'; frame[off++] = 'b'; frame[off++] = 'c';
    uint64_t huge = (uint64_t)1 << 60;
    for (int i = 0; i < 8; i++) frame[off++] = (uint8_t)(huge >> (56 - 8 * i));

    bp_aap_msg_t out = {0};
    size_t consumed = 0;
    int rc = bp_aap_parse(frame, sizeof(frame), &out, &consumed);
    ASSERT(rc == BP_AAP_NEED_MORE);
    PASS();
}

static void test_aap_serialize_overflow(void) {
    bp_aap_msg_t m = {0};
    m.type = BP_AAP_SENDBUNDLE;
    m.eid = "dtn://x/y";
    m.eid_len = strlen(m.eid);
    m.payload_len = SIZE_MAX;
    m.payload = (uint8_t *)m.eid;

    ASSERT(bp_aap_serialized_size(&m) == 0);
    uint8_t buf[64];
    size_t w = 0;
    ASSERT(bp_aap_serialize(&m, buf, sizeof(buf), &w) == BP_AAP_ERR);
    PASS();
}

int main(void) {
    printf("=== AAP v1 codec tests ===\n");
    RUN_TEST(aap_roundtrip);
    RUN_TEST(aap_partial_and_malformed);
    RUN_TEST(aap_overflow_guard);
    RUN_TEST(aap_serialize_overflow);
    TEST_SUMMARY();
    return tests_failed == 0 ? 0 : 1;
}
