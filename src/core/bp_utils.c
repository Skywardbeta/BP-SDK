/* bp_utils.c - Core utilities */
#include "bp_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static bp_log_level_t g_log_level = BP_LOG_INFO;

uint64_t bp_time_to_dtn(uint64_t unix_sec) {
    return (unix_sec > BP_DTN_EPOCH) ? (unix_sec - BP_DTN_EPOCH) : 0;
}

uint64_t bp_time_from_dtn(uint64_t dtn_sec) { return dtn_sec + BP_DTN_EPOCH; }
uint64_t bp_time_now_dtn(void) { return bp_time_to_dtn((uint64_t)time(NULL)); }

uint16_t bp_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) crc = (crc & 1) ? (crc >> 1) ^ 0x8408 : crc >> 1;
    }
    return crc ^ 0xFFFF;
}

uint32_t bp_crc32c(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) crc = (crc & 1) ? (crc >> 1) ^ 0x82F63B78 : crc >> 1;
    }
    return crc ^ 0xFFFFFFFF;
}

void *bp_alloc(size_t size) { return malloc(size); }
void *bp_realloc(void *ptr, size_t size) { return realloc(ptr, size); }
void bp_free(void *ptr) { free(ptr); }
char *bp_strdup(const char *s) { return s ? strdup(s) : NULL; }

void bp_log_set_level(bp_log_level_t level) { g_log_level = level; }

void bp_log(bp_log_level_t level, const char *fmt, ...) {
    if (level > g_log_level) return;
    static const char *names[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
    fprintf(stderr, "[BP-%s] ", names[level]);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}
