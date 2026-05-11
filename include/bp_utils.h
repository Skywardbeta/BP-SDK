/* bp_utils.h - Core utilities */
#ifndef BP_UTILS_H
#define BP_UTILS_H

#include <stdint.h>
#include <stddef.h>

#define BP_DTN_EPOCH 946684800ULL

uint64_t bp_time_to_dtn(uint64_t unix_sec);
uint64_t bp_time_from_dtn(uint64_t dtn_sec);
uint64_t bp_time_now_dtn(void);

uint16_t bp_crc16(const uint8_t *data, size_t len);
uint32_t bp_crc32c(const uint8_t *data, size_t len);

void *bp_alloc(size_t size);
void *bp_realloc(void *ptr, size_t size);
void bp_free(void *ptr);
char *bp_strdup(const char *s);

typedef enum {
    BP_LOG_ERROR = 0,
    BP_LOG_WARN = 1,
    BP_LOG_INFO = 2,
    BP_LOG_DEBUG = 3,
    BP_LOG_TRACE = 4
} bp_log_level_t;

void bp_log_set_level(bp_log_level_t level);
void bp_log(bp_log_level_t level, const char *fmt, ...);

#define BP_LOG_ERROR(...) bp_log(BP_LOG_ERROR, __VA_ARGS__)
#define BP_LOG_WARN(...)  bp_log(BP_LOG_WARN, __VA_ARGS__)
#define BP_LOG_INFO(...)  bp_log(BP_LOG_INFO, __VA_ARGS__)
#define BP_LOG_DEBUG(...) bp_log(BP_LOG_DEBUG, __VA_ARGS__)
#define BP_LOG_TRACE(...) bp_log(BP_LOG_TRACE, __VA_ARGS__)

#endif
