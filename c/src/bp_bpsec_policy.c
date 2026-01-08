/*
 * bp_bpsec_policy.c - BPSec Security Policy Implementation
 * 
 * Thread-safe policy rule management with wildcard EID matching.
 * Rules are stored sorted by priority (higher first) for deterministic matching.
 */
#include "bp_bpsec_policy.h"
#include "bp_utils.h"
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define MUTEX_T CRITICAL_SECTION
#define MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#else
#include <pthread.h>
#define MUTEX_T pthread_mutex_t
#define MUTEX_INIT(m) pthread_mutex_init(&(m), NULL)
#define MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#endif

struct bpsec_policy_ctx {
    bpsec_policy_rule_t *rules;
    size_t rule_count;
    size_t rule_capacity;
    bpsec_policy_rule_t default_rule;
    int has_default;
    bpsec_policy_stats_t stats;
    MUTEX_T mutex;
};

bpsec_policy_ctx_t *bpsec_policy_create(void) {
    bpsec_policy_ctx_t *ctx = bp_alloc(sizeof(bpsec_policy_ctx_t));
    if (!ctx) return NULL;
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->rule_capacity = 16;
    ctx->rules = bp_alloc(sizeof(bpsec_policy_rule_t) * ctx->rule_capacity);
    if (!ctx->rules) {
        bp_free(ctx);
        return NULL;
    }
    
    MUTEX_INIT(ctx->mutex);
    return ctx;
}

void bpsec_policy_destroy(bpsec_policy_ctx_t *ctx) {
    if (!ctx) return;
    
    MUTEX_LOCK(ctx->mutex);
    bp_free(ctx->rules);
    ctx->rules = NULL;
    ctx->rule_count = 0;
    MUTEX_UNLOCK(ctx->mutex);
    
    MUTEX_DESTROY(ctx->mutex);
    bp_free(ctx);
}

static int pattern_match(const char *pattern, const char *str) {
    if (!pattern || !str) return 0;
    
    if (strcmp(pattern, "*") == 0) return 1;
    
    size_t plen = strlen(pattern);
    if (plen > 0 && pattern[plen - 1] == '*') {
        return strncmp(pattern, str, plen - 1) == 0;
    }
    
    return strcmp(pattern, str) == 0;
}

int bpsec_policy_add_rule(bpsec_policy_ctx_t *ctx,
                          const bpsec_policy_rule_t *rule) {
    if (!ctx || !rule) return -1;
    if (rule->dest_pattern[0] == '\0') return -1;
    
    MUTEX_LOCK(ctx->mutex);
    
    for (size_t i = 0; i < ctx->rule_count; i++) {
        if (strcmp(ctx->rules[i].dest_pattern, rule->dest_pattern) == 0) {
            ctx->rules[i] = *rule;
            MUTEX_UNLOCK(ctx->mutex);
            return 0;
        }
    }
    
    if (ctx->rule_count >= ctx->rule_capacity) {
        size_t new_cap = ctx->rule_capacity * 2;
        bpsec_policy_rule_t *new_rules = bp_realloc(ctx->rules,
                                                     sizeof(bpsec_policy_rule_t) * new_cap);
        if (!new_rules) {
            MUTEX_UNLOCK(ctx->mutex);
            return -1;
        }
        ctx->rules = new_rules;
        ctx->rule_capacity = new_cap;
    }
    
    size_t insert_pos = ctx->rule_count;
    for (size_t i = 0; i < ctx->rule_count; i++) {
        if (rule->priority > ctx->rules[i].priority) {
            insert_pos = i;
            break;
        }
    }
    
    if (insert_pos < ctx->rule_count) {
        memmove(&ctx->rules[insert_pos + 1], &ctx->rules[insert_pos],
                sizeof(bpsec_policy_rule_t) * (ctx->rule_count - insert_pos));
    }
    
    ctx->rules[insert_pos] = *rule;
    ctx->rule_count++;
    
    MUTEX_UNLOCK(ctx->mutex);
    return 0;
}

int bpsec_policy_remove_rule(bpsec_policy_ctx_t *ctx,
                             const char *dest_pattern) {
    if (!ctx || !dest_pattern) return -1;
    
    MUTEX_LOCK(ctx->mutex);
    
    for (size_t i = 0; i < ctx->rule_count; i++) {
        if (strcmp(ctx->rules[i].dest_pattern, dest_pattern) == 0) {
            if (i < ctx->rule_count - 1) {
                memmove(&ctx->rules[i], &ctx->rules[i + 1],
                        sizeof(bpsec_policy_rule_t) * (ctx->rule_count - i - 1));
            }
            ctx->rule_count--;
            MUTEX_UNLOCK(ctx->mutex);
            return 0;
        }
    }
    
    MUTEX_UNLOCK(ctx->mutex);
    return -1;
}

int bpsec_policy_lookup(bpsec_policy_ctx_t *ctx, const char *dest_eid,
                        bpsec_policy_rule_t *out) {
    if (!ctx || !dest_eid || !out) return -1;
    
    MUTEX_LOCK(ctx->mutex);
    
    for (size_t i = 0; i < ctx->rule_count; i++) {
        if (pattern_match(ctx->rules[i].dest_pattern, dest_eid)) {
            *out = ctx->rules[i];
            MUTEX_UNLOCK(ctx->mutex);
            return 0;
        }
    }
    
    if (ctx->has_default) {
        *out = ctx->default_rule;
        MUTEX_UNLOCK(ctx->mutex);
        return 0;
    }
    
    MUTEX_UNLOCK(ctx->mutex);
    return -1;
}

int bpsec_policy_set_default(bpsec_policy_ctx_t *ctx,
                             const bpsec_policy_rule_t *rule) {
    if (!ctx) return -1;
    
    MUTEX_LOCK(ctx->mutex);
    
    if (rule) {
        ctx->default_rule = *rule;
        ctx->has_default = 1;
    } else {
        memset(&ctx->default_rule, 0, sizeof(ctx->default_rule));
        ctx->has_default = 0;
    }
    
    MUTEX_UNLOCK(ctx->mutex);
    return 0;
}

int bpsec_policy_get_stats(bpsec_policy_ctx_t *ctx,
                           bpsec_policy_stats_t *out) {
    if (!ctx || !out) return -1;
    
    MUTEX_LOCK(ctx->mutex);
    *out = ctx->stats;
    MUTEX_UNLOCK(ctx->mutex);
    
    return 0;
}

void bpsec_policy_reset_stats(bpsec_policy_ctx_t *ctx) {
    if (!ctx) return;
    
    MUTEX_LOCK(ctx->mutex);
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    MUTEX_UNLOCK(ctx->mutex);
}

void bpsec_policy_inc_stat(bpsec_policy_ctx_t *ctx, int stat_type) {
    if (!ctx) return;
    
    MUTEX_LOCK(ctx->mutex);
    
    switch (stat_type) {
        case BPSEC_STAT_SIGNED:      ctx->stats.bundles_signed++; break;
        case BPSEC_STAT_ENCRYPTED:   ctx->stats.bundles_encrypted++; break;
        case BPSEC_STAT_VERIFIED:    ctx->stats.bundles_verified++; break;
        case BPSEC_STAT_DECRYPTED:   ctx->stats.bundles_decrypted++; break;
        case BPSEC_STAT_VERIFY_FAIL: ctx->stats.verify_failures++; break;
        case BPSEC_STAT_DECRYPT_FAIL: ctx->stats.decrypt_failures++; break;
        case BPSEC_STAT_DROP:        ctx->stats.policy_drops++; break;
    }
    
    MUTEX_UNLOCK(ctx->mutex);
}

size_t bpsec_policy_rule_count(bpsec_policy_ctx_t *ctx) {
    if (!ctx) return 0;
    
    MUTEX_LOCK(ctx->mutex);
    size_t count = ctx->rule_count;
    MUTEX_UNLOCK(ctx->mutex);
    
    return count;
}

