#include "bp_adapter_ion.h"
#include "bp_ion_policy.h"
#include "bp_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

#define ION_RC_DEFAULT  "bpsdk.bpsecrc"
#define ION_SCRIPT_MAX  4096

/* argv-style spawn (no shell) so the rc path can never be a command injection. */
static int run_bpsecadmin(const char *rc_path) {
#ifdef _WIN32
    return _spawnlp(_P_WAIT, "bpsecadmin", "bpsecadmin", rc_path,
                    (const char *)NULL) == 0 ? 0 : -1;
#else
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execlp("bpsecadmin", "bpsecadmin", rc_path, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
#endif
}

typedef struct {
    char    *rc_path;
    char    *inject_cmd;
    int      exec;
    uint16_t next_rule_id;
} ion_state_t;

static char *config_get(const char *config, const char *key) {
    if (!config) return NULL;
    size_t klen = strlen(key);
    const char *p = config;
    while (*p) {
        const char *eq = strchr(p, '=');
        const char *end = strchr(p, ';');
        if (!end) end = p + strlen(p);
        if (eq && eq < end && (size_t)(eq - p) == klen &&
            strncmp(p, key, klen) == 0) {
            size_t vlen = (size_t)(end - (eq + 1));
            char *v = bp_alloc(vlen + 1);
            if (!v) return NULL;
            memcpy(v, eq + 1, vlen);
            v[vlen] = '\0';
            return v;
        }
        p = (*end == ';') ? end + 1 : end;
    }
    return NULL;
}

static int ion_open(const char *config, void **state_out) {
    ion_state_t *st = bp_alloc(sizeof(*st));
    if (!st) return BPSEC_ERR_INTERNAL;
    memset(st, 0, sizeof(*st));

    char *rc = config_get(config, "rc");
    st->rc_path = rc ? rc : bp_strdup(ION_RC_DEFAULT);
    if (!st->rc_path) { bp_free(st); return BPSEC_ERR_INTERNAL; }

    st->inject_cmd = config_get(config, "inject");
    char *exec = config_get(config, "exec");
    st->exec = (exec && exec[0] == '1');
    bp_free(exec);
    st->next_rule_id = 1;

    FILE *f = fopen(st->rc_path, "w");
    if (!f) {
        bp_free(st->rc_path);
        bp_free(st->inject_cmd);
        bp_free(st);
        return BPSEC_ERR_INTERNAL;
    }
    fclose(f);

    *state_out = st;
    return BPSEC_SUCCESS;
}

static void ion_close(void *state) {
    ion_state_t *st = state;
    if (!st) return;
    bp_free(st->rc_path);
    bp_free(st->inject_cmd);
    bp_free(st);
}

static int ion_register_security(void *state,
                                 const char *source_eid, const char *dest_eid,
                                 const bp_security_policy_t *policy) {
    ion_state_t *st = state;
    if (!st || !source_eid || !dest_eid || !policy) return BPSEC_ERR_INVALID_POLICY;
    if (policy->mode == BPSEC_MODE_NONE) return BPSEC_SUCCESS;

    char es_name[64];
    snprintf(es_name, sizeof(es_name), "bpsdk_es_%u", (unsigned)st->next_rule_id);

    char script[ION_SCRIPT_MAX];
    int n = bp_ion_policy_lower(policy, source_eid, dest_eid, es_name,
                                st->next_rule_id, script, sizeof(script));
    if (n < 0) return n;

    FILE *f = fopen(st->rc_path, "a");
    if (!f) return BPSEC_ERR_INTERNAL;
    size_t w = fwrite(script, 1, (size_t)n, f);
    fclose(f);
    if (w != (size_t)n) return BPSEC_ERR_INTERNAL;

    st->next_rule_id = (uint16_t)(st->next_rule_id + 2);

    if (st->exec && run_bpsecadmin(st->rc_path) != 0)
        return BPSEC_ERR_BPA_REJECTED;
    BP_LOG_INFO("ion: registered BPSec rule(s) for %s -> %s", source_eid, dest_eid);
    return BPSEC_SUCCESS;
}

static int ion_send(void *state,
                    const char *source_eid, const char *dest_eid,
                    const uint8_t *data, size_t len,
                    const bp_delivery_opts_t *opts) {
    ion_state_t *st = state;
    (void)opts;
    if (!st || !source_eid || !dest_eid || !data || len == 0)
        return BPSEC_ERR_INVALID_POLICY;

    /* inject is a deliberate raw shell escape: operator/test-only, never
     * feed it untrusted config (see bp_adapter_ion.h). */
    if (st->exec && st->inject_cmd) {
        if (system(st->inject_cmd) != 0) return BPSEC_ERR_BPA_REJECTED;
    }
    BP_LOG_DEBUG("ion: handed %zu bytes to BPA (%s -> %s)", len,
                 source_eid, dest_eid);
    return BPSEC_SUCCESS;
}

const bp_adapter_t g_bp_ion_adapter = {
    .name              = "ion",
    .open              = ion_open,
    .close             = ion_close,
    .set_source        = NULL,
    .validate_policy   = bp_ion_policy_validate,
    .register_security = ion_register_security,
    .send              = ion_send,
    .recv              = NULL,
};
