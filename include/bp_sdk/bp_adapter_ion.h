/*
 * bp_adapter_ion.h - ION-DTN adapter configuration.
 *
 * Selected through bp_secure_link_open("ion", config). The config string is
 * a ";"-separated list of key=value pairs:
 *
 *   rc=<path>     bpsecadmin command script to (re)generate. Default
 *                 "bpsdk.bpsecrc" in the working directory.
 *   exec=0|1      when 1, run `bpsecadmin <rc>` after writing the script and
 *                 invoke the inject command on send. Default 0 (offline:
 *                 generate rules only, do not touch a live daemon).
 *   inject=<cmd>  raw shell command run via system() to hand a payload to
 *                 ION's BPA on send (e.g. a bpsource/bpsendfile wrapper).
 *                 Only used when exec=1. UNSAFE: this is a deliberate shell
 *                 escape for operator/test use only; never pass untrusted
 *                 config. The rc path, by contrast, is spawned argv-style.
 *
 * The adapter only emits bpsecadmin-conformant rules and (optionally) feeds
 * them to ION; ION's BPA owns all BIB/BCB construction and crypto.
 */
#ifndef BP_ADAPTER_ION_H
#define BP_ADAPTER_ION_H

#include "bp_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const bp_adapter_t g_bp_ion_adapter;

#ifdef __cplusplus
}
#endif

#endif
