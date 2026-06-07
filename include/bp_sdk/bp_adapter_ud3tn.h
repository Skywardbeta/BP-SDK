/*
 * bp_adapter_ud3tn.h - uD3TN adapter configuration.
 *
 * Selected through bp_secure_link_open("ud3tn", config). The config string is
 * a ";"-separated list of key=value pairs:
 *
 *   host=<host>   AAP TCP listener host. Default "127.0.0.1".
 *   port=<port>   AAP TCP listener port. Default 4242.
 *   agent=<id>    AAP sub-EID to register. If omitted, it is derived from the
 *                 link source EID per ud3tn_aap.md (dtn demux part, or the ipn
 *                 service number string), not the full EID.
 *
 * uD3TN's AAP v1 can register an endpoint and send/receive bundles, but it does
 * not carry per-flow BPSec policy. So this adapter declares the SDK's intent and
 * hands data to uD3TN; BPSec enforcement must already be configured in the uD3TN
 * node. The adapter never translates policy into AAP security configuration.
 */
#ifndef BP_ADAPTER_UD3TN_H
#define BP_ADAPTER_UD3TN_H

#include "bp_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const bp_adapter_t g_bp_ud3tn_adapter;

#ifdef __cplusplus
}
#endif

#endif
