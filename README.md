# BP-SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A C SDK for **DTN Bundle Protocol v7 (RFC 9171)** with a declarative
**BPSec (RFC 9172 / 9173)** runtime control layer.

For engineers coming from IP networking: BPSec is the bundle-layer
analogue of IPsec. Where IPsec offers per-packet AH / ESP integrity
and confidentiality services driven by SPD/SAD, BPSec offers
per-block BIB / BCB services driven by a security policy engine.
What's missing in the BP world is the runtime control layer that
IPsec stacks expose to applications — a place to declare intent
("protect this flow with these algorithms and these keys") and let
the engine handle policy installation, crypto-context reuse, IV
management, and key expiry. BP-SDK fills that gap for BPSec.

Key management protocols (DTKA, BERMUDA, SAFE, BPSec-MLS, KMS
adapters) are out of scope and are integrated through the pluggable
`bp_key_provider_t` contract.

> Status: **Phase 1 prototype** — payload-only BIB-HMAC-SHA-256 /
> BCB-AES-GCM-256 against the in-tree POSIX TCPCL backend.

## Repository Layout

Public API headers (the consumer contract) live in `include/bp_sdk/`. Module
sources and their private headers live under `src/`, grouped by module. Every
module directory plus `include/bp_sdk` is on the include path, so
`#include "bp_x.h"` resolves regardless of where the caller lives.

```
.
├── include/bp_sdk/  Public API: bp_sdk, bp_session, bp_utils, bp_adapter,
│                    bp_adapter_ion, bp_adapter_ud3tn, bp_bpsec_keys, bp_key_provider
├── src/
│   ├── core/        SDK entry, allocator, CBOR (bp_sdk, bp_utils, bp_cbor)
│   ├── bundle/      Bundle build/parse, fragments, admin records, streaming
│   ├── transport/   TCPCL, storage, pluggable backends (POSIX, Linux AF_BP)
│   ├── session/     Session + BPSec policy/session implementation
│   ├── bpsec/       BPSec engine, keys, policy store, crypto + key providers
│   └── adapters/    Adapter Contract + bp_secure_link facade (bp_adapter)
│       ├── ion/     ION-DTN: bpsecadmin lowering + adapter
│       └── ud3tn/   uD3TN: AAP v1 client + adapter
├── tests/           Mirrors the source modules; shared test_harness.h
│   ├── integration/ Cross-cutting phase + concurrency suites
│   ├── bpsec/  session/
│   └── adapters/    facade, ion/, ud3tn/ (codec + adapter)
├── examples/        Minimal sample programs
├── Makefile         Cross-platform build (Linux / macOS / MinGW)
├── build.bat        Windows convenience wrapper
└── README.md
```

Only headers under `include/bp_sdk/` are part of the stable public surface;
headers inside `src/` are implementation detail and may change.

## Building

### Linux / macOS

```bash
make            # builds libbp_sdk.a, tests, examples
make test       # runs the test suite
```

### Windows (MinGW-w64)

```bat
build.bat
```

Either path produces `build/libbp_sdk.a` plus the test and example
binaries under `build/`.

## Quick Start — Plain Send / Receive

```c
#include "bp_sdk.h"
#include <stdio.h>

int main(void) {
    bp_init("ipn:1.0", NULL);

    bp_send("ipn:1.1", "ipn:2.1",
            "Hello, DTN", 10,
            BP_PRIORITY_STANDARD, BP_CUSTODY_NONE, 3600, NULL);

    bp_endpoint_t *ep;
    bp_endpoint_create("ipn:2.1", &ep);

    bp_bundle_t *bundle;
    if (bp_receive(ep, &bundle, 5000) == BP_SUCCESS) {
        printf("got %.*s\n", (int)bundle->payload_len,
               (char *)bundle->payload);
        bp_bundle_free(bundle);
    }

    bp_endpoint_destroy(ep);
    bp_shutdown();
    return 0;
}
```

## Quick Start — BPSec Session

```c
#include "bp_sdk.h"
#include "bp_session.h"
#include "bp_key_provider.h"
#include "bp_bpsec_keys.h"

int main(void) {
    bp_init("ipn:1.0", NULL);

    uint8_t key[32] = { /* 32 bytes from your KMS / file / DTKA */ };
    bpsec_keystore_add(bpsdk_default_keystore(),
                       "k1", BPSEC_KEY_TYPE_AES,
                       key, sizeof(key), NULL, 0);

    bp_session_t *s = bp_session_open("uplink");
    bp_session_set_source(s, "ipn:1.1");

    bp_security_policy_t policy = {
        .mode        = BPSEC_MODE_BCB_ONLY,
        .bcb_context = BPSEC_CTX_AES_GCM_256,
        .bcb_targets = BPSEC_TARGET_PAYLOAD,
        .bcb_scope   = BPSEC_SCOPE_BTSD_ONLY,
        .bcb_key_ref = "k1",
    };
    bp_session_set_security(s, &policy);

    bp_delivery_opts_t opts = {
        .dest_eid    = "ipn:2.1",
        .lifetime_ms = 60000,
    };
    bp_session_send(s, (uint8_t *)"hello", 5, &opts);

    bp_session_close(s);
    bp_shutdown();
}
```

## Quick Start — Native BPSec via a Secure Link

The `bp_secure_link` facade lets the **same code** drive a host stack's own
BPSec engine. You declare intent + key references once; the adapter either
lowers the policy onto the stack's native configuration path (ION) or declares
the intent and relies on the node's existing BPSec configuration (uD3TN), then
hands data to the Bundle Protocol Agent (BPA), which owns BIB/BCB construction
and crypto. Switch stacks by changing one string — `"ion"` or `"ud3tn"`.

```c
#include "bp_adapter.h"
#include "bp_session.h"

int main(void) {
    /* "ion"   -> lowers to bpsecadmin rules (.bpsecrc) for ION-DTN
       "ud3tn" -> registers an endpoint and ships data over AAP */
    bp_secure_link_t *link = bp_secure_link_open("ion", "rc=node.bpsecrc");

    bp_secure_link_set_source(link, "dtn://sat-1/telemetry");

    bp_security_policy_t policy = {
        .mode        = BPSEC_MODE_BIB_BCB,
        .bib_context = BPSEC_CTX_HMAC_SHA2_256, .bib_key_ref = "int-key",
        .bib_targets = BPSEC_TARGET_PAYLOAD,    .bib_scope = BPSEC_SCOPE_BTSD_ONLY,
        .bcb_context = BPSEC_CTX_AES_GCM_256,   .bcb_key_ref = "conf-key",
        .bcb_targets = BPSEC_TARGET_PAYLOAD,    .bcb_scope = BPSEC_SCOPE_BTSD_ONLY,
    };
    /* Fail-fast: an unapplicable policy is rejected here, before any send. */
    bp_secure_link_set_security(link, &policy);

    bp_secure_link_send(link, "dtn://ground/sink",
                        (const uint8_t *)"telemetry", 9, NULL);

    bp_secure_link_close(link);
}
```

The **Adapter Contract** (`bp_adapter.h`) is the invariant behind this: every
adapter sits above the host BPA and never performs crypto or pushes bundles to
a convergence layer itself.

- **ION adapter** (`bp_ion_policy.h`) translates the declared intent into
  `bpsecadmin`-conformant `event_set` + `policyrule` commands (BIB-HMAC-SHA2
  `sc_id 1`, BCB-AES-GCM   `sc_id 2`) and feeds them to ION's policy engine. BP-SDK's lowering currently
  emits only `key_name`, so it intentionally supports only ION's default
  variants (SHA-256, AES-256); other variants are rejected at `set_security`
  rather than silently downgraded.
- **uD3TN adapter** (`bp_aap.h`) speaks AAP v1 — connect, register the sub-EID
  (dtn demux / ipn service number per `ud3tn_aap.md`), send bundle. AAP v1
  carries no per-flow BPSec policy, so the adapter declares intent and hands
  data to uD3TN; **BPSec enforcement must already be configured in the node.**

## Architecture

```
┌──────────────────────────────────────────────┐
│             Application                      │
└──────────────┬───────────────────────────────┘
               │ bp_send / bp_session_send / bp_receive
┌──────────────▼───────────────────────────────┐
│  Public API (bp_sdk.h, bp_session.h)         │
├──────────────────────────────────────────────┤
│  Bundle Core    │  SecurityService           │
│  bp_bundle      │  bp_session                │
│  bp_cbor        │  bp_bpsec  bp_bpsec_keys   │
│  bp_fragment    │  bp_bpsec_policy           │
│  bp_admin       │                            │
├─────────────────┴─────┬──────────────────────┤
│  Backend abstraction  │  Plugin Container    │
│  bp_backend           │  bp_key_provider     │
│  └ POSIX TCPCL        │  bp_crypto_backend   │
│  └ AF_BP socket       │                      │
├───────────────────────┴──────────────────────┤
│  Adapter Contract (bp_adapter / secure_link)  │
│  └ ION   adapter  → bpsecadmin rules          │
│  └ uD3TN adapter  → AAP client                │
└───────────────────────────────────────────────┘
```

### SecurityService Highlights

- **Declarative policy** — `mode / context / targets / scope / key_ref`
  declared once per session.
- **Cached crypto contexts** — HMAC and AES-GCM key schedules are
  expanded on `bp_session_set_security()` and reused for every send.
- **Thread-safe sends** — every `bp_session_*` call serialises on the
  session mutex; concurrent sends across sessions run in parallel.
- **IV uniqueness** — 8-byte CSPRNG salt + 4-byte atomic counter, with
  optional `bp_iv_state_provider_t` for cross-restart persistence.
- **Key expiry / TTL** — bundle lifetime is rejected if it would
  outlive the configured key (`BPSEC_ERR_KEY_TTL_MISMATCH`).
- **Key plugin** — `bp_key_provider_t` lets BERMUDA / DTKA / file / KMS
  plug in without forking the SDK. Keystore-backed and text-file
  reference providers are shipped in-tree.
- **Crypto backend plugin** — `bp_crypto_backend_t` lets you swap the
  in-tree HMAC / AES-GCM for OpenSSL, libsodium, or hardware acceleration.

## Pluggable Backends

The Bundle layer is reached through `bp_backend_t`:

```c
extern bp_backend_t g_posix_backend;     /* TCPCL over POSIX sockets */
extern bp_backend_t g_bpsocket_backend;  /* Linux AF_BP socket (kernel module) */
```

Selecting a backend is a string match in `bp_init()`'s config argument
(default: POSIX). Adding a new backend means filling in a `bp_backend_t`
and exposing it as a global.

## Compatibility

- **C standard:** C11
- **Platforms:** Linux, macOS, Windows (MinGW-w64)
- **Architectures:** x86_64, ARM64
- **BPv7:** RFC 9171
- **BPSec:** RFC 9172 + RFC 9173 default contexts
