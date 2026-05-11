# BP-SDK

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

```
.
├── include/         Public headers
├── src/             Library sources
│   └── backend/     Pluggable backends (POSIX TCPCL, Linux AF_BP)
├── tests/           Unit and integration tests
├── examples/        Minimal sample programs
├── Makefile         Cross-platform build (Linux / macOS / MinGW)
├── build.bat        Windows convenience wrapper
└── README.md
```

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
└───────────────────────┴──────────────────────┘
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
