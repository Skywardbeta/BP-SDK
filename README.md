# Bundle Protocol SDK (BP-SDK)

Clean, modern protoype API for BP implementation, available in both C and Rust.

## Overview

BP-SDK provides high-level interfaces to DTNs

- **C API**: Wrapper over ION-DTN, uD3tn, HDTN with automated memory management
- **Rust API**: Type-safe, async interface with zero-copy operations
- **Cross-Compatible**: Both APIs work with the same ION-DTN installation
- **Thread-Safe**: Safe concurrent operations in both languages

## Installation
ION-DTN as example

### Prerequisites

1. **ION-DTN Installation** (Required for both C and Rust)
   ```bash
   # Install ION-DTN
   cd /path/to/ION-DTN
   ./configure && make && sudo make install
   ```

2. **For C Development**
   ```bash
   cd BP-SDKS
   make
   sudo make install
   ```

3. **For Rust Development**
   ```bash
   # Install Rust (1.70+)
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Add to Cargo.toml
   [dependencies]
   bp-sdk = { path = "path/to/BP-SDKS/rust" }
   tokio = { version = "1.0", features = ["full"] }
   ```

## Quick Start

### C API

```c
#include "bp_sdk.h"

int main() {
    bp_init("ipn:1.1", NULL);
    
    bp_send("ipn:1.1", "ipn:2.1", "Hello", 5, 
            BP_PRIORITY_STANDARD, BP_CUSTODY_NONE, 3600, NULL);
    
    bp_endpoint_t *endpoint;
    bp_endpoint_create("ipn:2.1", &endpoint);
    bp_endpoint_register(endpoint);
    
    bp_bundle_t *bundle;
    if (bp_receive(endpoint, &bundle, 5000) == BP_SUCCESS) {
        printf("Received: %.*s\n", (int)bundle->payload_len, (char*)bundle->payload);
        bp_bundle_free(bundle);
    }
    
    bp_endpoint_unregister(endpoint);
    bp_endpoint_destroy(endpoint);
    bp_shutdown();
    return 0;
}
```

### Rust API

```rust
use bp_sdk::prelude::*;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let sdk = BpSdk::new(Eid::new("ipn:1.1")?, None)?;
    sdk.init().await?;
    

    let endpoint = sdk.create_endpoint(Eid::new("ipn:1.1")?).await?;
    

    let bundle = Bundle::new(
        Eid::new("ipn:1.1")?,
        Eid::new("ipn:2.1")?,
        "Hello from Rust!"
    );
    sdk.send(bundle).await?;
    

    match endpoint.receive(Some(Duration::from_secs(10))).await {
        Ok(bundle) => {
            println!("Received: {}", 
                String::from_utf8_lossy(&bundle.payload));
        }
        Err(BpError::Timeout) => println!("No bundles received"),
        Err(e) => eprintln!("Error: {}", e),
    }
    
    sdk.shutdown().await?;
    Ok(())
}
```

## Key Features

### C API Features
- **Memory Management**: Automatic cleanup of bundles and endpoints
- **Error Handling**: Clear error codes with descriptive messages
- **Thread Safety**: Safe for multi-threaded applications
- **ION Integration**: Direct compatibility with existing ION setups

### Rust API Features  
- **Type Safety**: Compile-time validation of EIDs and configurations
- **Async/Await**: Non-blocking operations with tokio
- **Zero-Copy**: Efficient payload handling with `Bytes`
- **Memory Safety**: No buffer overflows or memory leaks

## Examples

### Build and Run C Examples
```bash
# Build examples
make examples

./build/simple_send ipn:1.1 ipn:2.1 "Hello, DTN!"
./build/simple_receive ipn:2.1
```

### Run Rust Examples
```bash
cargo run --example simple_send
cargo run --example simple_receive
```

## Custom Convergence Layer Adapters

### C Implementation
```c
int my_send(const void *data, size_t len, const char *dest, void *ctx) {
    return send_via_my_protocol(data, len, dest);
}

int my_receive(void *data, size_t len, char *source, void *ctx) {
    return receive_via_my_protocol(data, len, source);
}

bp_cla_t *cla = malloc(sizeof(bp_cla_t));
cla->protocol_name = strdup("my_protocol");
cla->send_callback = my_send;
cla->receive_callback = my_receive;
bp_cla_register(cla);
```

### Rust Implementation
```rust
use bp_sdk::ClaManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ClaManager::new();
    let udp_cla = manager.create_udp_cla("0.0.0.0:4556").await?;
    
    udp_cla.set_receive_callback(Arc::new(|data, source_addr| {
        println!("Received {} bytes from {}", data.len(), source_addr);
    }));
    
    udp_cla.start().await?;
    Ok(())
}
```

## Testing

### C Tests
```bash

make test
./build/test_runner
```

### Rust Tests
```bash

cd rust/
cargo test


cargo test test_eid_validation
cargo test --test integration
```

## Error Handling

### C Error Handling
```c
int result = bp_send(...);
if (result != BP_SUCCESS) {
    printf("Error: %s\n", bp_strerror(result));
}
```

### Rust Error Handling
```rust
match sdk.send(bundle).await {
    Ok(()) => println!("Success"),
    Err(BpError::Timeout) => println!("Timeout"),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Architecture

```
┌─────────────────────────────────┐
│        Applications             │
├─────────────────────────────────┤
│    C API        │   Rust API    │
│  (bp_sdk.h)     │  (bp-sdk)     │
├─────────────────────────────────┤
│           ION-DTN Core          │
│      (NASA Flight Software)     │
└─────────────────────────────────┘
```

## Administrative Functions

### C Administrative API
```c
bp_admin_add_plan("ipn:2.0", 1000000);
time_t start = time(NULL);
bp_admin_add_contact("ipn:2.1", start, start + 3600, 1000000);

bp_admin_add_range("ipn:2.1", start, start + 3600, 5);
```

### Rust Administrative API
```rust
// Administrative functions available through ION integration
sdk.admin().add_plan("ipn:2.0", 1000000).await?;
sdk.admin().add_contact("ipn:2.1", start, duration, 1000000).await?;
```

## Compatibility

- **ION-DTN**: 4.0+ 
- **C Standard**: C99+
- **Rust**: 1.70+
- **Platforms**: Linux, macOS
- **Architecture**: x86_64, ARM64

## Contributing

1. Ensure ION-DTN is installed
2. For C: Run `make && make test`
3. For Rust: Run `cargo test`
4. Follow existing code patterns
5. Add tests for new functionality

## License

Extends NASA's ION-DTN. See ION-DTN license for terms. 
