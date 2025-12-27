# 🦀 CDD Core (v0.3.0)
> **The High-Performance Security Engine for CDD Framework.**

This repository contains the core scanning engine written in Rust. It is designed to be fast, memory-safe, and easily extensible with new security tests.

## Features
* **Asynchronous Engine**: Powered by `tokio` and `reqwest` for concurrent network auditing.
* **Typed Error System**: Comprehensive error diagnostics using a custom `CddError` enum.
* **JSON Output**: Communicates with the Node.js wrapper via structured JSON.

## Included Security Checks
1. **X-Powered-By**: Identifies server technology leaks.
2. **HSTS**: Validates Strict Transport Security enforcement.
3. **CORS**: Analyzes Cross-Origin Resource Sharing policies.
4. **Secret Exposure**: Scans for public `.env` files.

## Building from source
Ensure you have the Rust toolchain installed.

```bash
# Build the production binary
cargo build --release
```

The binary will be located at ./target/release/cdd-core.

## Contributing
To add a new security test, modify src/scanner.rs and ensure it returns a Result<SecurityReport, CddError>.

License: MIT