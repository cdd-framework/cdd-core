# 🦀 CDD Core (v0.3.0)
> **The High-Performance Security Engine for CDD Framework.**

This repository contains the core scanning engine written in **Rust**. It is designed for maximum throughput, memory safety, and precise security diagnostics.

---

## Key Technical Features

* **Asynchronous I/O**: Leveraging `tokio` for non-blocking network operations, allowing the engine to handle multiple probes concurrently without overhead.
* **Memory Safety**: Built with Rust to eliminate common vulnerabilities like buffer overflows or race conditions.
* **Strongly Typed Errors**: Custom `CddError` implementation ensuring that every network failure or malformed response is caught and reported.
* **JSON API**: Native serialization of security reports for seamless integration with Node.js or other wrappers.

## Security Audit Modules

The engine currently executes 4 specialized security tests:
1.  **X-Powered-By Detector**: Identifies server-side technology leaks.
2.  **HSTS Validator**: Checks for Strict-Transport-Security policy enforcement.
3.  **CORS Policy Analyzer**: Detects overly permissive Cross-Origin Resource Sharing configurations.
4.  **Secret Exposure Probe**: Scans for publicly accessible `.env` and configuration files.

## Local Development

To compile the production-ready binary:

```bash
# Optimized build for maximum performance
cargo build --release
```
The binary will be available at ./target/release/cdd-core.

## Project Structure
src/main.rs: Entry point and JSON orchestration.

src/scanner.rs: Core logic for all security tests.

src/error.rs: Custom error types and formatting.

src/models.rs: Data structures for security reports.

---

### License: MIT

### Author: Fabio Meyer<github.com/jemmyx>
