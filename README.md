# 🛡️ CDD Framework (v0.3.0)
> **Cyberattack-Driven Development**: A high-performance vulnerability scanner powered by Rust.

[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Node.js](https://img.shields.io/badge/Language-Node.js-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub Followers](https://img.shields.io/github/followers/jemmyx?style=social)](https://github.com/jemmyx)

CDD is a modern security scanning engine designed for speed and reliability. It combines a **memory-safe Rust core** for intensive network operations with a **Node.js CLI** for a seamless developer experience.

---

## Quick Start

You don't need to have Rust installed locally to use the framework. The installer automatically fetches the pre-compiled binary for your specific architecture (Windows, macOS, or Linux).

```bash
# Clone the repository
git clone [https://github.com/cdd-framework/cdd-node.git](https://github.com/cdd-framework/cdd-node.git)
cd cdd-node

# Install dependencies and download the Rust kernel
npm install -g .
```
## Usage
Run a security audit on any target URL directly from your terminal:

Bash

cdd [https://yourwebsite.com](https://yourwebsite.com)

Included Security Tests (v0.3.0):
Gateway: X-Powered-By : Detects technology stack exposure in HTTP headers.

Protocol: HSTS Check : Verifies if Strict Transport Security is properly enforced.

Network: Permissive CORS Policy : Analyzes Cross-Origin Resource Sharing policies for potential data leaks.

Business: Exposed Secrets : Scans for publicly accessible .env files containing sensitive credentials.


## Architecture
The framework is architected for maximum performance and modularity:

cdd-core (Rust): Handles raw HTTP requests and concurrent scanning using tokio and reqwest. It features a strictly typed error system (CddError) to ensure the engine never crashes silently.

cdd-node (Node.js): Orchestrates binary execution and formats raw JSON output into a professional "Hacker Dark Mode" terminal table.

## Error Handling
CDD implements a robust diagnostic system. If a scan fails, the engine provides clear, structured feedback:

InvalidUrl: The provided target URL is malformed or unreachable.

NetworkError: Connection failure, DNS issues, or request timeout.

InternalError: Captured internal engine configuration issues.

## Contributing
This is an open-source project. Feel free to open issues or submit pull requests to add new security tests to the Rust core!

Author: Fabio Meyer<github.com/jemmyx>

Version: 0.3.0

License: MIT