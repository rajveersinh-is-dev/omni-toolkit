# Security Policy

## 1. Local-First Security Architecture

OMNI is designed from the ground up as a **local-first, privacy-preserving engineering toolkit**.

- **No Remote Telemetry**: By default, no metrics, telemetry, or user data leave your workstation.
- **Local File Processing**: All files, buffers, binaries, and streams are processed in-process or via sandboxed local workers.
- **Explicit Network Scoping**: Any network-dependent operations (such as authorized port scanning, DNS resolution, and HTTP requests) require explicit user-specified targets. Diagnostic scanners default strictly to loopback (`127.0.0.1`) and private lab subnets.
- **Memory & Resource Caps**: File processing, decompression, and parsing pipelines enforce strict time, recursion, and allocation limits to prevent denial-of-service and zip-bomb attacks.
- **Secret Redaction**: Passwords, private keys, API secrets, and sensitive authentication headers are automatically masked in logs and debug traces.

## 2. Threat Model & Sandboxing

For a comprehensive breakdown of our threat vectors, trust boundaries, and isolation guarantees, refer to [docs/security/threat-model.md](docs/security/threat-model.md).

## 3. Reporting a Vulnerability

If you discover a security vulnerability within OMNI, please do **NOT** open a public issue.

Instead, please report security issues directly to the maintainer via private security advisory on GitHub or email:
- **Email**: `daveaddams91@gmail.com`
- **GPG Key ID**: Maintainer GPG verification available upon request.

Please include:
1. Detailed description of the vulnerability.
2. Steps to reproduce or proof-of-concept (PoC).
3. Potential impact and affected components.
4. Suggested mitigation or fix (if available).

We acknowledge all vulnerability reports within 48 hours and provide coordinated disclosure timelines.
