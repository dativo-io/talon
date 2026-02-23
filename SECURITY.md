# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open a public issue for security vulnerabilities.

**Email:** security@dativo.io

**What to include:** Description, reproduction steps, impact assessment, affected version.

**Our commitment:**
- Acknowledge within **48 hours**
- Confirm and assess within **5 business days**
- Fix critical issues within **30 days**
- Credit reporters (unless anonymity preferred)

## Scope

**In scope:** Talon binary, evidence integrity (HMAC), secrets vault (AES-256-GCM), policy engine (OPA), LLM gateway proxy, MCP proxy, API authentication.

**Out of scope:** LLM provider security, upstream API vulnerabilities, issues in third-party dependencies (report upstream).

## Security Architecture

- **Secrets:** AES-256-GCM encrypted at rest, per-agent/tenant ACL, every access logged
- **Evidence:** HMAC-SHA256 signed at creation, verification via `talon audit verify`
- **API auth:** Timing-safe key comparison (`crypto/subtle.ConstantTimeCompare`)
- **PII:** Regex-based detection, configurable action (block/redact/warn/allow)
- **Injection:** 3-layer attachment scanning (extract, sandbox, detect)
