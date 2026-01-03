# Veriglob Core

**veriglob-core** is the open-source **reference implementation** of the **Veriglob decentralized identity protocol**.  
It provides the foundational tools for building **privacy-preserving, user-controlled digital identities** that are **chain-agnostic, interoperable, and secure**.

---

## 🚀 Features

- **Decentralized Identifiers (DIDs):** Support for `did:key` and future DID methods
- **Verifiable Credentials (VCs):** Issue, hold, and verify credentials
- **Secure Encodings:** Supports JWT and pluggable encodings like PASETO
- **Revocation Support:** Manage credential lifecycle without central storage
- **Protocol-First:** Reference implementation for SDKs, wallets, and integrations

---

## 🎯 Goals

1. Enable **developers** to integrate decentralized identity easily
2. Give **fintechs and enterprises** privacy-preserving user identity tools
3. Offer **governments and regulators** auditable, standards-aligned identity infrastructure
4. Build **trust through transparency** — the protocol is fully open-source

---

## 🏗 Architecture Overview

+-----------------+ +----------------+ +----------------+
| | | | | |
| User Wallet | <---> | Veriglob-Core | <---> | Issuer / |
| (private keys) | | Protocol SDK | | Verifier App |
| | | | | |
+-----------------+ +----------------+ +----------------+

- **Users** own their keys and credentials.
- **Veriglob-Core** handles DID creation, credential issuance, and verification.
- **Issuers / Verifiers** interact with the protocol without storing user secrets.

---

## 💻 Getting Started

### Prerequisites

- [Go 1.25.5+](https://golang.org/dl/)
- Git

### Clone the Repository

```bash
git clone https://github.com/veriglob/veriglob-core.git
cd veriglob-core
go mod tidy

```

### Run Example Verifiable Credential Issuance

    go run cmd/issuer/main.go

## Licensing

Apache 2.0 – free for commercial and non-commercial use, contributor-friendly.
See LICENSE
for full details.

## Contributing

We welcome contributions! Please read our:

CODE_OF_CONDUCT.md

CONTRIBUTING.md

SECURITY.md
before opening issues or PRs

## Security

This project handles sensitive identity material.
Follow best practices:

Never commit private keys

Use .gitignore

Report vulnerabilities through SECURITY.md

## Why Veriglob?

Veriglob is designed for a world where identity is user-owned, privacy-preserving, and interoperable.
With open-source transparency, strong cryptography, and a developer-first approach, Veriglob lays the foundation for the next generation of digital identity.
