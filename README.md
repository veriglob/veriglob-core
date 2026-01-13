# Veriglob Core

**veriglob-core** is the open-source **reference implementation** of the **Veriglob decentralized identity protocol**.
It provides the foundational tools for building **privacy-preserving, user-controlled digital identities** that are **chain-agnostic, interoperable, and secure**.

---

> ⚠️ **Work in Progress:** veriglob-core is currently under active development.
>
> Some APIs may change, features are being added, and documentation may be incomplete.
>
> Contributions, feedback, and testing are highly welcome!

---

## 🚀 Features

- **Decentralized Identifiers (DIDs):** Support for `did:key` and future DID methods
- **Verifiable Credentials (VCs):** Issue, hold, and verify credentials
- **Secure Encodings:** Supports JWT and pluggable encodings like PASETO
- **Revocation Support:** Manage credential lifecycle without central storage
- **Zero-Knowledge Proofs:** Privacy-preserving credential presentations
  - **BBS+ Signatures:** Selective disclosure - reveal only chosen credential fields
  - **zk-SNARKs:** Predicate proofs - prove properties (e.g., age > 18) without revealing actual values
- **Protocol-First:** Reference implementation for SDKs, wallets, and integrations

---

## 🔐 Zero-Knowledge Protocol Layer

Veriglob includes a dual ZK layer for **privacy-preserving credential presentations**:

### BBS+ Signatures (Selective Disclosure)

Reveal only the fields you choose while proving the credential is valid:

```go
// Issue a ZK-enabled credential
bbsKeys, _ := veriglob.GenerateBBSKeyPair(15)
zkCred, _ := veriglob.IssueZKCredential(
    issuerDID, holderDID, issuerPrivKey, bbsKeys, subject, credID,
)

// Create presentation revealing only name fields
request := zkp.SelectiveDisclosureRequest{
    RevealedFields: []string{"givenName", "familyName"},
}
presentation, _ := veriglob.CreateZKPresentation(
    zkCred, holderDID, bbsKeys, request, audience, nonce,
)

// Verifier sees: {"givenName": "Alice", "familyName": "Johnson"}
// All other fields remain hidden
```

### zk-SNARKs (Predicate Proofs)

Prove statements about credential fields without revealing the actual values:

```go
// Prove age > 21 without revealing birthdate
request := zkp.SelectiveDisclosureRequest{
    RevealedFields: []string{"givenName"},
    Predicates: []zkp.PredicateProof{{
        FieldName: "birthYear",
        Predicate: zkp.PredicateGreaterThan,
        Threshold: 21,
    }},
}
```

### Backward Compatibility

ZK credentials maintain full backward compatibility with existing PASETO-based verifiers:

```go
// Traditional verification still works
valid, _ := veriglob.VerifyVC(zkCred.OriginalToken, issuerPublicKey)
```

---

## 🎯 Goals

1. Enable **developers** to integrate decentralized identity easily
2. Give **fintechs and enterprises** privacy-preserving user identity tools
3. Offer **governments and regulators** auditable, standards-aligned identity infrastructure
4. Build **trust through transparency** — the protocol is fully open-source

---

## 🏗 Architecture Overview

```
+-----------------+     +----------------+     +----------------+
|                 |     |                |     |                |
|   User Wallet   | <-> | Veriglob-Core  | <-> |   Issuer /     |
|  (private keys) |     |  Protocol SDK  |     |  Verifier App  |
|                 |     |                |     |                |
+-----------------+     +----------------+     +----------------+
```

- **Users** own their keys and credentials.
- **Veriglob-Core** handles DID creation, credential issuance, and verification.
- **Issuers / Verifiers** interact with the protocol without storing user secrets.

### ZKP Package Structure

```
internal/zkp/
├── bbs/                    # BBS+ selective disclosure
│   ├── keys.go            # BLS12-381 key generation
│   ├── signer.go          # Sign/verify operations
│   └── proof.go           # Selective disclosure proofs
├── snark/                  # zk-SNARK predicates
│   ├── circuits/
│   │   └── range.go       # Range, age, equality circuits
│   └── prover.go          # Groth16 prover/verifier
├── credential.go          # ZK credential issuance
├── presentation.go        # ZK presentation creation
├── types.go               # Interfaces/types
└── errors.go              # Error definitions
```

---

## 💻 Getting Started

### Prerequisites

- [Go 1.21+](https://golang.org/dl/)
- Git

### Clone the Repository

```bash
git clone https://github.com/veriglob/veriglob-core.git
cd veriglob-core
go mod tidy
```

### Run Example Verifiable Credential Issuance

```bash
go run cmd/issuer/main.go
```

### Run Tests

```bash
# Run all tests
go test ./...

# Run ZKP tests specifically
go test ./internal/zkp/... -v
```

---

## 📦 Dependencies

Core cryptographic dependencies:

- **gnark** (v0.10.0) - zk-SNARK circuit compilation and Groth16 proving
- **gnark-crypto** (v0.12.1) - BLS12-381 curve operations for BBS+ signatures
- **PASETO** - Secure token encoding for backward-compatible credentials

---

## Licensing

Apache 2.0 – free for commercial and non-commercial use, contributor-friendly.
See [LICENSE](LICENSE) for full details.

## Contributing

We welcome contributions! Please read our:

- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)

before opening issues or PRs.

## Security

This project handles sensitive identity material.
Follow best practices:

- Never commit private keys
- Use `.gitignore`
- Report vulnerabilities through [SECURITY.md](SECURITY.md)

## Why Veriglob?

Veriglob is designed for a world where identity is user-owned, privacy-preserving, and interoperable.
With open-source transparency, strong cryptography, and a developer-first approach, Veriglob lays the foundation for the next generation of digital identity.
