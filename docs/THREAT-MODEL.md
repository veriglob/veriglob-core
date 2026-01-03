# Threat Model – Veriglob Core

This document outlines high-level threats and mitigations for the Veriglob decentralised identity protocol.

---

## Assets to Protect

- User private keys
- Verifiable credentials
- DID documents
- Consent & authorization states
- Revocation data
- Protocol integrity

---

## Threat Model Framework

We loosely follow **STRIDE**:

- Spoofing
- Tampering
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege

---

## Identified Threats & Mitigations

### 1. Private Key Compromise

**Threat:** Attacker gains access to user private keys  
**Mitigation:**

- Keys generated client-side
- No server-side key custody
- Hardware wallet compatibility
- Clear separation of signing & verification

---

### 2. Credential Replay

**Threat:** Previously shared credentials reused maliciously  
**Mitigation:**

- Selective disclosure
- Nonce / challenge-based verification
- Expiry & revocation support

---

### 3. Unauthorized Data Retention

**Threat:** Fintech stores user credentials permanently  
**Mitigation:**

- Hash-only verification
- Explicit consent model
- Cryptographic unlinkability
- Legal + protocol-level discouragement

---

### 4. Chain-Specific Lock-in

**Threat:** DID tied to a single blockchain  
**Mitigation:**

- DID method abstraction
- Off-chain DID documents
- Chain used only as an anchor

---

### 5. Malicious Verifier

**Threat:** Verifier attempts correlation across sessions  
**Mitigation:**

- Pairwise DIDs
- Multiple DIDs per user
- No global identifiers

---

### 6. Denial of Service

**Threat:** Flooding verification or revocation endpoints  
**Mitigation:**

- Stateless verification
- Rate limiting at platform layer
- Caching of public material

---

## Assumptions

- End users control their devices
- Wallet software is trusted
- Integrators follow protocol guidance
- Cryptographic primitives remain secure

---

## Out of Scope

- Social engineering
- Compromised user devices
- Third-party SDK misuse

---

## Review Cycle

This threat model is reviewed:

- Before major releases
- When adding new DID methods
- When changing cryptographic primitives
