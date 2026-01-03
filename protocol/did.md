# DID Method Specification

## Overview

Veriglob uses the `did:key` method for decentralized identifiers. This method is deterministic, requiring no blockchain or registry, as the DID is derived directly from the public key.

## DID Format

The format follows the `did:key` specification:

```
did:key:<multibase-encoded-public-key>
```

### Supported Key Types

Veriglob currently supports **Ed25519** keys.

- **Multicodec prefix**: `0xed` (Ed25519 public key)
- **Multibase encoding**: `base58btc` (prefix `z`)

Example:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

## DID Document

The DID Document is generated dynamically from the DID.

### Structure

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [
    {
      "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    }
  ],
  "authentication": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ],
  "assertionMethod": [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  ]
}
```

## Resolution

Resolution is purely algorithmic:

1. Decode the multibase string to get the public key bytes.
2. Verify the multicodec prefix (Ed25519).
3. Construct the DID Document using the public key.

No network requests are required.
