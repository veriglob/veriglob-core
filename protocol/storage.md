# Wallet Storage Specification

## Overview

The Veriglob wallet stores user keys and credentials locally. To ensure security, sensitive data is encrypted at rest using a passphrase-derived key.

## File Format

The wallet is stored as a JSON file containing an encrypted payload and metadata for key derivation.

### Schema

```json
{
  "version": "1.0",
  "kdf": {
    "algorithm": "argon2id",
    "params": {
      "time": 1,
      "memory": 64,
      "threads": 4
    },
    "salt": "<base64-encoded-salt>"
  },
  "encryption": {
    "algorithm": "chacha20poly1305",
    "nonce": "<base64-encoded-nonce>",
    "ciphertext": "<base64-encoded-encrypted-data>",
    "authTag": "<base64-encoded-tag>"
  }
}
```

_Note: Exact KDF and encryption parameters may vary by implementation version._

## Decrypted Payload

Once decrypted, the payload is a JSON object containing:

```json
{
  "did": "did:key:z6Mk...",
  "keys": {
    "privateKey": "<base64-encoded-private-key>",
    "publicKey": "<base64-encoded-public-key>"
  },
  "credentials": {
    "urn:uuid:credential-id-1": {
      "id": "urn:uuid:credential-id-1",
      "type": "IdentityCredential",
      "issuerDid": "did:key:z6MkIssuer...",
      "token": "v4.public.token...",
      "issuedAt": "2024-01-01T00:00:00Z",
      "expiresAt": "2025-01-01T00:00:00Z"
    }
  }
}
```

## Security Model

1.  **Encryption at Rest**: Private keys and credentials are never stored in plaintext.
2.  **Passphrase Protection**: Access requires a user-provided passphrase.
3.  **Local Only**: The wallet file is never transmitted to servers.

## Operations

- **Create**: Generates a new keypair and initializes an empty credential map.
- **Open**: Derives the decryption key from the passphrase and decrypts the payload.
- **Export**: Allows exporting the wallet data (requires passphrase).
