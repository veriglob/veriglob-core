# Revocation Specification

## Overview

Veriglob implements an issuer-managed revocation registry that allows credential issuers to revoke credentials after issuance. The registry is a simple, centralized data store that maps credential IDs to their revocation status.

## Design Principles

- **Issuer Control**: Only the issuer can revoke credentials they issued
- **Immediate Effect**: Revocation takes effect immediately upon recording
- **Audit Trail**: Revocation events include timestamps and reasons
- **Persistence**: Registry state is persisted to prevent data loss

## Registry Entry Structure

Each credential is tracked with the following fields:

```go
type Entry struct {
    CredentialID string    `json:"credentialId"`
    IssuerDID    string    `json:"issuerDid"`
    SubjectDID   string    `json:"subjectDid"`
    Status       Status    `json:"status"`
    IssuedAt     time.Time `json:"issuedAt"`
    RevokedAt    time.Time `json:"revokedAt,omitempty"`
    Reason       string    `json:"reason,omitempty"`
}
```

| Field | Description |
|-------|-------------|
| `credentialId` | Unique identifier (URN UUID format) |
| `issuerDid` | DID of the credential issuer |
| `subjectDid` | DID of the credential subject |
| `status` | Current status: `active` or `revoked` |
| `issuedAt` | Timestamp when credential was issued |
| `revokedAt` | Timestamp when credential was revoked |
| `reason` | Human-readable reason for revocation |

## Credential ID Format

Credential IDs follow the URN UUID format:

```
urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Example:
```
urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5
```

IDs are generated using cryptographically secure random bytes:

```go
import "veriglob/internal/revocation"

credID, err := revocation.GenerateCredentialID()
// urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

## Status Values

| Status | Description |
|--------|-------------|
| `active` | Credential is valid and not revoked |
| `revoked` | Credential has been revoked by issuer |

## Registry Operations

### Creating a Registry

```go
import "veriglob/internal/revocation"

// In-memory registry (for testing)
registry := revocation.NewRegistry()

// Persistent registry (for production)
registry, err := revocation.NewRegistryWithFile("./revocations.json")
```

### Registering a Credential

When a credential is issued, it should be registered in the revocation registry:

```go
err := registry.Register(credentialID, issuerDID, subjectDID)
```

### Checking Revocation Status

```go
// Get full entry
entry, err := registry.CheckStatus(credentialID)
if err == revocation.ErrCredentialNotFound {
    // Credential not in registry
}

// Quick boolean check
isRevoked, err := registry.IsRevoked(credentialID)
```

### Revoking a Credential

```go
err := registry.Revoke(credentialID, "Employee terminated")
```

Possible errors:
- `ErrCredentialNotFound`: Credential ID not in registry
- `ErrAlreadyRevoked`: Credential was already revoked

### Listing Credentials

```go
// List all credentials by issuer
entries := registry.ListByIssuer(issuerDID)

// List all credentials for a subject
entries := registry.ListBySubject(subjectDID)
```

## Credential Integration

Credentials include a status reference in the `credentialStatus` field:

```json
{
  "vc": {
    "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
    "type": ["VerifiableCredential", "IdentityCredential"],
    "credentialSubject": { ... },
    "credentialStatus": {
      "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
      "type": "RevocationRegistry2024"
    }
  }
}
```

## Verification Flow

When verifying a credential:

1. Parse and verify the PASETO token signature
2. Check the token expiration
3. Extract the credential ID from `jti` claim or `vc.credentialStatus.id`
4. Query the revocation registry for status
5. Reject if status is `revoked`

```go
// After verifying token signature
claims, err := vc.VerifyVC(token, issuerPublicKey)
if err != nil {
    return err
}

// Check revocation status
isRevoked, err := registry.IsRevoked(claims.ID)
if err != nil && err != revocation.ErrCredentialNotFound {
    return err
}
if isRevoked {
    return errors.New("credential has been revoked")
}
```

## Persistence Format

The registry persists as a JSON file:

```json
{
  "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5": {
    "credentialId": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
    "issuerDid": "did:key:z6MkIssuer...",
    "subjectDid": "did:key:z6MkSubject...",
    "status": "active",
    "issuedAt": "2024-01-15T10:30:00Z"
  },
  "urn:uuid:5678abcd-1234-5678-9abc-def012345678": {
    "credentialId": "urn:uuid:5678abcd-1234-5678-9abc-def012345678",
    "issuerDid": "did:key:z6MkIssuer...",
    "subjectDid": "did:key:z6MkOther...",
    "status": "revoked",
    "issuedAt": "2024-01-10T08:00:00Z",
    "revokedAt": "2024-01-14T16:45:00Z",
    "reason": "Credential issued in error"
  }
}
```

## CLI Usage

### Issue and Register

```bash
# Issue a credential (automatically registered)
issuer issue -type identity -registry ./registry.json \
  -subject did:key:z6MkSubject... \
  -given-name John -family-name Doe -dob 1990-01-15
```

### Check Status

```bash
# Verify includes revocation check
verifier verify -credential token.txt -registry ./registry.json
```

### Revoke a Credential

```bash
issuer revoke -registry ./registry.json \
  -id urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5 \
  -reason "Employment terminated"
```

### List Registry

```bash
issuer list -registry ./registry.json
```

## Security Considerations

### Registry Access Control

- Registry file should be protected with appropriate file permissions
- Only issuer processes should have write access
- Verifiers only need read access

### Revocation Timing

- Revocation is immediate but relies on verifiers checking the registry
- Verifiers should always check revocation status for sensitive operations
- Consider caching strategies for high-volume verification

### Privacy

- Registry reveals which credentials exist (by ID)
- Registry reveals issuer-subject relationships
- Consider privacy-preserving alternatives for sensitive use cases

## Common Revocation Reasons

| Reason | When to Use |
|--------|-------------|
| `Employee terminated` | Employment ended |
| `Certificate expired` | Underlying certification expired |
| `Information changed` | Subject's information changed (reissue required) |
| `Issued in error` | Credential was issued incorrectly |
| `Fraud detected` | Credential was obtained fraudulently |
| `Key compromise` | Subject's key was compromised |
| `Issuer request` | Issuer revoked for administrative reasons |
| `Subject request` | Subject requested revocation |

## Future Considerations

- **Distributed Registry**: Multi-node registry with consensus
- **Status List 2021**: W3C Bitstring-based revocation
- **Accumulator-based**: Cryptographic accumulators for privacy
- **Suspension**: Temporary revocation with reinstatement
- **Delegation**: Allow authorized parties to revoke on issuer's behalf

