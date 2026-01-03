# Credentials Specification

## Overview

Veriglob implements Verifiable Credentials (VCs) based on the [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/). Credentials are encoded as PASETO v4 public tokens for secure, stateless verification.

## Token Format

### PASETO v4 Public

Credentials use [PASETO](https://paseto.io/) (Platform-Agnostic Security Tokens) v4 public mode:

- **Algorithm**: Ed25519 signatures
- **Format**: `v4.public.<payload>.<signature>`
- **Advantages over JWT**:
  - No algorithm confusion attacks
  - Mandatory cryptographic agility
  - Simpler, more secure defaults

## Credential Structure

### Token Claims

| Claim | Description |
|-------|-------------|
| `iss` | Issuer DID |
| `sub` | Subject DID |
| `jti` | Credential ID (for revocation) |
| `iat` | Issued at timestamp |
| `exp` | Expiration timestamp (default: 1 year) |
| `vc` | Verifiable Credential payload |

### Verifiable Credential Payload

```json
{
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": ["VerifiableCredential", "IdentityCredential"],
  "credentialSubject": {
    "id": "did:key:z6MkSubject...",
    "givenName": "John",
    "familyName": "Doe",
    "dateOfBirth": "1990-01-15"
  },
  "credentialStatus": {
    "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
    "type": "RevocationRegistry2024"
  }
}
```

## Credential Types

### IdentityCredential

KYC/identity verification credentials.

```go
type IdentitySubject struct {
    ID            string `json:"id"`
    GivenName     string `json:"givenName"`
    FamilyName    string `json:"familyName"`
    DateOfBirth   string `json:"dateOfBirth"`
    Nationality   string `json:"nationality,omitempty"`
    DocumentType  string `json:"documentType,omitempty"`
    DocumentID    string `json:"documentId,omitempty"`
    PlaceOfBirth  string `json:"placeOfBirth,omitempty"`
    Gender        string `json:"gender,omitempty"`
    Address       string `json:"address,omitempty"`
    VerifiedAt    string `json:"verifiedAt,omitempty"`
    VerifiedLevel string `json:"verifiedLevel,omitempty"`
}
```

### EducationCredential

Educational and certification credentials.

```go
type EducationSubject struct {
    ID              string `json:"id"`
    InstitutionName string `json:"institutionName"`
    InstitutionDID  string `json:"institutionDid,omitempty"`
    Degree          string `json:"degree,omitempty"`
    FieldOfStudy    string `json:"fieldOfStudy,omitempty"`
    GraduationDate  string `json:"graduationDate,omitempty"`
    CertificateName string `json:"certificateName,omitempty"`
    CourseName      string `json:"courseName,omitempty"`
    CompletionDate  string `json:"completionDate,omitempty"`
    Grade           string `json:"grade,omitempty"`
    CreditsEarned   int    `json:"creditsEarned,omitempty"`
}
```

### EmploymentCredential

Employment verification credentials.

```go
type EmploymentSubject struct {
    ID              string `json:"id"`
    EmployerName    string `json:"employerName"`
    EmployerDID     string `json:"employerDid,omitempty"`
    JobTitle        string `json:"jobTitle"`
    Department      string `json:"department,omitempty"`
    StartDate       string `json:"startDate"`
    EndDate         string `json:"endDate,omitempty"`
    EmploymentType  string `json:"employmentType,omitempty"`
    WorkLocation    string `json:"workLocation,omitempty"`
    CurrentEmployee bool   `json:"currentEmployee"`
}
```

### MembershipCredential

Organization membership credentials.

```go
type MembershipSubject struct {
    ID               string   `json:"id"`
    OrganizationName string   `json:"organizationName"`
    OrganizationDID  string   `json:"organizationDid,omitempty"`
    MembershipID     string   `json:"membershipId,omitempty"`
    MembershipType   string   `json:"membershipType,omitempty"`
    Role             string   `json:"role,omitempty"`
    Roles            []string `json:"roles,omitempty"`
    AccessLevel      string   `json:"accessLevel,omitempty"`
    StartDate        string   `json:"startDate"`
    ExpirationDate   string   `json:"expirationDate,omitempty"`
    ActiveMember     bool     `json:"activeMember"`
}
```

## Issuance

### Process

1. Issuer generates or loads Ed25519 keypair
2. Issuer creates DID from public key
3. Generate unique credential ID
4. Create credential subject with claims
5. Sign credential as PASETO v4 public token
6. Register credential in revocation registry

### Example

```go
import (
    "veriglob/internal/vc"
    "veriglob/internal/revocation"
)

// Create credential subject
subject := vc.IdentitySubject{
    ID:          subjectDID,
    GivenName:   "John",
    FamilyName:  "Doe",
    DateOfBirth: "1990-01-15",
}

// Generate credential ID
credID, _ := revocation.GenerateCredentialID()

// Issue credential
token, err := vc.IssueVCWithID(
    issuerDID,
    subjectDID,
    issuerPrivateKey,
    subject,
    credID,
)
```

## Verification

### Process

1. Parse PASETO token
2. Verify signature with issuer's public key
3. Check expiration
4. Optionally check revocation status
5. Extract and validate claims

### Example

```go
import "veriglob/internal/vc"

claims, err := vc.VerifyVC(token, issuerPublicKey)
if err != nil {
    // Verification failed
}

// Access claims
fmt.Println(claims.Issuer)
fmt.Println(claims.VC.CredentialSubject)
```

## Verifiable Presentations

Holders can wrap credentials in signed presentations for verifiers.

### Structure

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiablePresentation"],
  "id": "urn:uuid:presentation-id",
  "holder": "did:key:z6MkHolder...",
  "verifiableCredential": ["v4.public.credential-token..."]
}
```

### Properties

| Property | Description |
|----------|-------------|
| Expiration | 15 minutes (short-lived) |
| Audience | Verifier's DID |
| Nonce | Challenge for replay protection |

### Example

```go
import "veriglob/internal/presentation"

vpToken, err := presentation.CreatePresentation(
    holderDID,
    holderPrivateKey,
    []string{credentialToken},
    verifierDID,
    nonce,
)
```

## Security Considerations

### Token Security

- PASETO v4 prevents algorithm confusion attacks
- Ed25519 provides 128-bit security level
- Tokens are tamper-evident

### Credential Binding

- Credentials are bound to subject DID
- Presentations prove holder controls the DID
- Nonce prevents replay attacks

### Revocation

- All credentials have revocation IDs
- Revocation status should be checked before accepting
- See [revocation.md](revocation.md) for details

## Future Considerations

- Selective disclosure (reveal only specific claims)
- Zero-knowledge proofs
- Credential schemas and validation
- Batch issuance
