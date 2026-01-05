// Package veriglob provides the public API for the Veriglob protocol.
// This package re-exports types and functions from internal packages
// for use by external applications.
package veriglob

import (
	"crypto/ed25519"
	"time"

	"github.com/veriglob/veriglob-core/internal/crypto"
	"github.com/veriglob/veriglob-core/internal/did"
	"github.com/veriglob/veriglob-core/internal/presentation"
	"github.com/veriglob/veriglob-core/internal/resolver"
	"github.com/veriglob/veriglob-core/internal/revocation"
	"github.com/veriglob/veriglob-core/internal/storage"
	"github.com/veriglob/veriglob-core/internal/vc"
)

// Re-export types from internal packages

// DID types
type (
	DIDKey             = did.DIDKey
	DIDDocument        = did.DIDDocument
	VerificationMethod = did.VerificationMethod
)

// Credential types
type (
	VCClaims             = vc.VCClaims
	VerifiableCredential = vc.VerifiableCredential
	CredentialStatus     = vc.CredentialStatus
	CredentialSubject    = vc.CredentialSubject
	IdentitySubject      = vc.IdentitySubject
	EducationSubject     = vc.EducationSubject
	EmploymentSubject    = vc.EmploymentSubject
	MembershipSubject    = vc.MembershipSubject
)

// Credential type constants
const (
	CredentialTypeIdentity   = vc.CredentialTypeIdentity
	CredentialTypeEducation  = vc.CredentialTypeEducation
	CredentialTypeEmployment = vc.CredentialTypeEmployment
	CredentialTypeMembership = vc.CredentialTypeMembership
)

// Presentation types
type (
	VPClaims               = presentation.VPClaims
	VerifiablePresentation = presentation.VerifiablePresentation
)

// Revocation types
type (
	RevocationRegistry = revocation.Registry
	RevocationEntry    = revocation.Entry
	RevocationStatus   = revocation.Status
)

// Revocation status constants
const (
	StatusActive  = revocation.StatusActive
	StatusRevoked = revocation.StatusRevoked
)

// Revocation errors
var (
	ErrCredentialNotFound = revocation.ErrCredentialNotFound
	ErrAlreadyRevoked     = revocation.ErrAlreadyRevoked
)

// Wallet types
type (
	Wallet           = storage.Wallet
	WalletData       = storage.WalletData
	KeyPair          = storage.KeyPair
	StoredCredential = storage.StoredCredential
)

// Wallet errors
var (
	ErrWalletNotFound   = storage.ErrWalletNotFound
	ErrWalletExists     = storage.ErrWalletExists
	ErrInvalidPassword  = storage.ErrInvalidPassword
	ErrCredentialExists = storage.ErrCredentialExists
)

// Resolver type
type Resolver = resolver.Resolver

// ============================================================================
// Crypto Functions
// ============================================================================

// GenerateEd25519Keypair generates a new Ed25519 key pair
func GenerateEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return crypto.GenerateEd25519Keypair()
}

// ============================================================================
// DID Functions
// ============================================================================

// CreateDIDKey generates a did:key from an Ed25519 public key
func CreateDIDKey(pub ed25519.PublicKey) (*DIDKey, error) {
	return did.CreateDIDKey(pub)
}

// ============================================================================
// Resolver Functions
// ============================================================================

// NewResolver creates a new DID resolver
func NewResolver() *Resolver {
	return resolver.NewResolver()
}

// ============================================================================
// Credential Functions
// ============================================================================

// IssueVC creates and signs a PASETO v4 public Verifiable Credential
func IssueVC(issuerDID, subjectDID string, privateKey interface{}, subject CredentialSubject) (string, error) {
	return vc.IssueVC(issuerDID, subjectDID, privateKey, subject)
}

// IssueVCWithID creates and signs a PASETO v4 public Verifiable Credential with a specific credential ID
func IssueVCWithID(issuerDID, subjectDID string, privateKey interface{}, subject CredentialSubject, credentialID string) (string, error) {
	return vc.IssueVCWithID(issuerDID, subjectDID, privateKey, subject, credentialID)
}

// VerifyVC verifies a PASETO v4 public token and returns the claims
func VerifyVC(tokenString string, publicKey ed25519.PublicKey) (*VCClaims, error) {
	return vc.VerifyVC(tokenString, publicKey)
}

// ============================================================================
// Presentation Functions
// ============================================================================

// CreatePresentation creates a signed Verifiable Presentation
func CreatePresentation(holderDID string, holderPrivateKey ed25519.PrivateKey, credentials []string, audience, nonce string) (string, error) {
	return presentation.CreatePresentation(holderDID, holderPrivateKey, credentials, audience, nonce)
}

// VerifyPresentation verifies a PASETO VP token and returns the claims
func VerifyPresentation(tokenString string, holderPublicKey ed25519.PublicKey, expectedAudience, expectedNonce string) (*VPClaims, error) {
	return presentation.VerifyPresentation(tokenString, holderPublicKey, expectedAudience, expectedNonce)
}

// GenerateNonce creates a random nonce for challenge-response
func GenerateNonce() (string, error) {
	return presentation.GenerateNonce()
}

// ============================================================================
// Revocation Functions
// ============================================================================

// NewRevocationRegistry creates a new in-memory revocation registry
func NewRevocationRegistry() *RevocationRegistry {
	return revocation.NewRegistry()
}

// NewRevocationRegistryWithFile creates a registry that persists to a file
func NewRevocationRegistryWithFile(path string) (*RevocationRegistry, error) {
	return revocation.NewRegistryWithFile(path)
}

// GenerateCredentialID creates a unique credential ID
func GenerateCredentialID() (string, error) {
	return revocation.GenerateCredentialID()
}

// ============================================================================
// Wallet Functions
// ============================================================================

// CreateWallet creates a new wallet with the given passphrase
func CreateWallet(path, passphrase string) (*Wallet, error) {
	return storage.CreateWallet(path, passphrase)
}

// OpenWallet opens an existing wallet
func OpenWallet(path, passphrase string) (*Wallet, error) {
	return storage.OpenWallet(path, passphrase)
}

// ============================================================================
// Helper Types for API
// ============================================================================

// CredentialInfo contains metadata about a credential for API responses
type CredentialInfo struct {
	ID               string
	Type             string
	IssuerDID        string
	SubjectDID       string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	Status           string
	RevocationReason string
}

// WalletInfo contains metadata about a wallet for API responses
type WalletInfo struct {
	ID              string
	DID             string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	CredentialCount int
}
