package storage

import (
	"crypto/ed25519"
	"errors"
)

// KeyProvider errors
var (
	ErrKeyNotFound      = errors.New("key not found")
	ErrKeyAlreadyExists = errors.New("key already exists")
	ErrHSMNotAvailable  = errors.New("HSM not available")
	ErrHSMSessionFailed = errors.New("HSM session failed")
	ErrSigningFailed    = errors.New("signing operation failed")
)

// KeyProviderType identifies the type of key provider
type KeyProviderType string

const (
	KeyProviderSoftware KeyProviderType = "software"
	KeyProviderHSM      KeyProviderType = "hsm"
)

// KeyProvider abstracts key storage and cryptographic operations.
// Implementations can use software keys or hardware security modules.
type KeyProvider interface {
	// Type returns the provider type (software or hsm)
	Type() KeyProviderType

	// GenerateKey creates a new Ed25519 key pair.
	// Returns the public key and a key ID for future reference.
	// For HSM, the private key never leaves the device.
	GenerateKey() (publicKey ed25519.PublicKey, keyID string, err error)

	// ImportKey imports an existing key pair (software provider only).
	// HSM providers may not support this or may wrap the key.
	ImportKey(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (keyID string, err error)

	// GetPublicKey retrieves the public key by ID.
	GetPublicKey(keyID string) (ed25519.PublicKey, error)

	// Sign signs data using the key identified by keyID.
	// For HSM, signing happens inside the secure hardware.
	Sign(keyID string, data []byte) (signature []byte, err error)

	// DeleteKey removes a key by ID.
	DeleteKey(keyID string) error

	// Close releases any resources (HSM sessions, etc.)
	Close() error
}

// KeyMetadata stores information about a key
type KeyMetadata struct {
	KeyID        string          `json:"keyId"`
	PublicKey    []byte          `json:"publicKey"`
	ProviderType KeyProviderType `json:"providerType"`
	CreatedAt    string          `json:"createdAt"`
	// For HSM keys, this may contain the HSM key label or handle reference
	HSMLabel string `json:"hsmLabel,omitempty"`
}
