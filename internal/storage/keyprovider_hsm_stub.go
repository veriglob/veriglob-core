// +build !hsm

package storage

import (
	"crypto/ed25519"
)

// HSMConfig contains configuration for HSM connection.
// This is a stub for builds without HSM support.
type HSMConfig struct {
	LibraryPath string
	SlotID      uint
	PIN         string
	TokenLabel  string
}

// HSMKeyProvider is a stub for builds without HSM support.
type HSMKeyProvider struct{}

// NewHSMKeyProvider returns an error when HSM support is not compiled in.
func NewHSMKeyProvider(config HSMConfig) (*HSMKeyProvider, error) {
	return nil, ErrHSMNotAvailable
}

// Type returns the provider type.
func (p *HSMKeyProvider) Type() KeyProviderType {
	return KeyProviderHSM
}

// GenerateKey is not available without HSM support.
func (p *HSMKeyProvider) GenerateKey() (ed25519.PublicKey, string, error) {
	return nil, "", ErrHSMNotAvailable
}

// ImportKey is not available without HSM support.
func (p *HSMKeyProvider) ImportKey(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (string, error) {
	return "", ErrHSMNotAvailable
}

// GetPublicKey is not available without HSM support.
func (p *HSMKeyProvider) GetPublicKey(keyID string) (ed25519.PublicKey, error) {
	return nil, ErrHSMNotAvailable
}

// Sign is not available without HSM support.
func (p *HSMKeyProvider) Sign(keyID string, data []byte) ([]byte, error) {
	return nil, ErrHSMNotAvailable
}

// DeleteKey is not available without HSM support.
func (p *HSMKeyProvider) DeleteKey(keyID string) error {
	return ErrHSMNotAvailable
}

// Close is a no-op for the stub.
func (p *HSMKeyProvider) Close() error {
	return nil
}

// GetHSMInfo is not available without HSM support.
func (p *HSMKeyProvider) GetHSMInfo() (map[string]string, error) {
	return nil, ErrHSMNotAvailable
}

// ListHSMSlots is not available without HSM support.
func ListHSMSlots(libraryPath string) ([]uint, error) {
	return nil, ErrHSMNotAvailable
}
