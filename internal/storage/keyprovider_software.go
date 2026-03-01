package storage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// SoftwareKeyProvider implements KeyProvider using in-memory software keys.
// This is the default provider for development and non-HSM deployments.
type SoftwareKeyProvider struct {
	mu   sync.RWMutex
	keys map[string]*softwareKey
}

type softwareKey struct {
	metadata   KeyMetadata
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// NewSoftwareKeyProvider creates a new software-based key provider.
func NewSoftwareKeyProvider() *SoftwareKeyProvider {
	return &SoftwareKeyProvider{
		keys: make(map[string]*softwareKey),
	}
}

// Type returns the provider type.
func (p *SoftwareKeyProvider) Type() KeyProviderType {
	return KeyProviderSoftware
}

// GenerateKey creates a new Ed25519 key pair.
func (p *SoftwareKeyProvider) GenerateKey() (ed25519.PublicKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}

	keyID := generateKeyID()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.keys[keyID] = &softwareKey{
		metadata: KeyMetadata{
			KeyID:        keyID,
			PublicKey:    pub,
			ProviderType: KeyProviderSoftware,
			CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		},
		publicKey:  pub,
		privateKey: priv,
	}

	return pub, keyID, nil
}

// ImportKey imports an existing key pair.
func (p *SoftwareKeyProvider) ImportKey(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (string, error) {
	keyID := generateKeyID()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.keys[keyID] = &softwareKey{
		metadata: KeyMetadata{
			KeyID:        keyID,
			PublicKey:    publicKey,
			ProviderType: KeyProviderSoftware,
			CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		},
		publicKey:  publicKey,
		privateKey: privateKey,
	}

	return keyID, nil
}

// GetPublicKey retrieves the public key by ID.
func (p *SoftwareKeyProvider) GetPublicKey(keyID string) (ed25519.PublicKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	key, exists := p.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return key.publicKey, nil
}

// Sign signs data using the key identified by keyID.
func (p *SoftwareKeyProvider) Sign(keyID string, data []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	key, exists := p.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	signature := ed25519.Sign(key.privateKey, data)
	return signature, nil
}

// DeleteKey removes a key by ID.
func (p *SoftwareKeyProvider) DeleteKey(keyID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.keys[keyID]; !exists {
		return ErrKeyNotFound
	}

	delete(p.keys, keyID)
	return nil
}

// Close releases resources (no-op for software provider).
func (p *SoftwareKeyProvider) Close() error {
	return nil
}

// GetPrivateKey retrieves the private key (software provider only).
// This method is not part of the KeyProvider interface as HSMs don't expose private keys.
func (p *SoftwareKeyProvider) GetPrivateKey(keyID string) (ed25519.PrivateKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	key, exists := p.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return key.privateKey, nil
}

// ListKeys returns all key IDs.
func (p *SoftwareKeyProvider) ListKeys() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ids := make([]string, 0, len(p.keys))
	for id := range p.keys {
		ids = append(ids, id)
	}
	return ids
}

// generateKeyID creates a unique key identifier.
func generateKeyID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
