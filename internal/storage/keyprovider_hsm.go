// +build hsm

package storage

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// HSMConfig contains configuration for HSM connection.
type HSMConfig struct {
	// LibraryPath is the path to the PKCS#11 library (.so/.dylib/.dll)
	// Examples:
	//   - SoftHSM2: /usr/lib/softhsm/libsofthsm2.so
	//   - AWS CloudHSM: /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
	//   - Thales Luna: /usr/safenet/lunaclient/lib/libCryptoki2_64.so
	LibraryPath string

	// SlotID is the HSM slot to use
	SlotID uint

	// PIN is the user PIN for the slot
	PIN string

	// TokenLabel is an optional label to identify the token
	TokenLabel string
}

// HSMKeyProvider implements KeyProvider using a PKCS#11 HSM.
// This provides FIPS 140-2 Level 3 compliant key storage.
type HSMKeyProvider struct {
	mu      sync.RWMutex
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	config  HSMConfig
	keys    map[string]pkcs11.ObjectHandle // keyID -> HSM object handle
}

// NewHSMKeyProvider creates a new HSM-based key provider.
func NewHSMKeyProvider(config HSMConfig) (*HSMKeyProvider, error) {
	if config.LibraryPath == "" {
		return nil, errors.New("HSM library path is required")
	}

	ctx := pkcs11.New(config.LibraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library: %s", config.LibraryPath)
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}

	// Open session
	session, err := ctx.OpenSession(config.SlotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		return nil, fmt.Errorf("failed to open HSM session: %w", err)
	}

	// Login
	if err := ctx.Login(session, pkcs11.CKU_USER, config.PIN); err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil, fmt.Errorf("failed to login to HSM: %w", err)
	}

	return &HSMKeyProvider{
		ctx:     ctx,
		session: session,
		config:  config,
		keys:    make(map[string]pkcs11.ObjectHandle),
	}, nil
}

// Type returns the provider type.
func (p *HSMKeyProvider) Type() KeyProviderType {
	return KeyProviderHSM
}

// GenerateKey creates a new Ed25519 key pair in the HSM.
func (p *HSMKeyProvider) GenerateKey() (ed25519.PublicKey, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	keyID := generateKeyID()
	label := []byte(keyID)

	// Ed25519 key generation template
	// Note: Not all HSMs support Ed25519 directly. Some may require EC keys.
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		// Ed25519 OID: 1.3.101.112
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x03, 0x2b, 0x65, 0x70}),
	}

	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // Key cannot be exported
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	// Generate key pair
	pubHandle, privHandle, err := p.ctx.GenerateKeyPair(
		p.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_EDWARDS_KEY_PAIR_GEN, nil)},
		pubTemplate,
		privTemplate,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate key pair in HSM: %w", err)
	}

	// Store private key handle
	p.keys[keyID] = privHandle

	// Extract public key
	pubKey, err := p.extractPublicKey(pubHandle)
	if err != nil {
		return nil, "", err
	}

	return pubKey, keyID, nil
}

// ImportKey imports a key into the HSM (wrapping it).
// Note: For true HSM security, keys should be generated in the HSM.
func (p *HSMKeyProvider) ImportKey(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	keyID := generateKeyID()
	label := []byte(keyID)

	// Import private key (will be wrapped by HSM)
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC_EDWARDS),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, privateKey.Seed()),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, []byte{0x06, 0x03, 0x2b, 0x65, 0x70}),
	}

	privHandle, err := p.ctx.CreateObject(p.session, privTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to import private key to HSM: %w", err)
	}

	p.keys[keyID] = privHandle
	return keyID, nil
}

// GetPublicKey retrieves the public key by ID.
func (p *HSMKeyProvider) GetPublicKey(keyID string) (ed25519.PublicKey, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Find public key by label
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyID)),
	}

	if err := p.ctx.FindObjectsInit(p.session, template); err != nil {
		return nil, err
	}
	defer p.ctx.FindObjectsFinal(p.session)

	handles, _, err := p.ctx.FindObjects(p.session, 1)
	if err != nil {
		return nil, err
	}
	if len(handles) == 0 {
		return nil, ErrKeyNotFound
	}

	return p.extractPublicKey(handles[0])
}

// Sign signs data using the key in the HSM.
func (p *HSMKeyProvider) Sign(keyID string, data []byte) ([]byte, error) {
	p.mu.RLock()
	privHandle, exists := p.keys[keyID]
	p.mu.RUnlock()

	if !exists {
		return nil, ErrKeyNotFound
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Initialize signing with Ed25519
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_EDDSA, nil)
	if err := p.ctx.SignInit(p.session, []*pkcs11.Mechanism{mechanism}, privHandle); err != nil {
		return nil, fmt.Errorf("failed to init signing: %w", err)
	}

	signature, err := p.ctx.Sign(p.session, data)
	if err != nil {
		return nil, fmt.Errorf("HSM signing failed: %w", err)
	}

	return signature, nil
}

// DeleteKey removes a key from the HSM.
func (p *HSMKeyProvider) DeleteKey(keyID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	privHandle, exists := p.keys[keyID]
	if !exists {
		return ErrKeyNotFound
	}

	// Delete private key
	if err := p.ctx.DestroyObject(p.session, privHandle); err != nil {
		return fmt.Errorf("failed to delete private key: %w", err)
	}

	// Find and delete public key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyID)),
	}

	if err := p.ctx.FindObjectsInit(p.session, template); err == nil {
		handles, _, _ := p.ctx.FindObjects(p.session, 1)
		p.ctx.FindObjectsFinal(p.session)
		if len(handles) > 0 {
			p.ctx.DestroyObject(p.session, handles[0])
		}
	}

	delete(p.keys, keyID)
	return nil
}

// Close releases HSM resources.
func (p *HSMKeyProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ctx != nil {
		p.ctx.Logout(p.session)
		p.ctx.CloseSession(p.session)
		p.ctx.Finalize()
		p.ctx = nil
	}
	return nil
}

// extractPublicKey extracts the public key bytes from an HSM object.
func (p *HSMKeyProvider) extractPublicKey(handle pkcs11.ObjectHandle) (ed25519.PublicKey, error) {
	attrs, err := p.ctx.GetAttributeValue(p.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	if len(attrs) == 0 || len(attrs[0].Value) < 32 {
		return nil, errors.New("invalid public key from HSM")
	}

	// EC_POINT is typically DER encoded, extract the raw 32 bytes
	// The format is usually 0x04 || X || Y for uncompressed, or just the key for Ed25519
	value := attrs[0].Value
	if len(value) == 32 {
		return ed25519.PublicKey(value), nil
	}
	// Handle DER encoding if present
	if len(value) > 32 {
		// Skip DER wrapper if present
		return ed25519.PublicKey(value[len(value)-32:]), nil
	}

	return nil, errors.New("unexpected public key format from HSM")
}

// GetHSMInfo returns information about the connected HSM.
func (p *HSMKeyProvider) GetHSMInfo() (map[string]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	info, err := p.ctx.GetInfo()
	if err != nil {
		return nil, err
	}

	slotInfo, err := p.ctx.GetSlotInfo(p.config.SlotID)
	if err != nil {
		return nil, err
	}

	tokenInfo, err := p.ctx.GetTokenInfo(p.config.SlotID)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"library_description":   string(info.LibraryDescription[:]),
		"library_version":       fmt.Sprintf("%d.%d", info.LibraryVersion.Major, info.LibraryVersion.Minor),
		"slot_description":      string(slotInfo.SlotDescription[:]),
		"token_label":           string(tokenInfo.Label[:]),
		"token_manufacturer":    string(tokenInfo.ManufacturerID[:]),
		"token_model":           string(tokenInfo.Model[:]),
		"token_serial":          string(tokenInfo.SerialNumber[:]),
		"hardware_version":      fmt.Sprintf("%d.%d", tokenInfo.HardwareVersion.Major, tokenInfo.HardwareVersion.Minor),
		"firmware_version":      fmt.Sprintf("%d.%d", tokenInfo.FirmwareVersion.Major, tokenInfo.FirmwareVersion.Minor),
	}, nil
}

// ListHSMSlots returns available HSM slots.
func ListHSMSlots(libraryPath string) ([]uint, error) {
	ctx := pkcs11.New(libraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library: %s", libraryPath)
	}
	defer ctx.Finalize()

	if err := ctx.Initialize(); err != nil {
		return nil, err
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	return slots, nil
}
