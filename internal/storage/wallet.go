package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	ErrWalletNotFound   = errors.New("wallet not found")
	ErrWalletExists     = errors.New("wallet already exists")
	ErrInvalidMnemonic  = errors.New("invalid mnemonic")
	ErrCredentialExists = errors.New("credential already exists")
	ErrInvalidWordCount = errors.New("mnemonic must be 12 or 24 words")
)

const (
	pbkdf2Iterations = 100000
	saltSize         = 32
	keySize          = 32
)

// Wallet stores keys and credentials
type Wallet struct {
	path        string
	data        *WalletData
	mnemonic    string
	keyProvider KeyProvider // Optional: for HSM or custom key storage
	keyID       string      // Key ID when using KeyProvider
}

// WalletData is the serializable wallet structure
type WalletData struct {
	Version         int                         `json:"version"`
	CreatedAt       time.Time                   `json:"createdAt"`
	UpdatedAt       time.Time                   `json:"updatedAt"`
	DID             string                      `json:"did"`
	Keys            KeyPair                     `json:"keys"`
	Credentials     map[string]StoredCredential `json:"credentials"`
	KeyProviderType KeyProviderType             `json:"keyProviderType,omitempty"` // "software" or "hsm"
	KeyID           string                      `json:"keyId,omitempty"`           // Key ID for KeyProvider
}

// KeyPair stores the public and private keys
type KeyPair struct {
	PublicKey  []byte `json:"publicKey"`
	PrivateKey []byte `json:"privateKey"`
}

// StoredCredential represents a stored verifiable credential
type StoredCredential struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	IssuerDID       string    `json:"issuerDid"`
	IssuerPublicKey string    `json:"issuerPublicKey"`
	Token           string    `json:"token"`
	IssuedAt        time.Time `json:"issuedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`
	StoredAt        time.Time `json:"storedAt"`
}

// encryptedWallet is the on-disk format
type encryptedWallet struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// WalletOptions contains optional configuration for wallet creation.
type WalletOptions struct {
	KeyProvider KeyProvider // Optional: use HSM or custom key provider
}

// CreateWallet creates a new wallet with the given mnemonic phrase.
// The mnemonic should be a 12 or 24 word BIP39-style recovery phrase provided by the user.
func CreateWallet(path, mnemonic string) (*Wallet, error) {
	return CreateWalletWithOptions(path, mnemonic, nil)
}

// CreateWalletWithOptions creates a new wallet with optional KeyProvider.
// If opts is nil or opts.KeyProvider is nil, uses software-based key storage.
func CreateWalletWithOptions(path, mnemonic string, opts *WalletOptions) (*Wallet, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, ErrWalletExists
	}

	// Validate mnemonic provided by user
	if err := ValidateMnemonic(mnemonic); err != nil {
		return nil, err
	}

	// Create directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	now := time.Now()
	w := &Wallet{
		path:     path,
		mnemonic: mnemonic,
		data: &WalletData{
			Version:     1,
			CreatedAt:   now,
			UpdatedAt:   now,
			Credentials: make(map[string]StoredCredential),
		},
	}

	// Set up KeyProvider if provided
	if opts != nil && opts.KeyProvider != nil {
		w.keyProvider = opts.KeyProvider
		w.data.KeyProviderType = opts.KeyProvider.Type()
	}

	if err := w.Save(); err != nil {
		return nil, err
	}

	return w, nil
}

// GetMnemonic returns the wallet's mnemonic phrase.
// This should be stored securely by the user for recovery.
func (w *Wallet) GetMnemonic() string {
	return w.mnemonic
}

// OpenWallet opens an existing wallet using the mnemonic phrase.
func OpenWallet(path, mnemonic string) (*Wallet, error) {
	return OpenWalletWithOptions(path, mnemonic, nil)
}

// OpenWalletWithOptions opens an existing wallet with optional KeyProvider.
// If the wallet was created with an HSM, you must provide the same HSM provider.
func OpenWalletWithOptions(path, mnemonic string, opts *WalletOptions) (*Wallet, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, ErrWalletNotFound
	}

	// Validate mnemonic
	if err := ValidateMnemonic(mnemonic); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ew encryptedWallet
	if err := json.Unmarshal(data, &ew); err != nil {
		return nil, err
	}

	// Derive key from mnemonic
	key := pbkdf2.Key([]byte(mnemonic), ew.Salt, pbkdf2Iterations, keySize, sha256.New)

	// Decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, ew.Nonce, ew.Ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidMnemonic
	}

	var walletData WalletData
	if err := json.Unmarshal(plaintext, &walletData); err != nil {
		return nil, err
	}

	w := &Wallet{
		path:     path,
		mnemonic: mnemonic,
		data:     &walletData,
	}

	// Restore KeyProvider if provided and wallet uses one
	if opts != nil && opts.KeyProvider != nil {
		if walletData.KeyProviderType != "" && walletData.KeyProviderType != opts.KeyProvider.Type() {
			return nil, errors.New("key provider type mismatch")
		}
		w.keyProvider = opts.KeyProvider
		w.keyID = walletData.KeyID
	}

	return w, nil
}

// Save encrypts and saves the wallet to disk
func (w *Wallet) Save() error {
	w.data.UpdatedAt = time.Now()

	plaintext, err := json.Marshal(w.data)
	if err != nil {
		return err
	}

	// Generate salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	// Derive key from mnemonic
	key := pbkdf2.Key([]byte(w.mnemonic), salt, pbkdf2Iterations, keySize, sha256.New)

	// Encrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	ew := encryptedWallet{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	data, err := json.Marshal(ew)
	if err != nil {
		return err
	}

	return os.WriteFile(w.path, data, 0600)
}

// SetKeys stores the key pair in the wallet.
// If a KeyProvider is configured, the key will be imported into it.
func (w *Wallet) SetKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey, did string) error {
	w.data.DID = did

	if w.keyProvider != nil {
		// Import key into KeyProvider
		keyID, err := w.keyProvider.ImportKey(pub, priv)
		if err != nil {
			return err
		}
		w.keyID = keyID
		w.data.KeyID = keyID
		// Only store public key, private key is in KeyProvider
		w.data.Keys = KeyPair{
			PublicKey: pub,
		}
	} else {
		// Store both keys in wallet (software mode)
		w.data.Keys = KeyPair{
			PublicKey:  pub,
			PrivateKey: priv,
		}
	}
	return w.Save()
}

// GenerateKeys generates a new key pair using the configured KeyProvider.
// If no KeyProvider is set, derives keys from the mnemonic.
func (w *Wallet) GenerateKeys(did string) error {
	w.data.DID = did

	if w.keyProvider != nil {
		// Generate key in KeyProvider (e.g., HSM)
		pub, keyID, err := w.keyProvider.GenerateKey()
		if err != nil {
			return err
		}
		w.keyID = keyID
		w.data.KeyID = keyID
		w.data.Keys = KeyPair{
			PublicKey: pub,
		}
	} else {
		// Derive from mnemonic
		pub, priv, err := DeriveKeysFromMnemonic(w.mnemonic)
		if err != nil {
			return err
		}
		w.data.Keys = KeyPair{
			PublicKey:  pub,
			PrivateKey: priv,
		}
	}
	return w.Save()
}

// GetKeys retrieves the key pair from the wallet.
// Note: When using HSM, the private key will be nil.
func (w *Wallet) GetKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(w.data.Keys.PublicKey) == 0 {
		return nil, nil, errors.New("no keys stored in wallet")
	}

	pub := ed25519.PublicKey(w.data.Keys.PublicKey)

	// For HSM wallets, private key is not available
	if w.keyProvider != nil && w.data.KeyProviderType == KeyProviderHSM {
		return pub, nil, nil
	}

	return pub, ed25519.PrivateKey(w.data.Keys.PrivateKey), nil
}

// Sign signs data using the wallet's private key.
// Uses the KeyProvider if configured (e.g., HSM), otherwise uses the stored private key.
func (w *Wallet) Sign(data []byte) ([]byte, error) {
	if w.keyProvider != nil && w.keyID != "" {
		return w.keyProvider.Sign(w.keyID, data)
	}

	// Software signing
	if len(w.data.Keys.PrivateKey) == 0 {
		return nil, errors.New("no private key available for signing")
	}

	priv := ed25519.PrivateKey(w.data.Keys.PrivateKey)
	return ed25519.Sign(priv, data), nil
}

// GetKeyProvider returns the wallet's KeyProvider, if any.
func (w *Wallet) GetKeyProvider() KeyProvider {
	return w.keyProvider
}

// UsesHSM returns true if the wallet is configured to use an HSM.
func (w *Wallet) UsesHSM() bool {
	return w.data.KeyProviderType == KeyProviderHSM
}

// GetDID returns the wallet's DID
func (w *Wallet) GetDID() string {
	return w.data.DID
}

// AddCredential stores a credential in the wallet
func (w *Wallet) AddCredential(cred StoredCredential) error {
	if _, exists := w.data.Credentials[cred.ID]; exists {
		return ErrCredentialExists
	}
	cred.StoredAt = time.Now()
	w.data.Credentials[cred.ID] = cred
	return w.Save()
}

// GetCredential retrieves a credential by ID
func (w *Wallet) GetCredential(id string) (*StoredCredential, error) {
	cred, exists := w.data.Credentials[id]
	if !exists {
		return nil, errors.New("credential not found")
	}
	return &cred, nil
}

// ListCredentials returns all stored credentials
func (w *Wallet) ListCredentials() []StoredCredential {
	creds := make([]StoredCredential, 0, len(w.data.Credentials))
	for _, c := range w.data.Credentials {
		creds = append(creds, c)
	}
	return creds
}

// RemoveCredential removes a credential by ID
func (w *Wallet) RemoveCredential(id string) error {
	if _, exists := w.data.Credentials[id]; !exists {
		return errors.New("credential not found")
	}
	delete(w.data.Credentials, id)
	return w.Save()
}

// Export returns the wallet data as JSON (for backup)
func (w *Wallet) Export() ([]byte, error) {
	return json.MarshalIndent(w.data, "", "  ")
}

// ValidateMnemonic checks if the mnemonic has the correct format.
// Accepts 12 or 24 word mnemonics.
func ValidateMnemonic(mnemonic string) error {
	if mnemonic == "" {
		return ErrInvalidMnemonic
	}

	words := strings.Fields(mnemonic)
	wordCount := len(words)

	if wordCount != 12 && wordCount != 24 {
		return ErrInvalidWordCount
	}

	return nil
}

// DeriveKeysFromMnemonic derives Ed25519 keys from a mnemonic phrase.
// This provides deterministic key generation from the recovery phrase.
func DeriveKeysFromMnemonic(mnemonic string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := ValidateMnemonic(mnemonic); err != nil {
		return nil, nil, err
	}

	// Derive seed from mnemonic using PBKDF2
	// Using "veriglob" as the salt for domain separation
	seed := pbkdf2.Key([]byte(mnemonic), []byte("veriglob-ed25519-seed"), pbkdf2Iterations, ed25519.SeedSize, sha256.New)

	// Generate Ed25519 key pair from seed
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return publicKey, privateKey, nil
}
