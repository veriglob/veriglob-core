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
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	ErrWalletNotFound   = errors.New("wallet not found")
	ErrWalletExists     = errors.New("wallet already exists")
	ErrInvalidPassword  = errors.New("invalid password")
	ErrCredentialExists = errors.New("credential already exists")
)

const (
	pbkdf2Iterations = 100000
	saltSize         = 32
	keySize          = 32
)

// Wallet stores keys and credentials
type Wallet struct {
	path       string
	data       *WalletData
	passphrase string
}

// WalletData is the serializable wallet structure
type WalletData struct {
	Version     int                         `json:"version"`
	CreatedAt   time.Time                   `json:"createdAt"`
	UpdatedAt   time.Time                   `json:"updatedAt"`
	DID         string                      `json:"did"`
	Keys        KeyPair                     `json:"keys"`
	Credentials map[string]StoredCredential `json:"credentials"`
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

// CreateWallet creates a new wallet with the given passphrase
func CreateWallet(path, passphrase string) (*Wallet, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, ErrWalletExists
	}

	// Create directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	now := time.Now()
	w := &Wallet{
		path:       path,
		passphrase: passphrase,
		data: &WalletData{
			Version:     1,
			CreatedAt:   now,
			UpdatedAt:   now,
			Credentials: make(map[string]StoredCredential),
		},
	}

	if err := w.Save(); err != nil {
		return nil, err
	}

	return w, nil
}

// OpenWallet opens an existing wallet
func OpenWallet(path, passphrase string) (*Wallet, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, ErrWalletNotFound
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ew encryptedWallet
	if err := json.Unmarshal(data, &ew); err != nil {
		return nil, err
	}

	// Derive key from passphrase
	key := pbkdf2.Key([]byte(passphrase), ew.Salt, pbkdf2Iterations, keySize, sha256.New)

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
		return nil, ErrInvalidPassword
	}

	var walletData WalletData
	if err := json.Unmarshal(plaintext, &walletData); err != nil {
		return nil, err
	}

	return &Wallet{
		path:       path,
		passphrase: passphrase,
		data:       &walletData,
	}, nil
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

	// Derive key from passphrase
	key := pbkdf2.Key([]byte(w.passphrase), salt, pbkdf2Iterations, keySize, sha256.New)

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

// SetKeys stores the key pair in the wallet
func (w *Wallet) SetKeys(pub ed25519.PublicKey, priv ed25519.PrivateKey, did string) error {
	w.data.DID = did
	w.data.Keys = KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}
	return w.Save()
}

// GetKeys retrieves the key pair from the wallet
func (w *Wallet) GetKeys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(w.data.Keys.PublicKey) == 0 {
		return nil, nil, errors.New("no keys stored in wallet")
	}
	return ed25519.PublicKey(w.data.Keys.PublicKey),
		ed25519.PrivateKey(w.data.Keys.PrivateKey), nil
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
