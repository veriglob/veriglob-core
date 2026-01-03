package storage

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}
	return pub, priv
}

func TestCreateWallet(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")
	passphrase := "testpassword123"

	wallet, err := CreateWallet(path, passphrase)
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	if wallet == nil {
		t.Fatal("Wallet is nil")
	}

	// Check file was created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Wallet file should exist")
	}
}

func TestCreateWalletAlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	CreateWallet(path, "pass1")

	_, err := CreateWallet(path, "pass2")
	if err != ErrWalletExists {
		t.Errorf("Expected ErrWalletExists, got %v", err)
	}
}

func TestOpenWallet(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")
	passphrase := "testpassword123"

	// Create wallet
	w1, _ := CreateWallet(path, passphrase)
	pub, priv := generateTestKeypair(t)
	w1.SetKeys(pub, priv, "did:key:test")

	// Open wallet
	w2, err := OpenWallet(path, passphrase)
	if err != nil {
		t.Fatalf("Failed to open wallet: %v", err)
	}

	if w2.GetDID() != "did:key:test" {
		t.Errorf("Expected DID 'did:key:test', got %s", w2.GetDID())
	}
}

func TestOpenWalletWrongPassword(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	CreateWallet(path, "correctpassword")

	_, err := OpenWallet(path, "wrongpassword")
	if err != ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword, got %v", err)
	}
}

func TestOpenWalletNotFound(t *testing.T) {
	_, err := OpenWallet("/nonexistent/path/wallet.json", "pass")
	if err != ErrWalletNotFound {
		t.Errorf("Expected ErrWalletNotFound, got %v", err)
	}
}

func TestWalletSetAndGetKeys(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "pass")
	pub, priv := generateTestKeypair(t)
	did := "did:key:z6MkTest"

	err := wallet.SetKeys(pub, priv, did)
	if err != nil {
		t.Fatalf("Failed to set keys: %v", err)
	}

	gotPub, gotPriv, err := wallet.GetKeys()
	if err != nil {
		t.Fatalf("Failed to get keys: %v", err)
	}

	if !pub.Equal(gotPub) {
		t.Error("Public keys don't match")
	}

	if !priv.Equal(gotPriv) {
		t.Error("Private keys don't match")
	}

	if wallet.GetDID() != did {
		t.Errorf("Expected DID %s, got %s", did, wallet.GetDID())
	}
}

func TestWalletGetKeysEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "pass")

	_, _, err := wallet.GetKeys()
	if err == nil {
		t.Error("Expected error when getting keys from empty wallet")
	}
}

func TestWalletAddCredential(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "pass")

	cred := StoredCredential{
		ID:              "urn:uuid:test-cred",
		Type:            "IdentityCredential",
		IssuerDID:       "did:key:issuer",
		IssuerPublicKey: "abc123",
		Token:           "v4.public.token",
		IssuedAt:        time.Now(),
		ExpiresAt:       time.Now().Add(365 * 24 * time.Hour),
	}

	err := wallet.AddCredential(cred)
	if err != nil {
		t.Fatalf("Failed to add credential: %v", err)
	}

	// Retrieve credential
	got, err := wallet.GetCredential(cred.ID)
	if err != nil {
		t.Fatalf("Failed to get credential: %v", err)
	}

	if got.ID != cred.ID {
		t.Errorf("Expected ID %s, got %s", cred.ID, got.ID)
	}

	if got.Type != cred.Type {
		t.Errorf("Expected type %s, got %s", cred.Type, got.Type)
	}

	if got.StoredAt.IsZero() {
		t.Error("StoredAt should be set")
	}
}

func TestWalletAddCredentialDuplicate(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "pass")

	cred := StoredCredential{ID: "urn:uuid:dup-test"}
	wallet.AddCredential(cred)

	err := wallet.AddCredential(cred)
	if err != ErrCredentialExists {
		t.Errorf("Expected ErrCredentialExists, got %v", err)
	}
}

func TestWalletGetCredentialNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "pass")

	_, err := wallet.GetCredential("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent credential")
	}
}

func TestWalletListCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "pass")

	// Empty initially
	creds := wallet.ListCredentials()
	if len(creds) != 0 {
		t.Errorf("Expected 0 credentials, got %d", len(creds))
	}

	// Add some credentials
	wallet.AddCredential(StoredCredential{ID: "cred1"})
	wallet.AddCredential(StoredCredential{ID: "cred2"})
	wallet.AddCredential(StoredCredential{ID: "cred3"})

	creds = wallet.ListCredentials()
	if len(creds) != 3 {
		t.Errorf("Expected 3 credentials, got %d", len(creds))
	}
}

func TestWalletRemoveCredential(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "pass")

	wallet.AddCredential(StoredCredential{ID: "to-remove"})

	err := wallet.RemoveCredential("to-remove")
	if err != nil {
		t.Fatalf("Failed to remove credential: %v", err)
	}

	_, err = wallet.GetCredential("to-remove")
	if err == nil {
		t.Error("Credential should not exist after removal")
	}
}

func TestWalletRemoveCredentialNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "pass")

	err := wallet.RemoveCredential("nonexistent")
	if err == nil {
		t.Error("Expected error when removing nonexistent credential")
	}
}

func TestWalletExport(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "pass")
	pub, priv := generateTestKeypair(t)
	wallet.SetKeys(pub, priv, "did:key:export-test")
	wallet.AddCredential(StoredCredential{ID: "export-cred"})

	data, err := wallet.Export()
	if err != nil {
		t.Fatalf("Failed to export: %v", err)
	}

	if len(data) == 0 {
		t.Error("Export should return non-empty data")
	}

	// Should be valid JSON containing expected fields
	dataStr := string(data)
	if !contains(dataStr, "did:key:export-test") {
		t.Error("Export should contain DID")
	}
	if !contains(dataStr, "export-cred") {
		t.Error("Export should contain credential ID")
	}
}

func TestWalletPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")
	pass := "persistencetest"

	// Create and populate wallet
	w1, _ := CreateWallet(path, pass)
	pub, priv := generateTestKeypair(t)
	w1.SetKeys(pub, priv, "did:key:persist")
	w1.AddCredential(StoredCredential{ID: "persist-cred", Type: "TestCred"})

	// Open wallet again
	w2, err := OpenWallet(path, pass)
	if err != nil {
		t.Fatalf("Failed to reopen wallet: %v", err)
	}

	// Verify data persisted
	if w2.GetDID() != "did:key:persist" {
		t.Error("DID not persisted")
	}

	gotPub, gotPriv, _ := w2.GetKeys()
	if !pub.Equal(gotPub) || !priv.Equal(gotPriv) {
		t.Error("Keys not persisted correctly")
	}

	creds := w2.ListCredentials()
	if len(creds) != 1 || creds[0].ID != "persist-cred" {
		t.Error("Credentials not persisted correctly")
	}
}

func TestWalletEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wallet.json")

	wallet, _ := CreateWallet(path, "secretpass")
	pub, priv := generateTestKeypair(t)
	wallet.SetKeys(pub, priv, "did:key:encrypted")

	// Read raw file
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read wallet file: %v", err)
	}

	// Should not contain plaintext DID or key material
	dataStr := string(data)
	if contains(dataStr, "did:key:encrypted") {
		t.Error("Wallet file should not contain plaintext DID")
	}
	if contains(dataStr, "publicKey") {
		t.Error("Wallet file should not contain plaintext key field names")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
