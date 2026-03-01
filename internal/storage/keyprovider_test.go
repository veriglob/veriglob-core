package storage

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSoftwareKeyProviderType(t *testing.T) {
	provider := NewSoftwareKeyProvider()
	if provider.Type() != KeyProviderSoftware {
		t.Errorf("Expected type %s, got %s", KeyProviderSoftware, provider.Type())
	}
}

func TestSoftwareKeyProviderGenerateKey(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	pub, keyID, err := provider.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("Expected public key size %d, got %d", ed25519.PublicKeySize, len(pub))
	}

	if keyID == "" {
		t.Error("Key ID should not be empty")
	}

	// Verify key can be retrieved
	gotPub, err := provider.GetPublicKey(keyID)
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	if !pub.Equal(gotPub) {
		t.Error("Retrieved public key doesn't match generated key")
	}
}

func TestSoftwareKeyProviderImportKey(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	// Generate a key pair to import
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test keypair: %v", err)
	}

	keyID, err := provider.ImportKey(pub, priv)
	if err != nil {
		t.Fatalf("Failed to import key: %v", err)
	}

	if keyID == "" {
		t.Error("Key ID should not be empty")
	}

	// Verify key can be retrieved
	gotPub, err := provider.GetPublicKey(keyID)
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	if !pub.Equal(gotPub) {
		t.Error("Retrieved public key doesn't match imported key")
	}
}

func TestSoftwareKeyProviderSign(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	pub, keyID, err := provider.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	data := []byte("test message to sign")
	signature, err := provider.Sign(keyID, data)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Expected signature size %d, got %d", ed25519.SignatureSize, len(signature))
	}

	// Verify signature
	if !ed25519.Verify(pub, data, signature) {
		t.Error("Signature verification failed")
	}
}

func TestSoftwareKeyProviderSignNotFound(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	_, err := provider.Sign("nonexistent-key", []byte("data"))
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestSoftwareKeyProviderGetPublicKeyNotFound(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	_, err := provider.GetPublicKey("nonexistent-key")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestSoftwareKeyProviderDeleteKey(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	_, keyID, err := provider.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Delete the key
	err = provider.DeleteKey(keyID)
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify key is gone
	_, err = provider.GetPublicKey(keyID)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after deletion, got %v", err)
	}
}

func TestSoftwareKeyProviderDeleteKeyNotFound(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	err := provider.DeleteKey("nonexistent-key")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestSoftwareKeyProviderClose(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	err := provider.Close()
	if err != nil {
		t.Errorf("Close should not return error: %v", err)
	}
}

func TestSoftwareKeyProviderGetPrivateKey(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	pub, keyID, err := provider.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	priv, err := provider.GetPrivateKey(keyID)
	if err != nil {
		t.Fatalf("Failed to get private key: %v", err)
	}

	// Verify private key corresponds to public key
	derivedPub := priv.Public().(ed25519.PublicKey)
	if !pub.Equal(derivedPub) {
		t.Error("Private key doesn't match public key")
	}
}

func TestSoftwareKeyProviderGetPrivateKeyNotFound(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	_, err := provider.GetPrivateKey("nonexistent-key")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestSoftwareKeyProviderListKeys(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	// Initially empty
	keys := provider.ListKeys()
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}

	// Generate some keys
	_, keyID1, _ := provider.GenerateKey()
	_, keyID2, _ := provider.GenerateKey()
	_, keyID3, _ := provider.GenerateKey()

	keys = provider.ListKeys()
	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}

	// Verify all key IDs are present
	keyMap := make(map[string]bool)
	for _, id := range keys {
		keyMap[id] = true
	}

	if !keyMap[keyID1] || !keyMap[keyID2] || !keyMap[keyID3] {
		t.Error("Not all key IDs are present in list")
	}
}

func TestSoftwareKeyProviderConcurrency(t *testing.T) {
	provider := NewSoftwareKeyProvider()

	// Generate a key for signing
	_, keyID, err := provider.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			// Generate keys
			provider.GenerateKey()
			// Sign data
			provider.Sign(keyID, []byte("concurrent test data"))
			// Get public key
			provider.GetPublicKey(keyID)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify provider still works
	keys := provider.ListKeys()
	if len(keys) < 11 { // 1 original + 10 concurrent
		t.Errorf("Expected at least 11 keys, got %d", len(keys))
	}
}

func TestHSMKeyProviderNotAvailable(t *testing.T) {
	// Test that HSM provider returns proper error when not compiled with HSM support
	_, err := NewHSMKeyProvider(HSMConfig{
		LibraryPath: "/nonexistent/path.so",
		SlotID:      0,
		PIN:         "1234",
	})

	if err != ErrHSMNotAvailable {
		t.Logf("HSM error (expected when not built with hsm tag): %v", err)
	}
}

func TestWalletWithSoftwareKeyProvider(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/wallet_with_provider.json"

	provider := NewSoftwareKeyProvider()
	opts := &WalletOptions{
		KeyProvider: provider,
	}

	wallet, err := CreateWalletWithOptions(path, testMnemonic, opts)
	if err != nil {
		t.Fatalf("Failed to create wallet with KeyProvider: %v", err)
	}

	// Generate keys using the provider
	err = wallet.GenerateKeys("did:key:test")
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// Verify signing works
	data := []byte("test data to sign")
	signature, err := wallet.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Get public key and verify
	pub, _, err := wallet.GetKeys()
	if err != nil {
		t.Fatalf("Failed to get keys: %v", err)
	}

	if !ed25519.Verify(pub, data, signature) {
		t.Error("Signature verification failed")
	}
}

func TestWalletWithImportedKey(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/wallet_import.json"

	provider := NewSoftwareKeyProvider()
	opts := &WalletOptions{
		KeyProvider: provider,
	}

	wallet, err := CreateWalletWithOptions(path, testMnemonic, opts)
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	// Generate external key
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Import into wallet
	err = wallet.SetKeys(pub, priv, "did:key:imported")
	if err != nil {
		t.Fatalf("Failed to set keys: %v", err)
	}

	// Sign data
	data := []byte("imported key test")
	signature, err := wallet.Sign(data)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if !ed25519.Verify(pub, data, signature) {
		t.Error("Signature verification failed with imported key")
	}
}

func TestWalletKeyProviderPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/wallet_persist.json"

	provider := NewSoftwareKeyProvider()
	opts := &WalletOptions{
		KeyProvider: provider,
	}

	// Create wallet
	wallet, err := CreateWalletWithOptions(path, testMnemonic, opts)
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	err = wallet.GenerateKeys("did:key:persist")
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// Get the public key for later comparison
	originalPub, _, _ := wallet.GetKeys()

	// Open wallet with same provider
	wallet2, err := OpenWalletWithOptions(path, testMnemonic, opts)
	if err != nil {
		t.Fatalf("Failed to open wallet: %v", err)
	}

	restoredPub, _, _ := wallet2.GetKeys()
	if !originalPub.Equal(restoredPub) {
		t.Error("Public key not persisted correctly")
	}
}

func TestWalletUsesHSM(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/wallet_hsm_check.json"

	// Software wallet
	wallet, _ := CreateWallet(path, testMnemonic)
	if wallet.UsesHSM() {
		t.Error("Software wallet should not report using HSM")
	}
}

func TestWalletSignWithoutKeys(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/wallet_no_keys.json"

	wallet, _ := CreateWallet(path, testMnemonic)

	_, err := wallet.Sign([]byte("test"))
	if err == nil {
		t.Error("Expected error when signing without keys")
	}
}
