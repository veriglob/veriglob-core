package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerateEd25519Keypair(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair() error = %v", err)
	}

	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("PublicKey length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("PrivateKey length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}

	// Verify keys work together
	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("Failed to verify signature with generated keypair")
	}
}
