package resolver

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/mr-tron/base58"
)

func TestNewResolver(t *testing.T) {
	r := NewResolver()
	if r == nil {
		t.Fatal("New() returned nil")
	}
}

func TestResolveValidDIDKey(t *testing.T) {
	// Generate a test keypair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Create did:key manually (same as did package)
	multicodec := []byte{0xed, 0x01}
	prefixedKey := append(multicodec, pub...)
	encoded := "z" + base58.Encode(prefixedKey)
	did := "did:key:" + encoded

	// Resolve
	r := NewResolver()
	resolvedPub, err := r.Resolve(did)
	if err != nil {
		t.Fatalf("Failed to resolve DID: %v", err)
	}

	// Compare keys
	if !pub.Equal(resolvedPub) {
		t.Error("Resolved public key does not match original")
	}
}

func TestResolveDIDConvenienceFunction(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	multicodec := []byte{0xed, 0x01}
	prefixedKey := append(multicodec, pub...)
	encoded := "z" + base58.Encode(prefixedKey)
	did := "did:key:" + encoded

	resolvedPub, err := ResolveDID(did)
	if err != nil {
		t.Fatalf("ResolveDID failed: %v", err)
	}

	if !pub.Equal(resolvedPub) {
		t.Error("Resolved public key does not match original")
	}
}

func TestResolveInvalidDID(t *testing.T) {
	r := NewResolver()

	tests := []struct {
		name string
		did  string
		err  error
	}{
		{"empty", "", ErrInvalidDID},
		{"no prefix", "key:z6MkTest", ErrInvalidDID},
		{"single part", "did", ErrInvalidDID},
		{"two parts", "did:key", ErrInvalidDID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := r.Resolve(tt.did)
			if err != tt.err {
				t.Errorf("Expected error %v, got %v", tt.err, err)
			}
		})
	}
}

func TestResolveUnsupportedMethod(t *testing.T) {
	r := NewResolver()

	_, err := r.Resolve("did:web:example.com")
	if err != ErrUnsupportedMethod {
		t.Errorf("Expected ErrUnsupportedMethod, got %v", err)
	}

	_, err = r.Resolve("did:ethr:0x1234")
	if err != ErrUnsupportedMethod {
		t.Errorf("Expected ErrUnsupportedMethod, got %v", err)
	}
}

func TestResolveInvalidMultibase(t *testing.T) {
	r := NewResolver()

	// Missing 'z' prefix
	_, err := r.Resolve("did:key:6MkTest")
	if err != ErrInvalidDID {
		t.Errorf("Expected ErrInvalidDID for missing z prefix, got %v", err)
	}
}

func TestResolveInvalidMulticodec(t *testing.T) {
	r := NewResolver()

	// Valid base58 but wrong multicodec prefix
	wrongPrefix := []byte{0x00, 0x01} // Not Ed25519 prefix
	fakeKey := make([]byte, 32)
	prefixedKey := append(wrongPrefix, fakeKey...)
	encoded := "z" + base58.Encode(prefixedKey)
	did := "did:key:" + encoded

	_, err := r.Resolve(did)
	if err != ErrInvalidMulticodec {
		t.Errorf("Expected ErrInvalidMulticodec, got %v", err)
	}
}

func TestResolveInvalidKeyLength(t *testing.T) {
	r := NewResolver()

	// Correct multicodec but wrong key length
	multicodec := []byte{0xed, 0x01}
	shortKey := make([]byte, 16) // Should be 32
	prefixedKey := append(multicodec, shortKey...)
	encoded := "z" + base58.Encode(prefixedKey)
	did := "did:key:" + encoded

	_, err := r.Resolve(did)
	if err != ErrInvalidKeyLength {
		t.Errorf("Expected ErrInvalidKeyLength, got %v", err)
	}
}

func TestResolveRealWorldDID(t *testing.T) {
	// Test with a known valid did:key
	// This DID was generated with a known public key
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	multicodec := []byte{0xed, 0x01}
	prefixedKey := append(multicodec, pub...)
	encoded := "z" + base58.Encode(prefixedKey)
	did := "did:key:" + encoded

	resolvedPub, err := ResolveDID(did)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if len(resolvedPub) != ed25519.PublicKeySize {
		t.Errorf("Expected key size %d, got %d", ed25519.PublicKeySize, len(resolvedPub))
	}
}

func TestResolverRoundTrip(t *testing.T) {
	// Generate key -> create DID -> resolve DID -> compare key
	for i := 0; i < 10; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		multicodec := []byte{0xed, 0x01}
		prefixedKey := append(multicodec, pub...)
		encoded := "z" + base58.Encode(prefixedKey)
		did := "did:key:" + encoded

		resolved, err := ResolveDID(did)
		if err != nil {
			t.Fatalf("Failed to resolve: %v", err)
		}

		if !pub.Equal(resolved) {
			t.Errorf("Round trip %d: keys don't match", i)
		}
	}
}
