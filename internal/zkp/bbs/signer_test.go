package bbs

import (
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"),
	}

	// Sign the messages - use only the needed generators
	generators := kp.Generators[:len(messages)+1]
	sig, err := Sign(kp.SecretKey, generators, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if sig == nil {
		t.Fatal("Sign() returned nil signature")
	}

	// Verify the signature
	err = Verify(sig, kp.PublicKey, generators, messages)
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

func TestVerifyWithTamperedMessage(t *testing.T) {
	kp, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
	}

	generators := kp.Generators[:len(messages)+1]
	sig, err := Sign(kp.SecretKey, generators, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Tamper with a message
	tamperedMessages := [][]byte{
		[]byte("message1"),
		[]byte("TAMPERED"),
	}

	err = Verify(sig, kp.PublicKey, generators, tamperedMessages)
	if err == nil {
		t.Error("Verify() should fail with tampered message")
	}
}

func TestVerifyWithWrongKey(t *testing.T) {
	kp1, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}

	kp2, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	messages := [][]byte{
		[]byte("message1"),
	}

	// Sign with key pair 1
	generators1 := kp1.Generators[:len(messages)+1]
	sig, err := Sign(kp1.SecretKey, generators1, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify with key pair 2's public key (should fail)
	generators2 := kp2.Generators[:len(messages)+1]
	err = Verify(sig, kp2.PublicKey, generators2, messages)
	if err == nil {
		t.Error("Verify() should fail with wrong public key")
	}
}

func TestSignWithTooManyMessages(t *testing.T) {
	kp, err := GenerateKeyPair(2) // Only supports 2 messages (3 generators)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("message1"),
		[]byte("message2"),
		[]byte("message3"), // One too many
	}

	// Try to sign with all generators (only 3, need 4 for 3 messages)
	_, err = Sign(kp.SecretKey, kp.Generators, messages)
	if err == nil {
		t.Error("Sign() should fail when too many messages for generators")
	}
}

func TestSignatureSerialization(t *testing.T) {
	kp, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("test"),
	}

	generators := kp.Generators[:len(messages)+1]
	sig, err := Sign(kp.SecretKey, generators, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Serialize
	sigBytes := sig.Serialize()
	if len(sigBytes) == 0 {
		t.Fatal("Serialize() returned empty slice")
	}

	// Deserialize
	reconstructedSig, err := DeserializeSignature(sigBytes)
	if err != nil {
		t.Fatalf("DeserializeSignature() error = %v", err)
	}

	// Verify the reconstructed signature works
	err = Verify(reconstructedSig, kp.PublicKey, generators, messages)
	if err != nil {
		t.Errorf("Verify() with deserialized signature error = %v", err)
	}
}

func TestDeserializeSignatureErrors(t *testing.T) {
	// Test with invalid data
	_, err := DeserializeSignature([]byte{1, 2, 3})
	if err == nil {
		t.Error("DeserializeSignature() should fail with invalid data")
	}
}
