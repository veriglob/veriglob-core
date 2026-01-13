package bbs

import (
	"testing"
)

func TestSelectiveDisclosureProof(t *testing.T) {
	kp, err := GenerateKeyPair(10)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("field0"),
		[]byte("field1"),
		[]byte("field2"),
		[]byte("field3"),
		[]byte("field4"),
	}

	// Sign all messages - use only the needed generators
	generators := kp.Generators[:len(messages)+1]
	sig, err := Sign(kp.SecretKey, generators, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Reveal only messages at indexes 1 and 3
	revealedIndexes := []int{1, 3}
	nonce := []byte("test-nonce-123")

	// Create selective disclosure proof
	proof, err := CreateSelectiveDisclosureProof(sig, kp.PublicKey, generators, messages, revealedIndexes, nonce)
	if err != nil {
		t.Fatalf("CreateSelectiveDisclosureProof() error = %v", err)
	}

	if proof == nil {
		t.Fatal("CreateSelectiveDisclosureProof() returned nil")
	}

	// Verify the proof
	err = VerifySelectiveDisclosureProof(proof, kp.PublicKey, generators, nonce)
	if err != nil {
		t.Errorf("VerifySelectiveDisclosureProof() error = %v", err)
	}

	// Check revealed messages match
	if len(proof.RevealedMessages) != 2 {
		t.Errorf("RevealedMessages count = %d, want 2", len(proof.RevealedMessages))
	}
	if string(proof.RevealedMessages[0]) != "field1" {
		t.Errorf("RevealedMessages[0] = %s, want field1", string(proof.RevealedMessages[0]))
	}
	if string(proof.RevealedMessages[1]) != "field3" {
		t.Errorf("RevealedMessages[1] = %s, want field3", string(proof.RevealedMessages[1]))
	}
}

func TestSelectiveDisclosureProofWithTamperedMessage(t *testing.T) {
	kp, err := GenerateKeyPair(10)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("field0"),
		[]byte("field1"),
		[]byte("field2"),
	}

	generators := kp.Generators[:len(messages)+1]
	sig, err := Sign(kp.SecretKey, generators, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	revealedIndexes := []int{1}
	nonce := []byte("nonce")

	proof, err := CreateSelectiveDisclosureProof(sig, kp.PublicKey, generators, messages, revealedIndexes, nonce)
	if err != nil {
		t.Fatalf("CreateSelectiveDisclosureProof() error = %v", err)
	}

	// Tamper with a revealed message
	proof.RevealedMessages[0] = []byte("TAMPERED")

	// Verification should fail
	err = VerifySelectiveDisclosureProof(proof, kp.PublicKey, generators, nonce)
	if err == nil {
		t.Error("VerifySelectiveDisclosureProof() should fail with tampered message")
	}
}

func TestSelectiveDisclosureProofRevealAll(t *testing.T) {
	kp, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("msg0"),
		[]byte("msg1"),
		[]byte("msg2"),
	}

	generators := kp.Generators[:len(messages)+1]
	sig, err := Sign(kp.SecretKey, generators, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Reveal all messages
	revealedIndexes := []int{0, 1, 2}
	nonce := []byte("nonce")

	proof, err := CreateSelectiveDisclosureProof(sig, kp.PublicKey, generators, messages, revealedIndexes, nonce)
	if err != nil {
		t.Fatalf("CreateSelectiveDisclosureProof() error = %v", err)
	}

	err = VerifySelectiveDisclosureProof(proof, kp.PublicKey, generators, nonce)
	if err != nil {
		t.Errorf("VerifySelectiveDisclosureProof() error = %v", err)
	}
}

func TestSelectiveDisclosureProofRevealNone(t *testing.T) {
	kp, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("secret1"),
		[]byte("secret2"),
	}

	generators := kp.Generators[:len(messages)+1]
	sig, err := Sign(kp.SecretKey, generators, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Reveal no messages
	revealedIndexes := []int{}
	nonce := []byte("nonce")

	proof, err := CreateSelectiveDisclosureProof(sig, kp.PublicKey, generators, messages, revealedIndexes, nonce)
	if err != nil {
		t.Fatalf("CreateSelectiveDisclosureProof() error = %v", err)
	}

	err = VerifySelectiveDisclosureProof(proof, kp.PublicKey, generators, nonce)
	if err != nil {
		t.Errorf("VerifySelectiveDisclosureProof() error = %v", err)
	}

	if len(proof.RevealedMessages) != 0 {
		t.Errorf("RevealedMessages should be empty, got %d", len(proof.RevealedMessages))
	}
}

func TestSelectiveDisclosureProofSerialization(t *testing.T) {
	kp, err := GenerateKeyPair(10)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("field0"),
		[]byte("field1"),
		[]byte("field2"),
	}

	generators := kp.Generators[:len(messages)+1]
	sig, err := Sign(kp.SecretKey, generators, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	revealedIndexes := []int{1}
	nonce := []byte("nonce")

	proof, err := CreateSelectiveDisclosureProof(sig, kp.PublicKey, generators, messages, revealedIndexes, nonce)
	if err != nil {
		t.Fatalf("CreateSelectiveDisclosureProof() error = %v", err)
	}

	// Serialize
	proofBytes := proof.Serialize()
	if len(proofBytes) == 0 {
		t.Fatal("Serialize() returned empty slice")
	}

	// Deserialize
	reconstructedProof, err := DeserializeProof(proofBytes)
	if err != nil {
		t.Fatalf("DeserializeProof() error = %v", err)
	}

	// Verify the reconstructed proof
	err = VerifySelectiveDisclosureProof(reconstructedProof, kp.PublicKey, generators, nonce)
	if err != nil {
		t.Errorf("VerifySelectiveDisclosureProof() with deserialized proof error = %v", err)
	}
}

func TestSelectiveDisclosureProofInvalidIndex(t *testing.T) {
	kp, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := [][]byte{
		[]byte("msg0"),
		[]byte("msg1"),
	}

	generators := kp.Generators[:len(messages)+1]
	sig, err := Sign(kp.SecretKey, generators, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Try to reveal an index out of bounds
	revealedIndexes := []int{5} // Out of bounds
	nonce := []byte("nonce")

	_, err = CreateSelectiveDisclosureProof(sig, kp.PublicKey, generators, messages, revealedIndexes, nonce)
	if err == nil {
		t.Error("CreateSelectiveDisclosureProof() should fail with invalid index")
	}
}

func TestSelectiveDisclosureProofWrongKey(t *testing.T) {
	kp1, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}

	kp2, err := GenerateKeyPair(5)
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	messages := [][]byte{
		[]byte("msg0"),
		[]byte("msg1"),
	}

	// Sign with key pair 1
	generators1 := kp1.Generators[:len(messages)+1]
	sig, err := Sign(kp1.SecretKey, generators1, messages)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	revealedIndexes := []int{0}
	nonce := []byte("nonce")

	proof, err := CreateSelectiveDisclosureProof(sig, kp1.PublicKey, generators1, messages, revealedIndexes, nonce)
	if err != nil {
		t.Fatalf("CreateSelectiveDisclosureProof() error = %v", err)
	}

	// Verify with key pair 2 (should fail)
	generators2 := kp2.Generators[:len(messages)+1]
	err = VerifySelectiveDisclosureProof(proof, kp2.PublicKey, generators2, nonce)
	if err == nil {
		t.Error("VerifySelectiveDisclosureProof() should fail with wrong key")
	}
}
