package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func TestCreateDIDKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	didKey, err := CreateDIDKey(pub)
	if err != nil {
		t.Fatalf("CreateDIDKey failed: %v", err)
	}

	if !strings.HasPrefix(didKey.DID, "did:key:z") {
		t.Errorf("DID should start with did:key:z, got %s", didKey.DID)
	}

	if len(didKey.DIDDocument.VerificationMethod) != 1 {
		t.Errorf("Expected 1 verification method, got %d", len(didKey.DIDDocument.VerificationMethod))
	}

	vm := didKey.DIDDocument.VerificationMethod[0]
	if vm.Controller != didKey.DID {
		t.Errorf("Controller mismatch. Expected %s, got %s", didKey.DID, vm.Controller)
	}
}

func TestPrettyPrint(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	didKey, _ := CreateDIDKey(pub)

	jsonStr, err := didKey.PrettyPrint()
	if err != nil {
		t.Fatalf("PrettyPrint failed: %v", err)
	}

	var doc DIDDocument
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		t.Errorf("PrettyPrint returned invalid JSON: %v", err)
	}

	if doc.ID != didKey.DID {
		t.Errorf("JSON ID mismatch. Expected %s, got %s", didKey.DID, doc.ID)
	}
}
