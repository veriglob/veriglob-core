package vc

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestIssueAndVerifyVC(t *testing.T) {
	// Generate Issuer Keys
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	// Mock DIDs
	issuerDID := "did:key:zIssuer"
	subjectDID := "did:key:zSubject"

	// Create a Subject
	credSubject := IdentitySubject{
		ID:          subjectDID,
		GivenName:   "Alice",
		FamilyName:  "Doe",
		DateOfBirth: "1990-01-01",
	}

	// Issue VC
	token, err := IssueVC(issuerDID, subjectDID, issuerPriv, credSubject)
	if err != nil {
		t.Fatalf("IssueVC failed: %v", err)
	}

	if token == "" {
		t.Fatal("Token is empty")
	}

	// Verify VC
	claims, err := VerifyVC(token, issuerPub)
	if err != nil {
		t.Fatalf("VerifyVC failed: %v", err)
	}

	// Check Claims
	if claims.Issuer != issuerDID {
		t.Errorf("Issuer mismatch. Got %s, want %s", claims.Issuer, issuerDID)
	}
	if claims.Subject != subjectDID {
		t.Errorf("Subject mismatch. Got %s, want %s", claims.Subject, subjectDID)
	}

	// Check VC specific fields
	// When unmarshaling JSON into interface{}, it becomes map[string]interface{}
	subjectMap, ok := claims.VC.CredentialSubject.(map[string]interface{})
	if !ok {
		t.Fatalf("CredentialSubject is not a map, got %T", claims.VC.CredentialSubject)
	}

	if subjectMap["givenName"] != "Alice" {
		t.Errorf("GivenName mismatch. Got %v, want Alice", subjectMap["givenName"])
	}

	// Check Expiration
	if claims.ExpiresAt.Before(time.Now()) {
		t.Error("Token is expired")
	}
}

func TestIssueVC_InvalidKey(t *testing.T) {
	// Pass a wrong key type
	_, err := IssueVC("did:iss", "did:sub", "not-a-key", IdentitySubject{})
	if err == nil {
		t.Error("Expected error for invalid private key, got nil")
	}
}
