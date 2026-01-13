package zkp

import (
	"crypto/ed25519"
	"testing"

	"github.com/veriglob/veriglob-core/internal/vc"
	"github.com/veriglob/veriglob-core/internal/zkp/bbs"
)

func TestIssueZKCredential(t *testing.T) {
	// Generate Ed25519 key pair for PASETO
	_, ed25519PrivKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Generate BBS+ key pair (need enough generators for all messages)
	// 5 metadata fields + 12 identity fields = 17 messages
	bbsKeyPair, err := bbs.GenerateKeyPair(20)
	if err != nil {
		t.Fatalf("Failed to generate BBS+ key pair: %v", err)
	}

	// Create a ZK-capable subject (embeds IdentitySubject)
	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:veriglob:subject456",
			GivenName:   "Alice",
			FamilyName:  "Johnson",
			DateOfBirth: "1990-05-15",
			Nationality: "US",
		},
	}

	issuerDID := "did:veriglob:issuer123"
	subjectDID := "did:veriglob:subject456"
	credentialID := "cred-001"

	// Issue the ZK credential
	zkCred, err := IssueZKCredential(issuerDID, subjectDID, ed25519PrivKey, bbsKeyPair, subject, credentialID)
	if err != nil {
		t.Fatalf("IssueZKCredential() error = %v", err)
	}

	if zkCred == nil {
		t.Fatal("IssueZKCredential() returned nil")
	}

	// Verify fields
	if zkCred.CredentialID != credentialID {
		t.Errorf("CredentialID = %v, want %v", zkCred.CredentialID, credentialID)
	}
	if zkCred.IssuerDID != issuerDID {
		t.Errorf("IssuerDID = %v, want %v", zkCred.IssuerDID, issuerDID)
	}
	if zkCred.SubjectDID != subjectDID {
		t.Errorf("SubjectDID = %v, want %v", zkCred.SubjectDID, subjectDID)
	}
	if len(zkCred.BBSSignature) == 0 {
		t.Error("BBSSignature is empty")
	}
	if len(zkCred.BBSPublicKey) == 0 {
		t.Error("BBSPublicKey is empty")
	}
	if len(zkCred.OriginalToken) == 0 {
		t.Error("OriginalToken is empty")
	}

	// Messages should be created
	if len(zkCred.Messages) == 0 {
		t.Error("Messages is empty")
	}

	// Field names should be created
	if len(zkCred.FieldNames) == 0 {
		t.Error("FieldNames is empty")
	}
}

func TestVerifyZKCredentialSignature(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:subject",
			GivenName:   "Bob",
			FamilyName:  "Smith",
			DateOfBirth: "1985-03-20",
			Nationality: "CA",
		},
	}

	zkCred, err := IssueZKCredential("did:issuer", "did:subject", ed25519PrivKey, bbsKeyPair, subject, "cred-002")
	if err != nil {
		t.Fatalf("IssueZKCredential() error = %v", err)
	}

	// Verify the signature
	err = VerifyZKCredentialSignature(zkCred, bbsKeyPair)
	if err != nil {
		t.Errorf("VerifyZKCredentialSignature() error = %v", err)
	}
}

func TestVerifyZKCredentialSignatureWithWrongKey(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair1, _ := bbs.GenerateKeyPair(20)
	bbsKeyPair2, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:subject",
			GivenName:   "Charlie",
			FamilyName:  "Brown",
			DateOfBirth: "1995-07-10",
			Nationality: "UK",
		},
	}

	// Issue with key pair 1
	zkCred, _ := IssueZKCredential("did:issuer", "did:subject", ed25519PrivKey, bbsKeyPair1, subject, "cred-003")

	// Try to verify with key pair 2 (should fail)
	err := VerifyZKCredentialSignature(zkCred, bbsKeyPair2)
	if err == nil {
		t.Error("VerifyZKCredentialSignature() should fail with wrong key")
	}
}

func TestGetFieldIndex(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:subject",
			GivenName:   "Diana",
			FamilyName:  "Prince",
			DateOfBirth: "1980-01-01",
			Nationality: "GR",
		},
	}

	zkCred, _ := IssueZKCredential("did:issuer", "did:subject", ed25519PrivKey, bbsKeyPair, subject, "cred-004")

	// Test that we can find known fields
	credIdIdx := zkCred.GetFieldIndex("credentialId")
	if credIdIdx < 0 {
		t.Error("Should find credentialId field")
	}

	issuerIdx := zkCred.GetFieldIndex("issuerDid")
	if issuerIdx < 0 {
		t.Error("Should find issuerDid field")
	}

	// Test unknown field returns -1
	unknownIdx := zkCred.GetFieldIndex("nonexistent")
	if unknownIdx != -1 {
		t.Errorf("GetFieldIndex(nonexistent) = %d, want -1", unknownIdx)
	}
}

func TestGetFieldValue(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:subject",
			GivenName:   "Eve",
			FamilyName:  "Adams",
			DateOfBirth: "1975-12-25",
			Nationality: "AU",
		},
	}

	zkCred, _ := IssueZKCredential("did:issuer", "did:subject", ed25519PrivKey, bbsKeyPair, subject, "cred-005")

	// Test getting existing field
	value, err := zkCred.GetFieldValue("credentialId")
	if err != nil {
		t.Errorf("GetFieldValue() error = %v", err)
	}
	if string(value) != "cred-005" {
		t.Errorf("GetFieldValue(\"credentialId\") = %q, want \"cred-005\"", string(value))
	}

	// Test getting non-existent field
	_, err = zkCred.GetFieldValue("nonexistent")
	if err != ErrFieldNotFound {
		t.Errorf("GetFieldValue(\"nonexistent\") should return ErrFieldNotFound, got %v", err)
	}
}

func TestMapFieldsToIndexes(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:subject",
			GivenName:   "Frank",
			FamilyName:  "Castle",
			DateOfBirth: "1965-06-15",
			Nationality: "US",
		},
	}

	zkCred, _ := IssueZKCredential("did:issuer", "did:subject", ed25519PrivKey, bbsKeyPair, subject, "cred-006")

	// Test mapping valid fields
	indexes, err := MapFieldsToIndexes(zkCred, []string{"credentialId", "issuerDid"})
	if err != nil {
		t.Errorf("MapFieldsToIndexes() error = %v", err)
	}
	if len(indexes) != 2 {
		t.Errorf("MapFieldsToIndexes() returned %d indexes, want 2", len(indexes))
	}

	// Test with non-existent field
	_, err = MapFieldsToIndexes(zkCred, []string{"nonexistent"})
	if err != ErrFieldNotFound {
		t.Errorf("MapFieldsToIndexes() should return ErrFieldNotFound for nonexistent field")
	}
}

func TestIssueZKCredentialWithTooManyMessages(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	// Generate BBS+ key pair that can only handle 3 messages
	bbsKeyPair, _ := bbs.GenerateKeyPair(3)

	// Subject with 12 fields + 5 metadata = 17 messages total (too many for 3)
	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:subject",
			GivenName:   "Test",
			FamilyName:  "User",
			DateOfBirth: "2000-01-01",
			Nationality: "US",
		},
	}

	_, err := IssueZKCredential("did:issuer", "did:subject", ed25519PrivKey, bbsKeyPair, subject, "cred-007")
	if err != ErrInvalidMessageCount {
		t.Errorf("IssueZKCredential() should return ErrInvalidMessageCount, got %v", err)
	}
}
