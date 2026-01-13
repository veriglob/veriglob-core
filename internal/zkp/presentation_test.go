package zkp

import (
	"crypto/ed25519"
	"testing"

	"github.com/veriglob/veriglob-core/internal/vc"
	"github.com/veriglob/veriglob-core/internal/zkp/bbs"
)

func TestCreateZKPresentation(t *testing.T) {
	// Setup: create a ZK credential
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:holder",
			GivenName:   "Alice",
			FamilyName:  "Johnson",
			DateOfBirth: "1990-05-15",
			Nationality: "US",
		},
	}

	zkCred, err := IssueZKCredential("did:issuer", "did:holder", ed25519PrivKey, bbsKeyPair, subject, "cred-001")
	if err != nil {
		t.Fatalf("IssueZKCredential() error = %v", err)
	}

	// Create a presentation that reveals only givenName and familyName
	request := SelectiveDisclosureRequest{
		RevealedFields: []string{"givenName", "familyName"},
		Predicates:     nil, // No predicates for this test
	}

	presentation, err := CreateZKPresentation(zkCred, "did:holder", bbsKeyPair, request, "did:verifier", "nonce123")
	if err != nil {
		t.Fatalf("CreateZKPresentation() error = %v", err)
	}

	if presentation == nil {
		t.Fatal("CreateZKPresentation() returned nil")
	}

	// Verify presentation fields
	if presentation.Holder != "did:holder" {
		t.Errorf("Holder = %v, want did:holder", presentation.Holder)
	}
	if presentation.Audience != "did:verifier" {
		t.Errorf("Audience = %v, want did:verifier", presentation.Audience)
	}
	if presentation.Nonce != "nonce123" {
		t.Errorf("Nonce = %v, want nonce123", presentation.Nonce)
	}

	// Verify disclosed fields
	if len(presentation.DisclosedFields) != 2 {
		t.Errorf("DisclosedFields count = %d, want 2", len(presentation.DisclosedFields))
	}
	if val, ok := presentation.DisclosedFields["givenName"]; !ok || val != "Alice" {
		t.Errorf("DisclosedFields[\"givenName\"] = %v, want Alice", val)
	}
	if val, ok := presentation.DisclosedFields["familyName"]; !ok || val != "Johnson" {
		t.Errorf("DisclosedFields[\"familyName\"] = %v, want Johnson", val)
	}

	// Verify proof exists
	if len(presentation.BBSProof) == 0 {
		t.Error("BBSProof is empty")
	}
}

func TestCreateZKPresentationWithNoFields(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:holder",
			GivenName:   "Charlie",
			FamilyName:  "Brown",
			DateOfBirth: "1995-07-10",
			Nationality: "UK",
		},
	}

	zkCred, _ := IssueZKCredential("did:issuer", "did:holder", ed25519PrivKey, bbsKeyPair, subject, "cred-003")

	// Reveal no fields (zero-knowledge proof of credential possession)
	request := SelectiveDisclosureRequest{
		RevealedFields: []string{},
	}

	presentation, err := CreateZKPresentation(zkCred, "did:holder", bbsKeyPair, request, "did:verifier", "nonce789")
	if err != nil {
		t.Fatalf("CreateZKPresentation() error = %v", err)
	}

	if len(presentation.DisclosedFields) != 0 {
		t.Errorf("DisclosedFields should be empty, got %d", len(presentation.DisclosedFields))
	}
}

func TestCreateZKPresentationWithInvalidField(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:holder",
			GivenName:   "Diana",
			FamilyName:  "Prince",
			DateOfBirth: "1980-01-01",
			Nationality: "GR",
		},
	}

	zkCred, _ := IssueZKCredential("did:issuer", "did:holder", ed25519PrivKey, bbsKeyPair, subject, "cred-004")

	// Try to reveal a non-existent field
	request := SelectiveDisclosureRequest{
		RevealedFields: []string{"nonexistentField"},
	}

	_, err := CreateZKPresentation(zkCred, "did:holder", bbsKeyPair, request, "did:verifier", "nonce")
	if err != ErrFieldNotFound {
		t.Errorf("CreateZKPresentation() should return ErrFieldNotFound, got %v", err)
	}
}

func TestVerifyZKPresentation(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:holder",
			GivenName:   "Eve",
			FamilyName:  "Adams",
			DateOfBirth: "1975-12-25",
			Nationality: "AU",
		},
	}

	zkCred, _ := IssueZKCredential("did:issuer", "did:holder", ed25519PrivKey, bbsKeyPair, subject, "cred-005")

	request := SelectiveDisclosureRequest{
		RevealedFields: []string{"givenName", "familyName"},
	}

	presentation, _ := CreateZKPresentation(zkCred, "did:holder", bbsKeyPair, request, "did:verifier", "nonce")

	// Verify the presentation
	err := VerifyZKPresentation(presentation, bbsKeyPair, "did:verifier", "nonce")
	if err != nil {
		t.Errorf("VerifyZKPresentation() error = %v", err)
	}
}

func TestVerifyZKPresentationWithWrongKey(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair1, _ := bbs.GenerateKeyPair(20)
	bbsKeyPair2, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:holder",
			GivenName:   "Frank",
			FamilyName:  "Castle",
			DateOfBirth: "1965-06-15",
			Nationality: "US",
		},
	}

	zkCred, _ := IssueZKCredential("did:issuer", "did:holder", ed25519PrivKey, bbsKeyPair1, subject, "cred-006")

	request := SelectiveDisclosureRequest{
		RevealedFields: []string{"givenName"},
	}

	presentation, _ := CreateZKPresentation(zkCred, "did:holder", bbsKeyPair1, request, "did:verifier", "nonce")

	// Try to verify with different key pair (should fail)
	err := VerifyZKPresentation(presentation, bbsKeyPair2, "did:verifier", "nonce")
	if err == nil {
		t.Error("VerifyZKPresentation() should fail with wrong key")
	}
}

func TestZKPresentationEndToEnd(t *testing.T) {
	// This test simulates a complete flow:
	// 1. Issuer creates credential
	// 2. Holder creates presentation
	// 3. Verifier verifies presentation

	// === Issuer Side ===
	_, issuerEd25519Key, _ := ed25519.GenerateKey(nil)
	issuerBBSKeys, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:veriglob:holder:citizen456",
			GivenName:   "John",
			FamilyName:  "Doe",
			DateOfBirth: "1990-01-15",
			Nationality: "DE",
		},
	}

	credential, err := IssueZKCredential(
		"did:veriglob:issuer:gov123",
		"did:veriglob:holder:citizen456",
		issuerEd25519Key,
		issuerBBSKeys,
		subject,
		"credential-id-789",
	)
	if err != nil {
		t.Fatalf("Issuer: IssueZKCredential() error = %v", err)
	}

	// === Holder Side ===
	// Holder wants to prove they have a government-issued credential
	// but only reveal their nationality (not name or DOB)
	holderRequest := SelectiveDisclosureRequest{
		RevealedFields: []string{"nationality", "issuerDid"},
	}

	presentation, err := CreateZKPresentation(
		credential,
		"did:veriglob:holder:citizen456",
		issuerBBSKeys,
		holderRequest,
		"did:veriglob:verifier:company789",
		"unique-nonce-12345",
	)
	if err != nil {
		t.Fatalf("Holder: CreateZKPresentation() error = %v", err)
	}

	// === Verifier Side ===
	// Verifier receives the presentation and the issuer's BBS+ key pair
	// (in practice, they would fetch the public key from the issuer's DID document)

	// Verify the presentation
	err = VerifyZKPresentation(
		presentation,
		issuerBBSKeys,
		"did:veriglob:verifier:company789",
		"unique-nonce-12345",
	)
	if err != nil {
		t.Fatalf("Verifier: VerifyZKPresentation() error = %v", err)
	}

	// Verifier can now trust:
	// 1. The credential was issued by did:veriglob:issuer:gov123
	// 2. The holder's nationality is "DE"
	// 3. The holder possesses a valid credential (without knowing name or DOB)

	if presentation.DisclosedFields["nationality"] == nil {
		t.Error("Nationality should be disclosed")
	}
	if presentation.DisclosedFields["nationality"] != "DE" {
		t.Errorf("Nationality = %v, want DE", presentation.DisclosedFields["nationality"])
	}

	// These fields should NOT be in the presentation
	if _, exists := presentation.DisclosedFields["givenName"]; exists {
		t.Error("givenName should NOT be disclosed")
	}
	if _, exists := presentation.DisclosedFields["familyName"]; exists {
		t.Error("familyName should NOT be disclosed")
	}
	if _, exists := presentation.DisclosedFields["dateOfBirth"]; exists {
		t.Error("dateOfBirth should NOT be disclosed")
	}
}

func TestVerifyZKPresentationAudienceMismatch(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:holder",
			GivenName:   "Test",
			FamilyName:  "User",
			DateOfBirth: "1990-01-01",
			Nationality: "US",
		},
	}

	zkCred, _ := IssueZKCredential("did:issuer", "did:holder", ed25519PrivKey, bbsKeyPair, subject, "cred-008")

	request := SelectiveDisclosureRequest{
		RevealedFields: []string{"givenName"},
	}

	presentation, _ := CreateZKPresentation(zkCred, "did:holder", bbsKeyPair, request, "did:verifier-A", "nonce")

	// Try to verify with wrong audience
	err := VerifyZKPresentation(presentation, bbsKeyPair, "did:verifier-B", "nonce")
	if err != ErrAudienceMismatch {
		t.Errorf("VerifyZKPresentation() should return ErrAudienceMismatch, got %v", err)
	}
}

func TestVerifyZKPresentationNonceMismatch(t *testing.T) {
	_, ed25519PrivKey, _ := ed25519.GenerateKey(nil)
	bbsKeyPair, _ := bbs.GenerateKeyPair(20)

	subject := vc.ZKIdentitySubject{
		IdentitySubject: vc.IdentitySubject{
			ID:          "did:holder",
			GivenName:   "Test",
			FamilyName:  "User",
			DateOfBirth: "1990-01-01",
			Nationality: "US",
		},
	}

	zkCred, _ := IssueZKCredential("did:issuer", "did:holder", ed25519PrivKey, bbsKeyPair, subject, "cred-009")

	request := SelectiveDisclosureRequest{
		RevealedFields: []string{"givenName"},
	}

	presentation, _ := CreateZKPresentation(zkCred, "did:holder", bbsKeyPair, request, "did:verifier", "nonce-A")

	// Try to verify with wrong nonce
	err := VerifyZKPresentation(presentation, bbsKeyPair, "did:verifier", "nonce-B")
	if err != ErrNonceMismatch {
		t.Errorf("VerifyZKPresentation() should return ErrNonceMismatch, got %v", err)
	}
}
