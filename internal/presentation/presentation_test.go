package presentation

import (
	"crypto/ed25519"
	"crypto/rand"
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

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	if len(nonce1) != 64 { // 32 bytes hex encoded
		t.Errorf("Expected nonce length 64, got %d", len(nonce1))
	}

	// Ensure uniqueness
	nonce2, _ := GenerateNonce()
	if nonce1 == nonce2 {
		t.Error("Generated nonces should be unique")
	}
}

func TestCreatePresentation(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	holderDID := "did:key:z6MkHolder"
	credentials := []string{"v4.public.test-credential-token"}
	audience := "did:key:z6MkVerifier"
	nonce := "test-nonce-12345"

	token, err := CreatePresentation(holderDID, priv, credentials, audience, nonce)
	if err != nil {
		t.Fatalf("Failed to create presentation: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	// Token should be PASETO v4 public
	if len(token) < 10 || token[:10] != "v4.public." {
		t.Errorf("Token should start with 'v4.public.', got: %s", token[:min(20, len(token))])
	}

	// Verify the presentation
	claims, err := VerifyPresentation(token, pub, audience, nonce)
	if err != nil {
		t.Fatalf("Failed to verify presentation: %v", err)
	}

	if claims.Issuer != holderDID {
		t.Errorf("Expected issuer %s, got %s", holderDID, claims.Issuer)
	}

	if claims.Audience != audience {
		t.Errorf("Expected audience %s, got %s", audience, claims.Audience)
	}

	if claims.Nonce != nonce {
		t.Errorf("Expected nonce %s, got %s", nonce, claims.Nonce)
	}

	if len(claims.VP.VerifiableCredential) != 1 {
		t.Errorf("Expected 1 credential, got %d", len(claims.VP.VerifiableCredential))
	}
}

func TestCreatePresentationNoCredentials(t *testing.T) {
	_, priv := generateTestKeypair(t)

	_, err := CreatePresentation("did:key:holder", priv, []string{}, "did:key:verifier", "nonce")
	if err == nil {
		t.Error("Expected error when creating presentation with no credentials")
	}
}

func TestCreatePresentationMultipleCredentials(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	credentials := []string{
		"v4.public.credential-1",
		"v4.public.credential-2",
		"v4.public.credential-3",
	}

	token, err := CreatePresentation("did:key:holder", priv, credentials, "did:key:verifier", "nonce")
	if err != nil {
		t.Fatalf("Failed to create presentation: %v", err)
	}

	claims, err := VerifyPresentation(token, pub, "did:key:verifier", "nonce")
	if err != nil {
		t.Fatalf("Failed to verify presentation: %v", err)
	}

	if len(claims.VP.VerifiableCredential) != 3 {
		t.Errorf("Expected 3 credentials, got %d", len(claims.VP.VerifiableCredential))
	}
}

func TestVerifyPresentationWrongKey(t *testing.T) {
	_, priv := generateTestKeypair(t)
	wrongPub, _ := generateTestKeypair(t)

	token, _ := CreatePresentation("did:key:holder", priv, []string{"cred"}, "aud", "nonce")

	_, err := VerifyPresentation(token, wrongPub, "aud", "nonce")
	if err == nil {
		t.Error("Expected error when verifying with wrong key")
	}
}

func TestVerifyPresentationWrongAudience(t *testing.T) {
	pub, priv := generateTestKeypair(t)

	token, _ := CreatePresentation("did:key:holder", priv, []string{"cred"}, "did:key:verifier1", "nonce")

	_, err := VerifyPresentation(token, pub, "did:key:verifier2", "nonce")
	if err == nil {
		t.Error("Expected error when verifying with wrong audience")
	}
}

func TestVerifyPresentationWrongNonce(t *testing.T) {
	pub, priv := generateTestKeypair(t)

	token, _ := CreatePresentation("did:key:holder", priv, []string{"cred"}, "aud", "nonce1")

	_, err := VerifyPresentation(token, pub, "aud", "nonce2")
	if err == nil {
		t.Error("Expected error when verifying with wrong nonce")
	}
}

func TestVerifyPresentationEmptyExpectedValues(t *testing.T) {
	pub, priv := generateTestKeypair(t)

	token, _ := CreatePresentation("did:key:holder", priv, []string{"cred"}, "aud", "nonce")

	// Empty expected values should skip validation
	claims, err := VerifyPresentation(token, pub, "", "")
	if err != nil {
		t.Fatalf("Failed to verify with empty expected values: %v", err)
	}

	if claims.Audience != "aud" {
		t.Errorf("Expected audience 'aud', got %s", claims.Audience)
	}
}

func TestPresentationExpiration(t *testing.T) {
	pub, priv := generateTestKeypair(t)

	token, _ := CreatePresentation("did:key:holder", priv, []string{"cred"}, "aud", "nonce")

	claims, err := VerifyPresentation(token, pub, "", "")
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	// Presentation should expire in ~15 minutes
	expectedExpiry := time.Now().Add(15 * time.Minute)
	if claims.ExpiresAt.Before(expectedExpiry.Add(-1*time.Minute)) || claims.ExpiresAt.After(expectedExpiry.Add(1*time.Minute)) {
		t.Errorf("Expiration should be ~15 minutes from now, got %v", claims.ExpiresAt)
	}
}

func TestVerifiablePresentationStructure(t *testing.T) {
	pub, priv := generateTestKeypair(t)
	holderDID := "did:key:z6MkTestHolder"

	token, _ := CreatePresentation(holderDID, priv, []string{"cred"}, "aud", "nonce")
	claims, _ := VerifyPresentation(token, pub, "", "")

	// Check VP structure
	if len(claims.VP.Context) == 0 {
		t.Error("VP should have @context")
	}

	if claims.VP.Context[0] != "https://www.w3.org/2018/credentials/v1" {
		t.Errorf("Expected W3C context, got %s", claims.VP.Context[0])
	}

	if len(claims.VP.Type) == 0 || claims.VP.Type[0] != "VerifiablePresentation" {
		t.Error("VP should have type VerifiablePresentation")
	}

	if claims.VP.Holder != holderDID {
		t.Errorf("Expected holder %s, got %s", holderDID, claims.VP.Holder)
	}

	if claims.VP.ID == "" {
		t.Error("VP should have an ID")
	}

	if claims.VP.ID[:9] != "urn:uuid:" {
		t.Errorf("VP ID should be URN format, got %s", claims.VP.ID)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
