package presentation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"aidanwoods.dev/go-paseto"
)

// VerifiablePresentation represents a VP containing one or more VCs
type VerifiablePresentation struct {
	Context              []string `json:"@context"`
	Type                 []string `json:"type"`
	ID                   string   `json:"id,omitempty"`
	Holder               string   `json:"holder"`
	VerifiableCredential []string `json:"verifiableCredential"`
}

// VPClaims represents the PASETO claims for a Verifiable Presentation
type VPClaims struct {
	Issuer    string                 `json:"iss"`
	Subject   string                 `json:"sub"`
	Audience  string                 `json:"aud"`
	Nonce     string                 `json:"nonce"`
	IssuedAt  time.Time              `json:"iat"`
	ExpiresAt time.Time              `json:"exp"`
	VP        VerifiablePresentation `json:"vp"`
}

// CreatePresentation creates a signed Verifiable Presentation
func CreatePresentation(
	holderDID string,
	holderPrivateKey ed25519.PrivateKey,
	credentials []string,
	audience string,
	nonce string,
) (string, error) {
	if len(credentials) == 0 {
		return "", errors.New("at least one credential is required")
	}

	secretKey, err := paseto.NewV4AsymmetricSecretKeyFromBytes(holderPrivateKey)
	if err != nil {
		return "", err
	}

	// Generate presentation ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	presentationID := "urn:uuid:" + hex.EncodeToString(idBytes[:4]) + "-" +
		hex.EncodeToString(idBytes[4:6]) + "-" +
		hex.EncodeToString(idBytes[6:8]) + "-" +
		hex.EncodeToString(idBytes[8:10]) + "-" +
		hex.EncodeToString(idBytes[10:])

	now := time.Now()

	vp := VerifiablePresentation{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		Type: []string{
			"VerifiablePresentation",
		},
		ID:                   presentationID,
		Holder:               holderDID,
		VerifiableCredential: credentials,
	}

	vpClaims := VPClaims{
		Issuer:    holderDID,
		Subject:   holderDID,
		Audience:  audience,
		Nonce:     nonce,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute), // Presentations are short-lived
		VP:        vp,
	}

	token := paseto.NewToken()
	token.SetIssuer(vpClaims.Issuer)
	token.SetSubject(vpClaims.Subject)
	token.SetAudience(vpClaims.Audience)
	token.SetIssuedAt(vpClaims.IssuedAt)
	token.SetExpiration(vpClaims.ExpiresAt)
	token.SetString("nonce", vpClaims.Nonce)

	vpJSON, err := json.Marshal(vpClaims.VP)
	if err != nil {
		return "", err
	}
	if err := token.Set("vp", json.RawMessage(vpJSON)); err != nil {
		return "", err
	}

	return token.V4Sign(secretKey, nil), nil
}

// VerifyPresentation verifies a PASETO VP token and returns the claims
func VerifyPresentation(
	tokenString string,
	holderPublicKey ed25519.PublicKey,
	expectedAudience string,
	expectedNonce string,
) (*VPClaims, error) {
	pasetoPublicKey, err := paseto.NewV4AsymmetricPublicKeyFromBytes(holderPublicKey)
	if err != nil {
		return nil, err
	}

	parser := paseto.NewParser()
	token, err := parser.ParseV4Public(pasetoPublicKey, tokenString, nil)
	if err != nil {
		return nil, err
	}

	claims := &VPClaims{}

	claims.Issuer, err = token.GetIssuer()
	if err != nil {
		return nil, err
	}

	claims.Subject, err = token.GetSubject()
	if err != nil {
		return nil, err
	}

	claims.Audience, err = token.GetAudience()
	if err != nil {
		return nil, err
	}

	claims.IssuedAt, err = token.GetIssuedAt()
	if err != nil {
		return nil, err
	}

	claims.ExpiresAt, err = token.GetExpiration()
	if err != nil {
		return nil, err
	}

	claims.Nonce, err = token.GetString("nonce")
	if err != nil {
		return nil, err
	}

	// Verify audience if provided
	if expectedAudience != "" && claims.Audience != expectedAudience {
		return nil, errors.New("audience mismatch")
	}

	// Verify nonce if provided
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return nil, errors.New("nonce mismatch")
	}

	// Check expiration
	if time.Now().After(claims.ExpiresAt) {
		return nil, errors.New("presentation expired")
	}

	var vp VerifiablePresentation
	if err := token.Get("vp", &vp); err != nil {
		return nil, err
	}
	claims.VP = vp

	return claims, nil
}

// GenerateNonce creates a random nonce for challenge-response
func GenerateNonce() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
