package vc

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"aidanwoods.dev/go-paseto"
)

// VCClaims represents a PASETO Verifiable Credential
type VCClaims struct {
	Issuer    string               `json:"iss"`
	Subject   string               `json:"sub"`
	IssuedAt  time.Time            `json:"iat"`
	ExpiresAt time.Time            `json:"exp"`
	VC        VerifiableCredential `json:"vc"`
}

// VerifiableCredential payload
type VerifiableCredential struct {
	Type              []string    `json:"type"`
	CredentialSubject interface{} `json:"credentialSubject"`
}

// IssueVC creates and signs a PASETO v4 public Verifiable Credential
func IssueVC(
	issuerDID string,
	subjectDID string,
	privateKey interface{},
	subject CredentialSubject,
) (string, error) {
	edKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("private key must be ed25519.PrivateKey")
	}

	secretKey, err := paseto.NewV4AsymmetricSecretKeyFromBytes(edKey)
	if err != nil {
		return "", err
	}

	now := time.Now()

	vcClaims := VCClaims{
		Issuer:    issuerDID,
		Subject:   subjectDID,
		IssuedAt:  now,
		ExpiresAt: now.Add(365 * 24 * time.Hour),
		VC: VerifiableCredential{
			Type: []string{
				"VerifiableCredential",
				subject.CredentialType(),
			},
			CredentialSubject: subject,
		},
	}

	token := paseto.NewToken()
	token.SetIssuer(vcClaims.Issuer)
	token.SetSubject(vcClaims.Subject)
	token.SetIssuedAt(vcClaims.IssuedAt)
	token.SetExpiration(vcClaims.ExpiresAt)

	vcJSON, err := json.Marshal(vcClaims.VC)
	if err != nil {
		return "", err
	}
	if err := token.Set("vc", json.RawMessage(vcJSON)); err != nil {
		return "", err
	}

	return token.V4Sign(secretKey, nil), nil
}

// VerifyVC verifies a PASETO v4 public token and returns the claims
func VerifyVC(tokenString string, publicKey ed25519.PublicKey) (*VCClaims, error) {
	pasetoPublicKey, err := paseto.NewV4AsymmetricPublicKeyFromBytes(publicKey)
	if err != nil {
		return nil, err
	}

	parser := paseto.NewParser()
	token, err := parser.ParseV4Public(pasetoPublicKey, tokenString, nil)
	if err != nil {
		return nil, err
	}

	claims := &VCClaims{}

	claims.Issuer, err = token.GetIssuer()
	if err != nil {
		return nil, err
	}

	claims.Subject, err = token.GetSubject()
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

	var vc VerifiableCredential
	if err := token.Get("vc", &vc); err != nil {
		return nil, err
	}
	claims.VC = vc

	return claims, nil
}
