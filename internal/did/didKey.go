package did

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/mr-tron/base58"
)

// Multicodec prefix for Ed25519 public key (0xed01)
var ed25519Multicodec = []byte{0xed, 0x01}

// DIDKey represents a did:key identifier
type DIDKey struct {
	DID         string
	PublicKey   ed25519.PublicKey
	DIDDocument DIDDocument
}

// DIDDocument is a minimal DID Document for did:key
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication"`
	AssertionMethod    []string             `json:"assertionMethod"`
}

type VerificationMethod struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Controller      string `json:"controller"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}

// CreateDIDKey generates a did:key from an Ed25519 public key
func CreateDIDKey(pub ed25519.PublicKey) (*DIDKey, error) {
	// 1. Prefix public key with multicodec
	prefixedKey := append(ed25519Multicodec, pub...)

	// 2. Multibase encode (base58btc)
	encoded := "z" + base58.Encode(prefixedKey)

	did := fmt.Sprintf("did:key:%s", encoded)
	vmID := did + "#key-1"

	doc := DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
		},
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:              vmID,
				Type:            "Ed25519VerificationKey2018",
				Controller:      did,
				PublicKeyBase58: base58.Encode(pub),
			},
		},
		Authentication:  []string{vmID},
		AssertionMethod: []string{vmID},
	}

	return &DIDKey{
		DID:         did,
		PublicKey:   pub,
		DIDDocument: doc,
	}, nil
}

// PrettyPrint returns the DID Document as formatted JSON
func (d *DIDKey) PrettyPrint() (string, error) {
	b, err := json.MarshalIndent(d.DIDDocument, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
