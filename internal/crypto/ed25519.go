package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
)

// GenerateEd25519Keypair creates a new Ed25519 keypair
func GenerateEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}
