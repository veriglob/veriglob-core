// Package bbs implements BBS+ signatures for selective disclosure.
// BBS+ allows signing multiple messages and later proving knowledge of
// a subset of those messages without revealing the others.
package bbs

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// KeyPair contains a BBS+ key pair for signing credentials.
type KeyPair struct {
	// SecretKey is the private signing key (scalar in Fr)
	SecretKey *big.Int

	// PublicKey is the public verification key (point on G2)
	PublicKey *bls12381.G2Affine

	// Generators are the message-specific generators (points on G1)
	// generators[0] is h0 (for blinding), generators[1..n] are for messages
	Generators []bls12381.G1Affine

	// MessageCount is the maximum number of messages this key can sign
	MessageCount int
}

// GenerateKeyPair creates a new BBS+ key pair capable of signing up to messageCount messages.
func GenerateKeyPair(messageCount int) (*KeyPair, error) {
	if messageCount <= 0 {
		return nil, errors.New("bbs: message count must be positive")
	}

	// Generate secret key: random scalar in Fr
	secretKey, err := randomScalar(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Compute public key: W = g2 * sk
	_, _, _, g2Gen := bls12381.Generators()
	var publicKey bls12381.G2Affine
	publicKey.ScalarMultiplication(&g2Gen, secretKey)

	// Generate message-specific generators
	// We need messageCount + 1 generators: h0 for blinding, h1..hn for messages
	generators, err := generateG1Generators(messageCount + 1)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		SecretKey:    secretKey,
		PublicKey:    &publicKey,
		Generators:   generators,
		MessageCount: messageCount,
	}, nil
}

// SecretKeyBytes returns the secret key as bytes.
func (kp *KeyPair) SecretKeyBytes() []byte {
	return kp.SecretKey.Bytes()
}

// PublicKeyBytes returns the public key as compressed bytes.
func (kp *KeyPair) PublicKeyBytes() []byte {
	bytes := kp.PublicKey.Bytes()
	return bytes[:]
}

// GeneratorsBytes returns the generators as compressed bytes.
func (kp *KeyPair) GeneratorsBytes() []byte {
	var result []byte
	for _, g := range kp.Generators {
		gBytes := g.Bytes()
		result = append(result, gBytes[:]...)
	}
	return result
}

// PublicKeyFromBytes reconstructs a public key from bytes.
func PublicKeyFromBytes(data []byte) (*bls12381.G2Affine, error) {
	var pk bls12381.G2Affine
	_, err := pk.SetBytes(data)
	if err != nil {
		return nil, err
	}
	return &pk, nil
}

// SecretKeyFromBytes reconstructs a secret key from bytes.
func SecretKeyFromBytes(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

// GeneratorsFromBytes reconstructs generators from bytes.
// Each G1 point is 48 bytes compressed.
func GeneratorsFromBytes(data []byte, count int) ([]bls12381.G1Affine, error) {
	const g1Size = 48 // compressed G1 point size
	if len(data) != count*g1Size {
		return nil, errors.New("bbs: invalid generators data length")
	}

	generators := make([]bls12381.G1Affine, count)
	for i := 0; i < count; i++ {
		_, err := generators[i].SetBytes(data[i*g1Size : (i+1)*g1Size])
		if err != nil {
			return nil, err
		}
	}
	return generators, nil
}

// randomScalar generates a random scalar in Fr.
func randomScalar(reader io.Reader) (*big.Int, error) {
	var scalar fr.Element
	_, err := scalar.SetRandom()
	if err != nil {
		return nil, err
	}
	return scalar.BigInt(new(big.Int)), nil
}

// generateG1Generators creates n deterministic G1 generators using hash-to-curve.
func generateG1Generators(n int) ([]bls12381.G1Affine, error) {
	generators := make([]bls12381.G1Affine, n)
	dst := []byte("VERIGLOB_BBS_PLUS_G1_GENERATOR_")

	for i := 0; i < n; i++ {
		// Create unique seed for each generator
		seed := make([]byte, len(dst)+4)
		copy(seed, dst)
		seed[len(dst)] = byte(i >> 24)
		seed[len(dst)+1] = byte(i >> 16)
		seed[len(dst)+2] = byte(i >> 8)
		seed[len(dst)+3] = byte(i)

		// Hash to curve
		generators[i] = hashToG1(seed)
	}

	return generators, nil
}

// hashToG1 hashes arbitrary data to a G1 point using scalar multiplication.
// For production, consider using a standardized hash-to-curve method.
func hashToG1(data []byte) bls12381.G1Affine {
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Use scalar multiplication from base point
	// Generators() returns (g1Jac, g2Jac, g1Aff, g2Aff)
	_, _, g1Aff, _ := bls12381.Generators()
	var scalar fr.Element
	scalar.SetBytes(digest[:32])

	var point bls12381.G1Affine
	point.ScalarMultiplication(&g1Aff, scalar.BigInt(new(big.Int)))
	return point
}

// HashToScalar hashes data to a scalar in Fr (for message encoding).
func HashToScalar(data []byte) *fr.Element {
	h := sha256.Sum256(data)
	var scalar fr.Element
	scalar.SetBytes(h[:])
	return &scalar
}
