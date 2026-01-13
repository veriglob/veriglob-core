package bbs

import (
	"errors"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Signature represents a BBS+ signature.
type Signature struct {
	// A is the signature element (G1 point)
	A bls12381.G1Affine
	// E is the signature exponent
	E fr.Element
	// S is the blinding factor
	S fr.Element
}

// Sign creates a BBS+ signature over the given messages.
// messages should be pre-hashed to scalars using HashToScalar.
func Sign(secretKey *big.Int, generators []bls12381.G1Affine, messages [][]byte) (*Signature, error) {
	if len(messages)+1 != len(generators) {
		return nil, errors.New("bbs: message count must be generators count - 1")
	}

	// Convert messages to field elements
	msgScalars := make([]*fr.Element, len(messages))
	for i, msg := range messages {
		msgScalars[i] = HashToScalar(msg)
	}

	// Generate random e and s
	var e, s fr.Element
	_, err := e.SetRandom()
	if err != nil {
		return nil, err
	}
	_, err = s.SetRandom()
	if err != nil {
		return nil, err
	}

	// Compute B = g1 + h0*s + sum(hi*mi)
	// where g1 is the first generator (base), h0 is generators[0], hi is generators[i+1]
	B := computeB(generators, &s, msgScalars)

	// Compute A = B^(1/(sk+e))
	// First compute sk + e
	var skPlusE fr.Element
	skPlusE.SetBigInt(secretKey)
	skPlusE.Add(&skPlusE, &e)

	// Compute inverse
	var skPlusEInv fr.Element
	skPlusEInv.Inverse(&skPlusE)

	// A = B * (1/(sk+e))
	var A bls12381.G1Affine
	A.ScalarMultiplication(&B, skPlusEInv.BigInt(new(big.Int)))

	return &Signature{
		A: A,
		E: e,
		S: s,
	}, nil
}

// Verify verifies a BBS+ signature.
func Verify(sig *Signature, publicKey *bls12381.G2Affine, generators []bls12381.G1Affine, messages [][]byte) error {
	if len(messages)+1 != len(generators) {
		return errors.New("bbs: message count must be generators count - 1")
	}

	// Convert messages to field elements
	msgScalars := make([]*fr.Element, len(messages))
	for i, msg := range messages {
		msgScalars[i] = HashToScalar(msg)
	}

	// Compute B = g1 + h0*s + sum(hi*mi)
	B := computeB(generators, &sig.S, msgScalars)

	// Verify pairing: e(A, W * g2^e) == e(B, g2)
	// Equivalent to: e(A, W) * e(A, g2^e) == e(B, g2)
	// Or: e(A, W) * e(A^e, g2) == e(B, g2)

	// Generators() returns (g1Jac, g2Jac, g1Aff, g2Aff)
	_, _, _, g2Aff := bls12381.Generators()

	// Compute W * g2^e
	var g2e bls12381.G2Affine
	g2e.ScalarMultiplication(&g2Aff, sig.E.BigInt(new(big.Int)))

	var Wg2e bls12381.G2Jac
	Wg2e.FromAffine(publicKey)
	var g2eJac bls12381.G2Jac
	g2eJac.FromAffine(&g2e)
	Wg2e.AddAssign(&g2eJac)

	var Wg2eAffine bls12381.G2Affine
	Wg2eAffine.FromJacobian(&Wg2e)

	// Check pairing: e(A, W*g2^e) == e(B, g2)
	// Using multi-Miller loop: e(A, W*g2^e) * e(-B, g2) == 1
	var negB bls12381.G1Affine
	negB.Neg(&B)

	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{sig.A, negB},
		[]bls12381.G2Affine{Wg2eAffine, g2Aff},
	)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("bbs: signature verification failed")
	}

	return nil
}

// computeB computes B = g1 + h0*s + sum(hi*mi)
func computeB(generators []bls12381.G1Affine, s *fr.Element, messages []*fr.Element) bls12381.G1Affine {
	// Start with the base generator g1
	// Generators() returns (g1Jac, g2Jac, g1Aff, g2Aff)
	_, _, g1Aff, _ := bls12381.Generators()

	var result bls12381.G1Jac
	result.FromAffine(&g1Aff)

	// Add h0 * s
	var h0s bls12381.G1Affine
	h0s.ScalarMultiplication(&generators[0], s.BigInt(new(big.Int)))
	var h0sJac bls12381.G1Jac
	h0sJac.FromAffine(&h0s)
	result.AddAssign(&h0sJac)

	// Add hi * mi for each message
	for i, msg := range messages {
		var him bls12381.G1Affine
		him.ScalarMultiplication(&generators[i+1], msg.BigInt(new(big.Int)))
		var himJac bls12381.G1Jac
		himJac.FromAffine(&him)
		result.AddAssign(&himJac)
	}

	var resultAffine bls12381.G1Affine
	resultAffine.FromJacobian(&result)
	return resultAffine
}

// Serialize converts the signature to bytes.
func (s *Signature) Serialize() []byte {
	// A (48 bytes compressed) + E (32 bytes) + S (32 bytes) = 112 bytes
	result := make([]byte, 0, 112)
	aBytes := s.A.Bytes()
	result = append(result, aBytes[:]...)
	eBytes := s.E.Bytes()
	result = append(result, eBytes[:]...)
	sBytes := s.S.Bytes()
	result = append(result, sBytes[:]...)
	return result
}

// DeserializeSignature reconstructs a signature from bytes.
func DeserializeSignature(data []byte) (*Signature, error) {
	if len(data) != 112 {
		return nil, errors.New("bbs: invalid signature length")
	}

	sig := &Signature{}

	// Parse A (48 bytes)
	_, err := sig.A.SetBytes(data[:48])
	if err != nil {
		return nil, err
	}

	// Parse E (32 bytes)
	sig.E.SetBytes(data[48:80])

	// Parse S (32 bytes)
	sig.S.SetBytes(data[80:112])

	return sig, nil
}
